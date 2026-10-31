//! The gateway against fake providers on localhost: one real HTTP client,
//! the gateway on a local listener, and an upstream that records what it got.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::HeaderMap;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use tokio::net::TcpListener;

use sodabox_common::event::Event;
use sodabox_common::policy::VmPolicy;
use sodabox_common::provider::Provider;
use sodabox_common::quota::Ledger;
use sodabox_gateway::{Gateway, GatewayEvents, Providers};

// ---- fake upstream -------------------------------------------------------

#[derive(Clone)]
struct Seen {
    path: String,
    headers: HeaderMap,
    body: Value,
}

#[derive(Clone)]
enum Reply {
    /// Answer with this status, content type and body.
    Body(u16, &'static str, &'static str),
    /// Send `first`, then never finish the body.
    Stall(&'static str),
}

struct Upstream {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Upstream {
    async fn start(reply: Reply) -> Upstream {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let seen = seen2.clone();
                let reply = reply.clone();
                tokio::spawn(async move {
                    let svc =
                        hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                            let seen = seen.clone();
                            let reply = reply.clone();
                            async move {
                                let path = req.uri().path().to_string();
                                let headers = req.headers().clone();
                                let bytes = req.into_body().collect().await.unwrap().to_bytes();
                                let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                                seen.lock().unwrap().push(Seen {
                                    path,
                                    headers,
                                    body,
                                });
                                Ok::<_, hyper::Error>(respond(reply))
                            }
                        });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        Upstream { addr, seen }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    fn requests(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

type AnyBody = http_body_util::combinators::UnsyncBoxBody<Bytes, hyper::Error>;

fn respond(reply: Reply) -> Response<AnyBody> {
    match reply {
        Reply::Body(status, ctype, body) => {
            let mut r = Response::new(
                Full::new(Bytes::from_static(body.as_bytes()))
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            );
            *r.status_mut() = StatusCode::from_u16(status).unwrap();
            r.headers_mut()
                .insert("content-type", ctype.parse().unwrap());
            r
        }
        Reply::Stall(first) => {
            let (mut tx, body) = http_body_util::channel::Channel::<Bytes, hyper::Error>::new(4);
            tokio::spawn(async move {
                tx.send_data(Bytes::from_static(first.as_bytes()))
                    .await
                    .ok();
                // Keep the sender alive so the body never ends.
                tokio::time::sleep(Duration::from_secs(3600)).await;
                drop(tx);
            });
            let mut r = Response::new(body.boxed_unsync());
            r.headers_mut()
                .insert("content-type", "text/event-stream".parse().unwrap());
            r
        }
    }
}

// ---- gateway under test --------------------------------------------------

struct Fixed(HashMap<String, Provider>);

impl Providers for Fixed {
    fn get(&self, name: &str) -> Result<Provider, String> {
        self.0
            .get(name)
            .cloned()
            .ok_or_else(|| format!("no provider '{name}'"))
    }
}

#[derive(Default)]
struct Sink(Mutex<Vec<Event>>);

impl GatewayEvents for Sink {
    fn emit(&self, event: Event) {
        self.0.lock().unwrap().push(event);
    }
}

impl Sink {
    /// Wait for the first event matching `f`.
    async fn wait_for(&self, f: impl Fn(&Event) -> bool) -> Event {
        for _ in 0..200 {
            if let Some(e) = self.0.lock().unwrap().iter().find(|e| f(e)) {
                return e.clone();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("event never arrived");
    }
}

struct Harness {
    base: String,
    gateway: Gateway,
    events: Arc<Sink>,
    ledger: Ledger,
}

fn provider(name: &str, api: &str, base_url: &str, auth: bool) -> (String, Provider) {
    let auth = if auth {
        "auth = { command = [\"printf\", \"sk-test\"] }\n"
    } else {
        ""
    };
    let text = format!("api = \"{api}\"\nbase_url = \"{base_url}\"\n{auth}");
    (name.to_string(), Provider::parse(name, &text).unwrap())
}

async fn harness(test: &str, policy: &str, providers: Vec<(String, Provider)>) -> Harness {
    let dir = std::env::temp_dir().join(format!("sodabox-gw-{}-{test}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let ledger = Ledger::at(dir.join("quota.jsonl"));
    let policy: VmPolicy = toml::from_str(policy).unwrap();
    let events = Arc::new(Sink::default());
    let gateway = Gateway::new(
        "vm1",
        &policy,
        ledger.clone(),
        Arc::new(Fixed(providers.into_iter().collect())),
        events.clone(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gw = gateway.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let gw = gw.clone();
            tokio::spawn(async move { gw.serve_conn(stream).await });
        }
    });
    Harness {
        base: format!("http://{addr}"),
        gateway,
        events,
        ledger,
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

async fn post(h: &Harness, path: &str, body: Value) -> (u16, String) {
    let resp = client()
        .post(format!("{}{path}", h.base))
        .header("authorization", "Bearer guest-placeholder")
        .header("x-api-key", "guest-placeholder")
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.text().await.unwrap())
}

fn balance(h: &Harness, alias: &str) -> i64 {
    h.ledger.load().unwrap().get(alias).map_or(0, |b| b.balance)
}

const POLICY_HEAD: &str = "version = 1\n[gateway]\nenabled = true\n\
[[rules]]\nkind = \"service\"\nname = \"inference\"\n";

fn policy(models: &str) -> String {
    format!("{POLICY_HEAD}{models}")
}

const OPENAI_SSE: &str =
    "data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}],\"usage\":null}\n\n\
data: {\"choices\":[],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":20,\
\"prompt_tokens_details\":{\"cached_tokens\":40}}}\n\n\
data: [DONE]\n\n";

// ---- tests ---------------------------------------------------------------

#[tokio::test]
async fn openai_stream_rewrites_model_swaps_auth_and_books_usage() {
    let up = Upstream::start(Reply::Body(200, "text/event-stream", OPENAI_SSE)).await;
    let h = harness(
        "openai",
        &policy(
            "[[models]]\nalias = \"foo\"\nprovider = \"up\"\nmodel = \"real-foo\"\ninitial_quota = 1000\n",
        ),
        vec![provider("up", "openai", &up.url("/v1"), true)],
    )
    .await;

    let (status, body) = post(
        &h,
        "/v1/chat/completions",
        json!({"model": "foo", "stream": true, "messages": []}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body, OPENAI_SSE, "the stream passes through unchanged");

    let seen = &up.requests()[0];
    assert_eq!(seen.path, "/v1/chat/completions");
    assert_eq!(seen.body["model"], "real-foo");
    assert_eq!(seen.body["stream_options"]["include_usage"], true);
    assert_eq!(seen.headers["authorization"], "Bearer sk-test");
    assert!(
        seen.headers.get("x-api-key").is_none(),
        "client auth headers are dropped"
    );

    let ev = h
        .events
        .wait_for(|e| matches!(e, Event::Inference { status: 200, .. }))
        .await;
    let Event::Inference {
        tokens,
        complete,
        model,
        ..
    } = ev
    else {
        unreachable!()
    };
    assert_eq!(
        (tokens.input, tokens.output, tokens.cache_read),
        (100, 20, 40)
    );
    assert!(complete);
    assert_eq!(model.as_deref(), Some("real-foo"));
    // 1000 initial − (100 − 40 cached + 20).
    assert_eq!(balance(&h, "foo"), 920);
    assert_eq!(h.gateway.balances().unwrap()["foo"].balance, 920);
}

#[tokio::test]
async fn mistral_gets_no_stream_options() {
    let sse = "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":4}}\n\ndata: [DONE]\n\n";
    let up = Upstream::start(Reply::Body(200, "text/event-stream", sse)).await;
    let h = harness(
        "mistral",
        &policy(
            "[[models]]\nalias = \"big\"\nprovider = \"m\"\nmodel = \"mistral-large-latest\"\ninitial_quota = 100\n",
        ),
        vec![provider("m", "mistral", &up.url("/v1"), true)],
    )
    .await;
    let (status, _) = post(
        &h,
        "/v1/chat/completions",
        json!({"model": "big", "stream": true}),
    )
    .await;
    assert_eq!(status, 200);
    assert!(up.requests()[0].body.get("stream_options").is_none());
    h.events
        .wait_for(|e| matches!(e, Event::Inference { status: 200, .. }))
        .await;
    assert_eq!(balance(&h, "big"), 87);
}

#[tokio::test]
async fn ollama_native_chat_streamed_and_not() {
    let ndjson = "{\"message\":{\"content\":\"Hi\"},\"done\":false}\n\
{\"message\":{\"content\":\"\"},\"done\":true,\"prompt_eval_count\":26,\"eval_count\":74}\n";
    let up = Upstream::start(Reply::Body(200, "application/x-ndjson", ndjson)).await;
    let h = harness(
        "ollama",
        &policy(
            "[[models]]\nalias = \"foo:13b\"\nprovider = \"local\"\nmodel = \"the_actual_foo:13b\"\ninitial_quota = 500\n",
        ),
        vec![provider("local", "ollama", &up.url(""), false)],
    )
    .await;
    // Ollama streams by default.
    let (status, body) = post(&h, "/api/chat", json!({"model": "foo:13b", "messages": []})).await;
    assert_eq!((status, body.as_str()), (200, ndjson));
    let seen = &up.requests()[0];
    assert_eq!(
        (seen.path.as_str(), &seen.body["model"]),
        ("/api/chat", &json!("the_actual_foo:13b"))
    );
    assert!(
        seen.headers.get("authorization").is_none(),
        "no auth configured, none sent"
    );
    h.events
        .wait_for(|e| matches!(e, Event::Inference { status: 200, .. }))
        .await;
    assert_eq!(balance(&h, "foo:13b"), 400);
}

#[tokio::test]
async fn unknown_alias_is_a_404_in_each_format() {
    let h = harness("unknown", &policy(""), vec![]).await;
    let (status, body) = post(&h, "/v1/chat/completions", json!({"model": "gpt-9"})).await;
    assert_eq!(status, 404);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["error"]["code"], "model_not_found");
    let (status, body) = post(&h, "/api/generate", json!({"model": "gpt-9"})).await;
    assert_eq!(status, 404);
    assert!(serde_json::from_str::<Value>(&body).unwrap()["error"].is_string());
}

#[tokio::test]
async fn used_up_quota_is_refused_and_unlimited_is_unmetered() {
    let up = Upstream::start(Reply::Body(200, "text/event-stream", OPENAI_SSE)).await;
    let models = "[[models]]\nalias = \"foo\"\nprovider = \"up\"\nmodel = \"real-foo\"\n";
    let h = harness(
        "quota",
        &policy(models),
        vec![provider("up", "openai", &up.url("/v1"), true)],
    )
    .await;

    // No initial quota and no grant: refused before reaching the provider.
    let (status, body) = post(
        &h,
        "/v1/chat/completions",
        json!({"model": "foo", "stream": true}),
    )
    .await;
    assert_eq!(status, 429);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["error"]["code"], "insufficient_quota");
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("soda quota grant foo"));
    assert!(up.requests().is_empty());
    h.events
        .wait_for(|e| matches!(e, Event::QuotaExhausted { .. }))
        .await;

    // Unlimited for this alias: served, booked as unmetered, balance unchanged.
    let unlimited: VmPolicy =
        toml::from_str(&policy(&format!("{models}quota = \"unlimited\"\n"))).unwrap();
    h.gateway.update_policy(&unlimited);
    let (status, _) = post(
        &h,
        "/v1/chat/completions",
        json!({"model": "foo", "stream": true}),
    )
    .await;
    assert_eq!(status, 200);
    h.events
        .wait_for(|e| matches!(e, Event::Inference { status: 200, .. }))
        .await;
    let b = &h.ledger.load().unwrap()["foo"];
    // Unmetered use is recorded in the same measure as metered use (100 − 40 + 20).
    assert_eq!((b.balance, b.unmetered), (0, 80));

    // A grant appended by the CLI applies after a reload.
    h.gateway
        .update_policy(&toml::from_str(&policy(models)).unwrap());
    h.ledger
        .append(&sodabox_common::quota::Entry {
            ts: 0,
            alias: "foo".into(),
            delta: 50,
            reason: sodabox_common::quota::Reason::Grant,
            tokens: None,
        })
        .unwrap();
    h.gateway.reload_quota().unwrap();
    let (status, _) = post(
        &h,
        "/v1/chat/completions",
        json!({"model": "foo", "stream": true}),
    )
    .await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn upstream_errors_keep_the_status_and_redact_the_key() {
    let up = Upstream::start(Reply::Body(
        401,
        "application/json",
        "{\"message\":\"invalid key sk-test\"}",
    ))
    .await;
    let h = harness(
        "upstream-error",
        &policy(
            "[[models]]\nalias = \"foo\"\nprovider = \"up\"\nmodel = \"x\"\ninitial_quota = 10\n",
        ),
        vec![provider("up", "openai", &up.url("/v1"), true)],
    )
    .await;
    let (status, body) = post(&h, "/v1/chat/completions", json!({"model": "foo"})).await;
    assert_eq!(status, 401);
    assert!(!body.contains("sk-test"), "{body}");
    assert!(body.contains("[redacted]"), "{body}");
}

#[tokio::test]
async fn alias_on_the_wrong_api_is_a_config_error() {
    let h = harness(
        "wrong-api",
        &policy(
            "[[models]]\nalias = \"foo\"\nprovider = \"local\"\nmodel = \"x\"\ninitial_quota = 10\n",
        ),
        vec![provider("local", "ollama", "http://127.0.0.1:9", false)],
    )
    .await;
    let (status, body) = post(&h, "/v1/chat/completions", json!({"model": "foo"})).await;
    assert_eq!(status, 500);
    assert!(body.contains("can't serve openai requests"), "{body}");
}

#[tokio::test]
async fn model_lists_show_aliases_for_their_api_only() {
    let h = harness(
        "lists",
        &policy(
            "[[models]]\nalias = \"chat\"\nprovider = \"m\"\nmodel = \"mistral-small\"\n\
             [[models]]\nalias = \"foo:13b\"\nprovider = \"local\"\nmodel = \"foo\"\n",
        ),
        vec![
            provider("m", "mistral", "https://api.mistral.ai/v1", true),
            provider("local", "ollama", "http://127.0.0.1:11434", false),
        ],
    )
    .await;
    let models = json_of(client().get(format!("{}/v1/models", h.base))).await;
    assert_eq!(models["data"].as_array().unwrap().len(), 1);
    assert_eq!(models["data"][0]["id"], "chat");
    let tags = json_of(client().get(format!("{}/api/tags", h.base))).await;
    assert_eq!(tags["models"][0]["name"], "foo:13b");
    assert_eq!(tags["models"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn client_disconnect_mid_stream_still_books_usage_seen() {
    // Mistral-style: usage arrives on a content chunk, then the stream stalls.
    let first = "data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}],\
\"usage\":{\"prompt_tokens\":30,\"completion_tokens\":5}}\n\n";
    let up = Upstream::start(Reply::Stall(first)).await;
    let h = harness(
        "disconnect",
        &policy(
            "[[models]]\nalias = \"foo\"\nprovider = \"m\"\nmodel = \"x\"\ninitial_quota = 100\n",
        ),
        vec![provider("m", "mistral", &up.url("/v1"), true)],
    )
    .await;
    let mut resp = client()
        .post(format!("{}/v1/chat/completions", h.base))
        .body(json!({"model": "foo", "stream": true}).to_string())
        .send()
        .await
        .unwrap();
    let chunk = resp.chunk().await.unwrap().unwrap();
    assert_eq!(chunk, first.as_bytes());
    drop(resp);

    let ev = h
        .events
        .wait_for(|e| matches!(e, Event::Inference { status: 200, .. }))
        .await;
    let Event::Inference {
        complete, tokens, ..
    } = ev
    else {
        unreachable!()
    };
    assert!(!complete);
    assert_eq!(tokens.output, 5);
    assert_eq!(balance(&h, "foo"), 65);
}

async fn json_of(req: reqwest::RequestBuilder) -> Value {
    serde_json::from_str(&req.send().await.unwrap().text().await.unwrap()).unwrap()
}
