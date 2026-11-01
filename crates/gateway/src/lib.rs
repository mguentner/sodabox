//! Inference gateway (ADR-0020).
//!
//! Runs inside a VM's supervisor. The egress proxy hands it the guest's
//! connections to the gateway address, and it serves HTTP/1.1 on them in the
//! guest's chosen API format ([`api`]). For each request it resolves the
//! `model` through the VM's aliases, checks the alias's token quota, swaps
//! the guest's (placeholder) credentials for the provider's, and streams the
//! provider's response back unchanged while counting the tokens it reports
//! ([`usage`]). Provider keys never reach the guest.
//!
//! The gateway forwards requests as they are, apart from `model` and, for
//! OpenAI streams, the option that makes the provider report usage. It does
//! not translate between API formats: an alias only works with a provider
//! that speaks the format of the route it was called on.

pub mod api;
mod body;
mod book;
mod creds;
pub mod probe;
pub mod usage;

use std::convert::Infallible;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper::header::{HeaderValue, ACCEPT, CONTENT_TYPE};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Semaphore;

use sodabox_common::event::{now_ts, Event, Tokens, Verdict};
use sodabox_common::policy::VmPolicy;
use sodabox_common::provider::{Provider, ProviderApi};
use sodabox_common::quota::{Balances, Ledger};

use crate::api::{Api, ErrorKind, Route};
use crate::body::MeteredBody;
use crate::book::QuotaBook;
use crate::creds::Credentials;
use crate::usage::{Framing, UsageScanner};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
type GwBody = UnsyncBoxBody<Bytes, BoxError>;

/// The service name a `service` rule grants access to.
pub const SERVICE: &str = sodabox_common::policy::INFERENCE_SERVICE;

/// Largest request body accepted. Agents send their whole context with each
/// request, so this is generous.
const MAX_REQUEST_BODY: usize = 32 << 20;
/// How much of an upstream error body is read for the error message.
const MAX_ERROR_BODY: usize = 8 << 10;
/// Requests in flight per VM; more wait for a slot. This also bounds how far
/// a balance can go below zero (one response per request in flight).
const MAX_CONCURRENT: usize = 8;
/// Time a client gets to send its request headers.
const HEADER_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest silence from a provider mid-response. Generous: reasoning models
/// can think for minutes before the first token.
const READ_TIMEOUT: Duration = Duration::from_secs(600);

/// Where the gateway sends its events (the supervisor's event stream).
pub trait GatewayEvents: Send + Sync + 'static {
    fn emit(&self, event: Event);
}

/// Where providers come from. The real one reads the provider files on every
/// request, so edits apply without a restart; tests use a fixed set.
pub trait Providers: Send + Sync + 'static {
    fn get(&self, name: &str) -> Result<Provider, String>;
}

/// Providers from `$XDG_CONFIG_HOME/sodabox/providers/`.
pub struct ProviderFiles;

impl Providers for ProviderFiles {
    fn get(&self, name: &str) -> Result<Provider, String> {
        Provider::load(name)
    }
}

/// One VM's gateway. Cheap to clone.
#[derive(Clone)]
pub struct Gateway {
    inner: Arc<Inner>,
}

struct Inner {
    vm: String,
    policy: RwLock<VmPolicy>,
    providers: Arc<dyn Providers>,
    book: Mutex<QuotaBook>,
    creds: Credentials,
    events: Arc<dyn GatewayEvents>,
    client: reqwest::Client,
    permits: Arc<Semaphore>,
}

impl Gateway {
    /// A gateway for `vm` with its current policy and quota ledger. Fails if
    /// the ledger can't be read or the HTTP client can't be built.
    pub fn new(
        vm: &str,
        policy: &VmPolicy,
        ledger: Ledger,
        providers: Arc<dyn Providers>,
        events: Arc<dyn GatewayEvents>,
    ) -> Result<Gateway, String> {
        let book = QuotaBook::open(ledger).map_err(|e| format!("reading quota ledger: {e}"))?;
        let client = http_client()?;
        Ok(Gateway {
            inner: Arc::new(Inner {
                vm: vm.to_string(),
                policy: RwLock::new(policy.clone()),
                providers,
                book: Mutex::new(book),
                creds: Credentials::default(),
                events,
                client,
                permits: Arc::new(Semaphore::new(MAX_CONCURRENT)),
            }),
        })
    }

    /// Apply a new policy (aliases, quota modes, access) live.
    pub fn update_policy(&self, policy: &VmPolicy) {
        if let Ok(mut p) = self.inner.policy.write() {
            *p = policy.clone();
        }
    }

    /// Whether the guest may reach the gateway: it is switched on in
    /// `[gateway]` and a `service` rule grants access.
    pub fn reachable(&self) -> bool {
        self.inner
            .policy
            .read()
            .map(|p| is_reachable(&p))
            .unwrap_or(false)
    }

    /// Re-read the quota ledger, e.g. after a grant.
    pub fn reload_quota(&self) -> Result<(), String> {
        self.inner
            .book
            .lock()
            .map_err(|_| "quota book poisoned".to_string())?
            .reload()
            .map_err(|e| format!("reading quota ledger: {e}"))
    }

    /// The live balances.
    pub fn balances(&self) -> Result<Balances, String> {
        Ok(self
            .inner
            .book
            .lock()
            .map_err(|_| "quota book poisoned".to_string())?
            .balances()
            .clone())
    }

    /// Serve HTTP/1.1 on one connection until the client closes it.
    pub async fn serve_conn<I>(&self, io: I)
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let inner = self.inner.clone();
        let svc = hyper::service::service_fn(move |req| handle(inner.clone(), req));
        let mut builder = hyper::server::conn::http1::Builder::new();
        builder
            .timer(TokioTimer::new())
            .header_read_timeout(HEADER_TIMEOUT);
        // A connection error is the guest's problem (bad request, hang-up),
        // never the supervisor's.
        let _ = builder.serve_connection(TokioIo::new(io), svc).await;
    }
}

/// Whether `policy` lets the guest reach the gateway.
pub fn is_reachable(policy: &VmPolicy) -> bool {
    policy.gateway.as_ref().is_some_and(|g| g.enabled) && policy.allows_service(SERVICE)
}

/// A request the gateway answers itself, with an error.
struct Refusal {
    kind: ErrorKind,
    message: String,
    /// The alias the request named, for the event.
    alias: Option<String>,
}

impl Refusal {
    fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Refusal {
            kind,
            message: message.into(),
            alias: None,
        }
    }

    fn alias(mut self, alias: &str) -> Self {
        self.alias = Some(alias.to_string());
        self
    }
}

async fn handle(inner: Arc<Inner>, req: Request<Incoming>) -> Result<Response<GwBody>, Infallible> {
    let started = Instant::now();
    let path = req.uri().path().to_string();
    let Some(route) = Route::find(req.method(), &path) else {
        let api = Route::api_of_path(&path);
        let msg = format!("sodabox gateway: no endpoint {} {path}", req.method());
        return Ok(error_response(api, ErrorKind::NotFound, &msg));
    };
    Ok(match route {
        Route::Root => text_response(StatusCode::OK, "sodabox inference gateway\n"),
        Route::OpenaiModels | Route::OllamaTags => {
            let api = route.api();
            json_response(
                StatusCode::OK,
                &api::model_list(api, &inner.aliases_for(api)),
            )
        }
        Route::OpenaiChat | Route::OllamaChat | Route::OllamaGenerate => {
            match inner.clone().forward(route, req, started).await {
                Ok(resp) => resp,
                Err(r) => {
                    let api = route.api();
                    let status = r.kind.status(api);
                    if let Some(alias) = &r.alias {
                        inner.events.emit(Event::Inference {
                            ts: now_ts(),
                            verdict: match r.kind {
                                ErrorKind::Upstream(_) => Verdict::Allowed,
                                _ => Verdict::Blocked,
                            },
                            api: api.name().to_string(),
                            alias: alias.clone(),
                            provider: None,
                            model: None,
                            status: status.as_u16(),
                            tokens: Tokens::default(),
                            complete: true,
                            latency_ms: started.elapsed().as_millis() as u64,
                        });
                    }
                    error_response(api, r.kind, &r.message)
                }
            }
        }
    })
}

impl Inner {
    /// The aliases a client of `api` can use.
    fn aliases_for(&self, api: Api) -> Vec<String> {
        let models = match self.policy.read() {
            Ok(p) => p.models.clone(),
            Err(_) => return Vec::new(),
        };
        models
            .into_iter()
            .filter(|m| {
                self.providers
                    .get(&m.provider)
                    .is_ok_and(|p| api.serves(p.spec.api))
            })
            .map(|m| m.alias)
            .collect()
    }

    async fn forward(
        self: Arc<Self>,
        route: Route,
        req: Request<Incoming>,
        started: Instant,
    ) -> Result<Response<GwBody>, Refusal> {
        let api = route.api();
        // Held until the response body is done, so it bounds requests in flight.
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Refusal::new(ErrorKind::Config, "gateway shutting down"))?;
        let accept = req.headers().get(ACCEPT).cloned();
        let bytes = match Limited::new(req.into_body(), MAX_REQUEST_BODY)
            .collect()
            .await
        {
            Ok(c) => c.to_bytes(),
            Err(e) if e.downcast_ref::<LengthLimitError>().is_some() => {
                return Err(Refusal::new(ErrorKind::TooLarge, "request body too large"))
            }
            Err(e) => {
                return Err(Refusal::new(
                    ErrorKind::BadRequest,
                    format!("reading request body: {e}"),
                ))
            }
        };
        let mut body: Value = serde_json::from_slice(&bytes)
            .ok()
            .filter(Value::is_object)
            .ok_or_else(|| {
                Refusal::new(ErrorKind::BadRequest, "request body is not a JSON object")
            })?;
        let name = body
            .get("model")
            .and_then(Value::as_str)
            .ok_or_else(|| Refusal::new(ErrorKind::BadRequest, "request has no `model`"))?
            .to_string();

        let (alias, metered) = {
            let p = self
                .policy
                .read()
                .map_err(|_| Refusal::new(ErrorKind::Config, "policy poisoned"))?;
            (p.model(&name).cloned(), p.is_metered(&name))
        };
        let alias = alias.ok_or_else(|| {
            Refusal::new(
                ErrorKind::NotFound,
                format!("model '{name}' not found: this VM has no such alias (soda model ls)"),
            )
            .alias(&name)
        })?;
        let provider = self.providers.get(&alias.provider).map_err(|e| {
            Refusal::new(ErrorKind::Config, format!("sodabox gateway: {e}")).alias(&name)
        })?;
        if !api.serves(provider.spec.api) {
            return Err(Refusal::new(
                ErrorKind::Config,
                format!(
                    "model '{name}' uses provider '{}' ({} API), which can't serve {} requests",
                    provider.name,
                    provider.spec.api,
                    api.name()
                ),
            )
            .alias(&name));
        }

        self.check_quota(&name, alias.initial_quota.unwrap_or(0), metered)?;

        body["model"] = Value::String(alias.model.clone());
        let streams = route.streams(&body);
        if streams && provider.spec.api == ProviderApi::Openai {
            request_stream_usage(&mut body);
        }

        let secret = self.creds.get(&provider).await.map_err(|e| {
            Refusal::new(ErrorKind::Config, format!("sodabox gateway: {e}")).alias(&name)
        })?;
        let url = format!(
            "{}{}",
            provider.spec.base_url.trim_end_matches('/'),
            route
                .upstream_path()
                .expect("request routes have an upstream path")
        );
        let payload = serde_json::to_vec(&body).expect("a JSON value serializes");
        let mut upstream = self
            .client
            .post(&url)
            .header(CONTENT_TYPE, "application/json")
            .body(payload);
        if let Some(accept) = accept {
            upstream = upstream.header(ACCEPT, accept);
        }
        if let Some((header, value)) = auth_header(&provider, secret.as_deref()).map_err(|e| {
            Refusal::new(ErrorKind::Config, format!("sodabox gateway: {e}")).alias(&name)
        })? {
            upstream = upstream.header(header, value);
        }

        let resp = upstream.send().await.map_err(|e| {
            Refusal::new(
                ErrorKind::Upstream(StatusCode::BAD_GATEWAY),
                format!(
                    "provider '{}' unreachable: {}",
                    provider.name,
                    error_chain(e)
                ),
            )
            .alias(&name)
        })?;
        let status = resp.status();
        if !status.is_success() {
            if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
                self.creds.forget(&provider.name);
            }
            let detail = read_error_body(resp, secret.as_deref()).await;
            return Err(Refusal::new(
                ErrorKind::Upstream(status),
                format!("provider '{}' returned {status}: {detail}", provider.name),
            )
            .alias(&name));
        }

        let content_type = resp.headers().get(CONTENT_TYPE).cloned();
        let framing = match (api, streams) {
            (Api::Openai, true) => Framing::OpenaiSse,
            (Api::Openai, false) => Framing::OpenaiJson,
            (Api::Ollama, true) => Framing::OllamaNdjson,
            (Api::Ollama, false) => Framing::OllamaJson,
        };
        let me = self.clone();
        let provider_name = provider.name.clone();
        let upstream_model = alias.model.clone();
        let request_bytes = bytes.len();
        let on_finish: body::OnFinish = Box::new(move |reported, chunks, complete| {
            drop(permit);
            // Usage comes at the very end of a response. Without it (cut off,
            // or a provider that sends none) the request is still booked, at
            // an estimate, so cancelling early never makes a request free.
            let tokens = reported.unwrap_or_else(|| estimate(request_bytes, chunks));
            if let Ok(mut book) = me.book.lock() {
                if let Err(e) = book.book(&name, tokens.metered(), metered, tokens.estimated) {
                    eprintln!("gateway({}): writing quota ledger: {e}", me.vm);
                }
            }
            me.events.emit(Event::Inference {
                ts: now_ts(),
                verdict: Verdict::Allowed,
                api: api.name().to_string(),
                alias: name,
                provider: Some(provider_name),
                model: Some(upstream_model),
                status: status.as_u16(),
                tokens,
                complete,
                latency_ms: started.elapsed().as_millis() as u64,
            });
        });
        let body = MeteredBody::new(
            reqwest::Body::from(resp),
            UsageScanner::new(framing),
            on_finish,
        );
        let mut out = Response::new(body.boxed_unsync());
        *out.status_mut() = status;
        if let Some(ct) = content_type {
            out.headers_mut().insert(CONTENT_TYPE, ct);
        }
        Ok(out)
    }

    /// Initialize the alias's balance on first use, and refuse the request if
    /// a metered alias has nothing left.
    fn check_quota(&self, alias: &str, initial: u64, metered: bool) -> Result<(), Refusal> {
        let mut book = self
            .book
            .lock()
            .map_err(|_| Refusal::new(ErrorKind::Config, "quota book poisoned").alias(alias))?;
        book.ensure_initialized(alias, initial).map_err(|e| {
            Refusal::new(
                ErrorKind::Config,
                format!("sodabox gateway: writing quota ledger: {e}"),
            )
            .alias(alias)
        })?;
        if metered && book.balance(alias) <= 0 {
            self.events.emit(Event::QuotaExhausted {
                ts: now_ts(),
                alias: alias.to_string(),
            });
            return Err(Refusal::new(
                ErrorKind::QuotaExhausted,
                format!(
                    "sodabox: token quota for '{alias}' on VM '{vm}' is used up. \
                     Grant more on the host: soda quota grant {alias} <tokens> --vm {vm}",
                    vm = self.vm
                ),
            )
            .alias(alias));
        }
        Ok(())
    }
}

/// The HTTP client the gateway talks to providers with: rustls with the
/// host's trust store, timeouts, and no redirects.
fn http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_TIMEOUT)
        .user_agent("sodabox-gateway")
        // A redirect could carry the credential to another host.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("building HTTP client: {e}"))
}

/// A reqwest error with its causes, e.g. `error sending request: client
/// error (Connect): tcp connect error: Connection refused`. The top level
/// alone ("error sending request") doesn't say what went wrong. The URL is
/// left out; it is already in the message's context.
fn error_chain(e: reqwest::Error) -> String {
    let e = e.without_url();
    let mut msg = e.to_string();
    let mut source = std::error::Error::source(&e);
    while let Some(s) = source {
        msg.push_str(&format!(": {s}"));
        source = s.source();
    }
    msg
}

/// The provider's auth header (name, value) for `secret`, or `None` if the
/// provider needs no credential. The value is marked sensitive so it never
/// shows up in debug output.
fn auth_header(
    provider: &Provider,
    secret: Option<&str>,
) -> Result<Option<(String, HeaderValue)>, String> {
    let (Some(auth), Some(secret)) = (&provider.spec.auth, secret) else {
        return Ok(None);
    };
    let value = match auth.scheme() {
        "" => secret.to_string(),
        scheme => format!("{scheme} {secret}"),
    };
    let mut value = HeaderValue::from_str(&value).map_err(|_| {
        format!(
            "provider '{}': credential has invalid characters",
            provider.name
        )
    })?;
    value.set_sensitive(true);
    Ok(Some((auth.header.clone(), value)))
}

/// Bytes of request per input token, for the estimate. About right for
/// English text and JSON; the real ratio varies by tokenizer and language.
const BYTES_PER_TOKEN: u64 = 4;

/// The gateway's estimate of a request's usage when the provider reported
/// none: the input from the request's size, the output from the content
/// chunks streamed (streaming APIs send about one token per chunk).
fn estimate(request_bytes: usize, chunks: u64) -> Tokens {
    Tokens {
        input: (request_bytes as u64).div_ceil(BYTES_PER_TOKEN),
        output: chunks,
        estimated: true,
        ..Tokens::default()
    }
}

/// Ask an OpenAI-compatible provider to report usage in the stream, which it
/// otherwise leaves out.
fn request_stream_usage(body: &mut Value) {
    match body.get_mut("stream_options") {
        Some(Value::Object(opts)) => {
            opts.insert("include_usage".into(), Value::Bool(true));
        }
        _ => body["stream_options"] = json!({ "include_usage": true }),
    }
}

/// The first bytes of an upstream error body as one printable line, with the
/// credential redacted in case the provider echoes it.
async fn read_error_body(mut resp: reqwest::Response, secret: Option<&str>) -> String {
    let mut buf = Vec::new();
    while buf.len() < MAX_ERROR_BODY {
        match resp.chunk().await {
            Ok(Some(chunk)) => buf.extend_from_slice(&chunk),
            _ => break,
        }
    }
    buf.truncate(MAX_ERROR_BODY);
    let mut text: String = String::from_utf8_lossy(&buf)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if let Some(s) = secret.filter(|s| !s.is_empty()) {
        text = text.replace(s, "[redacted]");
    }
    let text = text.trim();
    if text.is_empty() {
        "(no details)".to_string()
    } else {
        text.to_string()
    }
}

fn full(bytes: impl Into<Bytes>) -> GwBody {
    Full::new(bytes.into())
        .map_err(|never: Infallible| match never {})
        .boxed_unsync()
}

fn json_response(status: StatusCode, v: &Value) -> Response<GwBody> {
    let mut r = Response::new(full(
        serde_json::to_vec(v).expect("a JSON value serializes"),
    ));
    *r.status_mut() = status;
    r.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    r
}

fn text_response(status: StatusCode, text: &'static str) -> Response<GwBody> {
    let mut r = Response::new(full(text));
    *r.status_mut() = status;
    r.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    r
}

fn error_response(api: Api, kind: ErrorKind, message: &str) -> Response<GwBody> {
    json_response(kind.status(api), &kind.body(api, message))
}
