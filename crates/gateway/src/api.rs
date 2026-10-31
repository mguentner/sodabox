//! The API formats the gateway serves to the guest, and their error shapes.
//!
//! Routing is by path, with no prefix, so clients can point their usual base
//! URL at the gateway: `OPENAI_BASE_URL=http://inference.sodabox.internal/v1`
//! or `OLLAMA_HOST=http://inference.sodabox.internal`.

use hyper::{Method, StatusCode};
use serde_json::{json, Value};
use sodabox_common::provider::ProviderApi;

/// An API format, as seen by the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Api {
    /// OpenAI-compatible Chat Completions.
    Openai,
    /// Ollama's native API.
    Ollama,
}

impl Api {
    pub fn name(self) -> &'static str {
        match self {
            Api::Openai => "openai",
            Api::Ollama => "ollama",
        }
    }

    /// Whether a provider speaking `provider` can serve this format without
    /// translation.
    pub fn serves(self, provider: ProviderApi) -> bool {
        match self {
            Api::Openai => matches!(provider, ProviderApi::Openai | ProviderApi::Mistral),
            Api::Ollama => provider == ProviderApi::Ollama,
        }
    }
}

/// A route the gateway answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// `GET /`: liveness probe.
    Root,
    /// `GET /v1/models`.
    OpenaiModels,
    /// `POST /v1/chat/completions`.
    OpenaiChat,
    /// `GET /api/tags`.
    OllamaTags,
    /// `POST /api/chat`.
    OllamaChat,
    /// `POST /api/generate`.
    OllamaGenerate,
}

impl Route {
    pub fn find(method: &Method, path: &str) -> Option<Route> {
        let path = path.trim_end_matches('/');
        Some(match (method, path) {
            (&Method::GET | &Method::HEAD, "") => Route::Root,
            (&Method::GET, "/v1/models") => Route::OpenaiModels,
            (&Method::POST, "/v1/chat/completions") => Route::OpenaiChat,
            (&Method::GET, "/api/tags") => Route::OllamaTags,
            (&Method::POST, "/api/chat") => Route::OllamaChat,
            (&Method::POST, "/api/generate") => Route::OllamaGenerate,
            _ => return None,
        })
    }

    /// The API format a path belongs to, for error shapes on unknown routes.
    pub fn api_of_path(path: &str) -> Api {
        if path.starts_with("/api/") {
            Api::Ollama
        } else {
            Api::Openai
        }
    }

    pub fn api(self) -> Api {
        match self {
            Route::Root | Route::OpenaiModels | Route::OpenaiChat => Api::Openai,
            Route::OllamaTags | Route::OllamaChat | Route::OllamaGenerate => Api::Ollama,
        }
    }

    /// The upstream path for a request route, relative to the provider's
    /// `base_url`.
    pub fn upstream_path(self) -> Option<&'static str> {
        match self {
            Route::OpenaiChat => Some("/chat/completions"),
            Route::OllamaChat => Some("/api/chat"),
            Route::OllamaGenerate => Some("/api/generate"),
            _ => None,
        }
    }

    /// Whether the request streams. Ollama streams unless told not to;
    /// OpenAI only when asked.
    pub fn streams(self, body: &Value) -> bool {
        let flag = body.get("stream").and_then(Value::as_bool);
        match self.api() {
            Api::Openai => flag == Some(true),
            Api::Ollama => flag != Some(false),
        }
    }
}

/// What went wrong, independent of how each format spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    BadRequest,
    NotFound,
    TooLarge,
    /// The alias's quota is used up. Spelled the way each API's own clients
    /// treat as "out of credit, don't retry".
    QuotaExhausted,
    /// The gateway or a provider is misconfigured on the host.
    Config,
    /// The provider failed or could not be reached.
    Upstream(StatusCode),
}

impl ErrorKind {
    pub fn status(self, api: Api) -> StatusCode {
        match self {
            ErrorKind::BadRequest => StatusCode::BAD_REQUEST,
            ErrorKind::NotFound => StatusCode::NOT_FOUND,
            ErrorKind::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            // OpenAI clients don't retry `insufficient_quota`; a plain 429
            // they would. Ollama has no such code, so a 403 stops retries.
            ErrorKind::QuotaExhausted => match api {
                Api::Openai => StatusCode::TOO_MANY_REQUESTS,
                Api::Ollama => StatusCode::FORBIDDEN,
            },
            ErrorKind::Config => StatusCode::INTERNAL_SERVER_ERROR,
            ErrorKind::Upstream(s) => s,
        }
    }

    /// The JSON error body in `api`'s shape.
    pub fn body(self, api: Api, message: &str) -> Value {
        match api {
            Api::Ollama => json!({ "error": message }),
            Api::Openai => {
                let (ty, code) = match self {
                    ErrorKind::BadRequest | ErrorKind::TooLarge => {
                        ("invalid_request_error", Value::Null)
                    }
                    ErrorKind::NotFound => ("invalid_request_error", json!("model_not_found")),
                    ErrorKind::QuotaExhausted => {
                        ("insufficient_quota", json!("insufficient_quota"))
                    }
                    ErrorKind::Config | ErrorKind::Upstream(_) => ("api_error", Value::Null),
                };
                json!({ "error": { "message": message, "type": ty, "code": code } })
            }
        }
    }
}

/// The model list for `api`: the VM's aliases, never the upstream names.
pub fn model_list(api: Api, aliases: &[String]) -> Value {
    match api {
        Api::Openai => json!({
            "object": "list",
            "data": aliases.iter().map(|a| json!({
                "id": a, "object": "model", "created": 0, "owned_by": "sodabox",
            })).collect::<Vec<_>>(),
        }),
        Api::Ollama => json!({
            "models": aliases.iter().map(|a| json!({
                "name": a, "model": a, "modified_at": "1970-01-01T00:00:00Z",
                "size": 0, "digest": "", "details": {},
            })).collect::<Vec<_>>(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_by_path_without_prefix() {
        assert_eq!(
            Route::find(&Method::POST, "/v1/chat/completions"),
            Some(Route::OpenaiChat)
        );
        assert_eq!(
            Route::find(&Method::POST, "/api/chat/"),
            Some(Route::OllamaChat)
        );
        assert_eq!(Route::find(&Method::GET, "/"), Some(Route::Root));
        assert_eq!(Route::find(&Method::GET, "/v1/chat/completions"), None);
        assert_eq!(Route::find(&Method::POST, "/v1/responses"), None);
        assert_eq!(Route::api_of_path("/api/pull"), Api::Ollama);
    }

    #[test]
    fn provider_compatibility() {
        assert!(Api::Openai.serves(ProviderApi::Mistral));
        assert!(Api::Openai.serves(ProviderApi::Openai));
        assert!(!Api::Openai.serves(ProviderApi::Ollama));
        assert!(Api::Ollama.serves(ProviderApi::Ollama));
        assert!(!Api::Ollama.serves(ProviderApi::Mistral));
    }

    #[test]
    fn streaming_defaults_differ_per_api() {
        assert!(!Route::OpenaiChat.streams(&json!({})));
        assert!(Route::OpenaiChat.streams(&json!({"stream": true})));
        assert!(Route::OllamaChat.streams(&json!({})));
        assert!(!Route::OllamaGenerate.streams(&json!({"stream": false})));
    }

    #[test]
    fn quota_errors_are_the_no_retry_kind() {
        let k = ErrorKind::QuotaExhausted;
        assert_eq!(k.status(Api::Openai), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            k.body(Api::Openai, "m")["error"]["code"],
            "insufficient_quota"
        );
        assert_eq!(k.status(Api::Ollama), StatusCode::FORBIDDEN);
        assert_eq!(k.body(Api::Ollama, "m"), json!({"error": "m"}));
    }
}
