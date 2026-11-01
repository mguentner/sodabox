//! `soda provider test`: check that a provider works before a VM depends on
//! it (ADR-0020).
//!
//! The probe fetches the credential the way the gateway does and asks the
//! provider for its model list with it: `GET {base_url}/models` for
//! OpenAI-compatible and Mistral providers, `GET {base_url}/api/tags` for
//! Ollama. Listing models costs no tokens, and the list helps pick the
//! upstream name for `soda model add`. The credential itself is never part
//! of the result.

use std::time::Instant;

use hyper::StatusCode;
use serde_json::Value;
use sodabox_common::provider::{Provider, ProviderApi};

use crate::creds::Credentials;
use crate::{auth_header, error_chain, http_client, read_error_body};

/// What a successful probe found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    /// Whether a credential was fetched (false: the provider needs none).
    pub credential: bool,
    pub status: u16,
    pub latency_ms: u64,
    /// The models the provider offers, as it names them.
    pub models: Vec<String>,
}

/// Where a probe failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeError {
    /// The credential command or variable failed.
    Credential(String),
    /// The provider couldn't be reached (DNS, connect, TLS, timeout).
    Unreachable(String),
    /// The provider rejected the credential (401/403).
    Rejected(u16, String),
    /// Any other HTTP error.
    Http(u16, String),
    /// The answer wasn't a model list.
    BadResponse(String),
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeError::Credential(e) => write!(f, "{e}"),
            ProbeError::Unreachable(e) => write!(f, "unreachable: {e}"),
            ProbeError::Rejected(s, d) => write!(f, "credential rejected ({s}): {d}"),
            ProbeError::Http(s, d) => write!(f, "provider returned {s}: {d}"),
            ProbeError::BadResponse(e) => write!(f, "unexpected answer: {e}"),
        }
    }
}

/// The path of the model list, relative to `base_url`.
pub fn models_path(api: ProviderApi) -> &'static str {
    match api {
        ProviderApi::Openai | ProviderApi::Mistral => "/models",
        ProviderApi::Ollama => "/api/tags",
    }
}

/// Probe `provider`.
pub async fn probe(provider: &Provider) -> Result<Probe, ProbeError> {
    let secret = Credentials::default()
        .get(provider)
        .await
        .map_err(ProbeError::Credential)?;
    let client = http_client().map_err(ProbeError::Unreachable)?;
    let url = format!(
        "{}{}",
        provider.spec.base_url.trim_end_matches('/'),
        models_path(provider.spec.api)
    );
    let mut req = client.get(&url);
    if let Some((header, value)) =
        auth_header(provider, secret.as_deref()).map_err(ProbeError::Credential)?
    {
        req = req.header(header, value);
    }

    let started = Instant::now();
    let resp = req
        .send()
        .await
        .map_err(|e| ProbeError::Unreachable(error_chain(e)))?;
    let status = resp.status();
    if !status.is_success() {
        let detail = read_error_body(resp, secret.as_deref()).await;
        return Err(
            if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
                ProbeError::Rejected(status.as_u16(), detail)
            } else {
                ProbeError::Http(status.as_u16(), detail)
            },
        );
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| ProbeError::Unreachable(error_chain(e)))?;
    let body: Value = serde_json::from_slice(&bytes)
        .map_err(|e| ProbeError::BadResponse(format!("not JSON: {e}")))?;
    let latency_ms = started.elapsed().as_millis() as u64;
    let models = model_names(provider.spec.api, &body).ok_or_else(|| {
        ProbeError::BadResponse(format!(
            "no model list at {}",
            models_path(provider.spec.api)
        ))
    })?;
    Ok(Probe {
        credential: secret.is_some(),
        status: status.as_u16(),
        latency_ms,
        models,
    })
}

/// The model names in a model-list answer: `data[].id` (OpenAI, Mistral) or
/// `models[].name` (Ollama).
fn model_names(api: ProviderApi, body: &Value) -> Option<Vec<String>> {
    let (list, key) = match api {
        ProviderApi::Openai | ProviderApi::Mistral => (body.get("data")?, "id"),
        ProviderApi::Ollama => (body.get("models")?, "name"),
    };
    Some(
        list.as_array()?
            .iter()
            .filter_map(|m| m.get(key)?.as_str().map(str::to_string))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn model_lists_per_api() {
        let openai = json!({"object": "list", "data": [{"id": "a"}, {"id": "b"}]});
        assert_eq!(
            model_names(ProviderApi::Mistral, &openai),
            Some(vec!["a".into(), "b".into()])
        );
        let ollama = json!({"models": [{"name": "qwen3:0.6b"}]});
        assert_eq!(
            model_names(ProviderApi::Ollama, &ollama),
            Some(vec!["qwen3:0.6b".into()])
        );
        assert_eq!(model_names(ProviderApi::Openai, &ollama), None);
    }
}
