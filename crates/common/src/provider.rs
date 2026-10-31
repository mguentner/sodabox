//! Inference providers (ADR-0020): where the gateway sends a model alias's
//! requests, and how it authenticates there.
//!
//! A provider is a TOML file in [`paths::providers_dir`], host-wide and never
//! copied into a VM. It holds the *how* (endpoint, API kind, credential
//! source); a VM's `policy.toml` holds the *what* (which aliases use it).
//! sodabox stores no secret itself: the credential comes from a command or an
//! environment variable when the gateway first needs it.

use serde::{Deserialize, Serialize};

use crate::paths;

/// The API a provider speaks upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderApi {
    /// OpenAI-compatible Chat Completions (OpenAI, OpenRouter, vLLM,
    /// Ollama's `/v1`, …). `base_url` ends in the version path, e.g. `…/v1`.
    Openai,
    /// Mistral's API: Chat Completions like `openai`, with Mistral's own
    /// usage reporting. `base_url` is e.g. `https://api.mistral.ai/v1`.
    Mistral,
    /// Ollama's native API (`/api/chat`, `/api/generate`). `base_url` is the
    /// server root, e.g. `http://127.0.0.1:11434`.
    Ollama,
}

impl std::fmt::Display for ProviderApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ProviderApi::Openai => "openai",
            ProviderApi::Mistral => "mistral",
            ProviderApi::Ollama => "ollama",
        })
    }
}

/// How the gateway authenticates to the provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Auth {
    /// Header that carries the credential (default `authorization`).
    #[serde(default = "default_auth_header")]
    pub header: String,
    /// Prefix before the credential, e.g. `Bearer` (the default for the
    /// `authorization` header). Set to `""` for none.
    #[serde(default)]
    pub scheme: Option<String>,
    /// Command whose trimmed stdout is the credential, e.g.
    /// `["pass", "show", "llm/mistral"]`.
    #[serde(default)]
    pub command: Option<Vec<String>>,
    /// Environment variable of the supervisor that holds the credential.
    #[serde(default)]
    pub env: Option<String>,
}

fn default_auth_header() -> String {
    "authorization".to_string()
}

impl Auth {
    /// The prefix written before the credential.
    pub fn scheme(&self) -> &str {
        match &self.scheme {
            Some(s) => s,
            None if self.header.eq_ignore_ascii_case("authorization") => "Bearer",
            None => "",
        }
    }
}

/// A provider file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSpec {
    #[serde(default)]
    pub description: Option<String>,
    pub api: ProviderApi,
    pub base_url: String,
    #[serde(default)]
    pub auth: Option<Auth>,
}

/// A loaded, validated provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provider {
    pub name: String,
    pub spec: ProviderSpec,
}

impl Provider {
    /// Parse and validate a provider named `name` from `text`.
    pub fn parse(name: &str, text: &str) -> Result<Provider, String> {
        validate_name(name)?;
        let spec: ProviderSpec =
            toml::from_str(text).map_err(|e| format!("provider '{name}': {e}"))?;
        let url = &spec.base_url;
        if !(url.starts_with("https://") || url.starts_with("http://")) {
            return Err(format!(
                "provider '{name}': base_url must start with http:// or https://"
            ));
        }
        if let Some(auth) = &spec.auth {
            match (&auth.command, &auth.env) {
                (Some(cmd), None) if !cmd.is_empty() => {}
                (None, Some(var)) if !var.is_empty() => {}
                _ => {
                    return Err(format!(
                        "provider '{name}': auth needs exactly one of `command` or `env`"
                    ))
                }
            }
            if auth.header.is_empty() || !auth.header.bytes().all(is_header_name_byte) {
                return Err(format!("provider '{name}': invalid auth header name"));
            }
        }
        Ok(Provider {
            name: name.to_string(),
            spec,
        })
    }

    /// Load `<providers dir>/<name>.toml`.
    pub fn load(name: &str) -> Result<Provider, String> {
        validate_name(name)?;
        let path = paths::provider_path(name);
        let text = std::fs::read_to_string(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                format!("no provider '{name}' (expected {})", path.display())
            }
            _ => format!("reading {}: {e}", path.display()),
        })?;
        Provider::parse(name, &text)
    }
}

/// RFC 9110 token characters, the bytes a header name may have.
fn is_header_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// A provider name follows the profile name rules (it becomes a file name).
pub fn validate_name(name: &str) -> Result<(), String> {
    crate::profile::validate_name(name).map_err(|_| {
        format!("invalid provider name '{name}': use lowercase letters, digits, '-' and '_'")
    })
}

/// Names of the providers in [`paths::providers_dir`], sorted. A missing dir
/// is an empty list.
pub fn list() -> std::io::Result<Vec<String>> {
    let entries = match std::fs::read_dir(paths::providers_dir()) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut names = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") || !path.is_file() {
            continue;
        }
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            if validate_name(stem).is_ok() {
                names.push(stem.to_string());
            }
        }
    }
    names.sort();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MISTRAL: &str = r#"
description = "Mistral La Plateforme"
api = "mistral"
base_url = "https://api.mistral.ai/v1"
auth = { command = ["pass", "show", "llm/mistral"] }
"#;

    #[test]
    fn parses_a_provider_with_command_auth() {
        let p = Provider::parse("mistral", MISTRAL).unwrap();
        assert_eq!(p.spec.api, ProviderApi::Mistral);
        let auth = p.spec.auth.unwrap();
        assert_eq!(auth.header, "authorization");
        assert_eq!(auth.scheme(), "Bearer");
    }

    #[test]
    fn local_ollama_needs_no_auth() {
        let p = Provider::parse(
            "local",
            "api = \"ollama\"\nbase_url = \"http://127.0.0.1:11434\"\n",
        )
        .unwrap();
        assert!(p.spec.auth.is_none());
    }

    #[test]
    fn custom_header_has_no_default_scheme() {
        let text = "api = \"openai\"\nbase_url = \"https://x.test/v1\"\n\
                    auth = { header = \"x-api-key\", env = \"KEY\" }\n";
        let auth = Provider::parse("x", text).unwrap().spec.auth.unwrap();
        assert_eq!(auth.scheme(), "");
    }

    #[test]
    fn rejects_bad_files() {
        // Unknown key.
        assert!(Provider::parse(
            "a",
            "api = \"openai\"\nbase_url = \"https://x/v1\"\nkey = \"s\"\n"
        )
        .is_err());
        // Unknown API kind.
        assert!(Provider::parse("a", "api = \"anthropic\"\nbase_url = \"https://x\"\n").is_err());
        // Not an http(s) URL.
        assert!(Provider::parse("a", "api = \"openai\"\nbase_url = \"file:///x\"\n").is_err());
        // Both or neither credential source.
        let both = "api = \"openai\"\nbase_url = \"https://x\"\n\
                    auth = { command = [\"a\"], env = \"B\" }\n";
        assert!(Provider::parse("a", both).is_err());
        let neither = "api = \"openai\"\nbase_url = \"https://x\"\nauth = {}\n";
        assert!(Provider::parse("a", neither).is_err());
        // Header injection via the header name.
        let bad_header = "api = \"openai\"\nbase_url = \"https://x\"\n\
                          auth = { header = \"a\\r\\nb\", env = \"K\" }\n";
        assert!(Provider::parse("a", bad_header).is_err());
        // Path traversal via the name.
        assert!(Provider::parse("../x", MISTRAL).is_err());
    }
}
