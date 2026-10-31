//! Provider credentials, fetched on first use and kept in memory only.
//!
//! sodabox stores no secrets (ADR-0019, ADR-0020): a provider names a command
//! (e.g. `pass show llm/mistral`) or an environment variable, and the
//! gateway asks for the credential when a request first needs it. A provider
//! that rejects it (401/403) has its cached copy dropped, so a rotated key is
//! fetched again on the next request.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use sodabox_common::provider::{Auth, Provider};

/// How long a credential command may take.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Default)]
pub struct Credentials {
    cache: Mutex<HashMap<String, String>>,
}

impl Credentials {
    /// The credential for `provider`, or `None` if it needs none.
    pub async fn get(&self, provider: &Provider) -> Result<Option<String>, String> {
        let Some(auth) = &provider.spec.auth else {
            return Ok(None);
        };
        if let Some(c) = self.cached(&provider.name) {
            return Ok(Some(c));
        }
        let secret = fetch(&provider.name, auth).await?;
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(provider.name.clone(), secret.clone());
        }
        Ok(Some(secret))
    }

    /// Forget `provider`'s credential, e.g. after the provider rejected it.
    pub fn forget(&self, provider: &str) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.remove(provider);
        }
    }

    fn cached(&self, provider: &str) -> Option<String> {
        self.cache.lock().ok()?.get(provider).cloned()
    }
}

async fn fetch(name: &str, auth: &Auth) -> Result<String, String> {
    let secret = if let Some(var) = &auth.env {
        std::env::var(var)
            .map_err(|_| format!("provider '{name}': environment variable {var} is not set"))?
    } else if let Some([program, args @ ..]) = auth.command.as_deref() {
        let out = tokio::time::timeout(
            COMMAND_TIMEOUT,
            tokio::process::Command::new(program)
                .args(args)
                .stdin(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .map_err(|_| format!("provider '{name}': credential command timed out"))?
        .map_err(|e| format!("provider '{name}': running credential command {program}: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "provider '{name}': credential command {program} failed ({})",
                out.status
            ));
        }
        String::from_utf8(out.stdout)
            .map_err(|_| format!("provider '{name}': credential is not UTF-8"))?
    } else {
        return Err(format!("provider '{name}': auth has no credential source"));
    };
    // `pass` and friends print a trailing newline; only the first line counts.
    let secret = secret.lines().next().unwrap_or("").trim().to_string();
    if secret.is_empty() {
        return Err(format!("provider '{name}': credential is empty"));
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(auth: &str) -> Provider {
        Provider::parse(
            "p",
            &format!("api = \"openai\"\nbase_url = \"https://x/v1\"\nauth = {auth}\n"),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn command_output_first_line_is_the_secret_and_is_cached() {
        let creds = Credentials::default();
        let p = provider(r#"{ command = ["printf", "sk-123\nsecond line\n"] }"#);
        assert_eq!(creds.get(&p).await.unwrap().as_deref(), Some("sk-123"));
        assert_eq!(creds.cached("p").as_deref(), Some("sk-123"));
        creds.forget("p");
        assert_eq!(creds.cached("p"), None);
    }

    #[tokio::test]
    async fn failing_or_empty_commands_are_errors() {
        let creds = Credentials::default();
        assert!(creds
            .get(&provider(r#"{ command = ["false"] }"#))
            .await
            .is_err());
        assert!(creds
            .get(&provider(r#"{ command = ["true"] }"#))
            .await
            .is_err());
        assert!(creds
            .get(&provider(r#"{ env = "SODABOX_TEST_UNSET_VAR" }"#))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn no_auth_needs_no_credential() {
        let p = Provider::parse(
            "o",
            "api = \"ollama\"\nbase_url = \"http://127.0.0.1:11434\"\n",
        )
        .unwrap();
        assert_eq!(Credentials::default().get(&p).await, Ok(None));
    }
}
