//! Git-native host↔guest sync transport (ADR-0013). The host's git treats the
//! VM as a remote via git's `ext::` helper, which re-invokes `sodabox
//! git-proxy` once per push/fetch — so, unlike a baked-in `ssh://` URL, the
//! remote URL hard-codes no port and cannot go stale: the live endpoint is read
//! from the VM's runtime dir on every push/fetch ([`crate::ssh::SshEndpoint`],
//! ADR-0011), which also makes "VM not running" a real error message
//! rather than a connection refused.

use std::ffi::OsString;

/// Environment override for the `git` binary (pinned on PATH by the
/// packaging wrapper, ADR-0010). Defaults to `git`.
const GIT_ENV: &str = "SODABOX_GIT";

/// The `git` binary to drive (`$SODABOX_GIT` or `git`).
pub fn git_bin() -> OsString {
    std::env::var_os(GIT_ENV).unwrap_or_else(|| "git".into())
}

/// The `ext::` URL sodabox configures for VM `vm`/user `user`. Per
/// git-remote-ext(1): command and arguments are split on *unescaped* spaces
/// (no shell involved — quoting does nothing), and `%S` is substituted with
/// the long service name (`git-upload-pack`/`git-receive-pack`) wherever it
/// appears — git does **not** append it as an extra trailing argument on its
/// own, so the placeholder must be given explicitly.
pub fn remote_ext_url(vm: &str, user: &str) -> String {
    format!(
        "ext::soda git-proxy {} --user {} %S",
        remote_ext_escape(vm),
        remote_ext_escape(user)
    )
}

/// Escapes `s` per git-remote-ext(1)'s own grammar: `%` must become `%%` and
/// a literal space must become `% ` (percent order matters — escaping `%`
/// first means the `%` introduced by the space rule is never re-escaped).
fn remote_ext_escape(s: &str) -> String {
    s.replace('%', "%%").replace(' ', "% ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_ext_url_carries_vm_and_user_and_ends_with_service_placeholder() {
        let url = remote_ext_url("web", "dev");
        assert_eq!(url, "ext::soda git-proxy web --user dev %S");
    }

    #[test]
    fn remote_ext_escape_protects_percent_and_space() {
        assert_eq!(remote_ext_escape("100%"), "100%%");
        assert_eq!(remote_ext_escape("a b"), "a% b");
        assert_eq!(remote_ext_escape("a% b"), "a%%% b");
    }
}
