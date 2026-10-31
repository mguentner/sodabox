//! Dynamic shell completion (clap_complete's `CompleteEnv`).
//!
//! The shell re-invokes `soda` with `COMPLETE=<shell>` on every Tab, so these
//! completers run on each keypress: they only read directories, never sync
//! vendor profiles or print, and treat any error as "no candidates".

use clap_complete::engine::CompletionCandidate;
use sodabox_common::{paths, profile, vm::VmMeta};

/// Existing VMs, with their persistence mode as the description.
pub fn vms() -> Vec<CompletionCandidate> {
    VmMeta::list()
        .unwrap_or_default()
        .into_iter()
        .map(|m| CompletionCandidate::new(&m.name).help(Some(m.persist.as_str().into())))
        .collect()
}

/// Profiles in the profiles dir plus the vendor ones, which may not have been
/// written there yet (that happens on the first `create`/`profile` command).
pub fn profiles() -> Vec<CompletionCandidate> {
    let mut names = profile::list().unwrap_or_default();
    names.extend(crate::profile::vendor_names().map(str::to_string));
    names.sort();
    names.dedup();
    names.into_iter().map(CompletionCandidate::new).collect()
}

/// Dotfile collections: the folders in the dotfiles dir with a valid name.
pub fn dotfiles() -> Vec<CompletionCandidate> {
    let Ok(entries) = std::fs::read_dir(paths::dotfiles_dir()) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| sodabox_common::dotfiles::validate_name(n).is_ok())
        .collect();
    names.sort();
    names.into_iter().map(CompletionCandidate::new).collect()
}

/// Services a `service` rule can grant (ADR-0020).
pub fn services() -> Vec<CompletionCandidate> {
    sodabox_common::policy::SERVICES
        .iter()
        .map(|s| CompletionCandidate::new(*s))
        .collect()
}

/// Inference providers in the providers dir (ADR-0020).
pub fn providers() -> Vec<CompletionCandidate> {
    sodabox_common::provider::list()
        .unwrap_or_default()
        .into_iter()
        .map(CompletionCandidate::new)
        .collect()
}

/// Model aliases of every VM, with the VM as the description. The completer
/// can't see `--vm`, so it offers all of them.
pub fn models() -> Vec<CompletionCandidate> {
    let mut out = Vec::new();
    for m in VmMeta::list().unwrap_or_default() {
        if let Ok(p) = sodabox_common::policy::VmPolicy::load(&m.name) {
            for a in p.models {
                out.push(CompletionCandidate::new(a.alias).help(Some(m.name.clone().into())));
            }
        }
    }
    out
}
