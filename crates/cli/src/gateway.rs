//! The inference gateway's verbs (ADR-0020): `soda gateway`, `soda provider`,
//! `soda model` and `soda quota`.
//!
//! Gateway settings and model aliases are policy, so they go through the same
//! persist-then-push path as `soda allow` ([`crate::apply_edit`]). Token
//! grants are not policy: they are appended to the VM's quota ledger, and a
//! running supervisor is told to re-read it.

use clap::Subcommand;
use clap_complete::engine::ArgValueCandidates;

use sodabox_common::event::now_ts;
use sodabox_common::policy::{ModelChange, QuotaMode, VmPolicy};
use sodabox_common::protocol::{Request, Response};
use sodabox_common::provider::{self, Provider};
use sodabox_common::quota::{self, Balances, Entry, Ledger, Reason};
use sodabox_supervisor::control::ControlClient;

use crate::{apply_edit, complete, is_not_running, resolve_vm, rt};

#[derive(Subcommand)]
pub enum GatewayAction {
    /// switch the gateway on (access also needs `soda allow service inference`)
    Enable {
        #[arg(long, add = ArgValueCandidates::new(complete::vms))]
        vm: Option<String>,
    },
    /// switch the gateway off
    Disable {
        #[arg(long, add = ArgValueCandidates::new(complete::vms))]
        vm: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum ProviderAction {
    /// list the providers in $XDG_CONFIG_HOME/sodabox/providers/
    Ls,
    /// print a provider file
    Show {
        #[arg(add = ArgValueCandidates::new(complete::providers))]
        name: String,
    },
}

#[derive(Subcommand)]
pub enum ModelAction {
    /// list a VM's model aliases
    Ls {
        #[arg(long, add = ArgValueCandidates::new(complete::vms))]
        vm: Option<String>,
    },
    /// add an alias, or re-point an existing one (its balance is kept)
    Add {
        /// the name the guest uses, e.g. foo:13b
        alias: String,
        /// <provider>/<upstream model>, e.g. local/the_actual_foo:13b
        target: String,
        /// balance the alias starts with on first use, e.g. 500k (default 0)
        #[arg(long)]
        initial_quota: Option<String>,
        #[arg(long, add = ArgValueCandidates::new(complete::vms))]
        vm: Option<String>,
    },
    /// remove an alias (its ledger history is kept)
    Rm {
        #[arg(add = ArgValueCandidates::new(complete::models))]
        alias: String,
        #[arg(long, add = ArgValueCandidates::new(complete::vms))]
        vm: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum QuotaAction {
    /// show token balances
    Show {
        #[arg(long, add = ArgValueCandidates::new(complete::vms))]
        vm: Option<String>,
    },
    /// grant tokens to an alias, e.g. `soda quota grant foo:13b 2M`
    Grant {
        #[arg(add = ArgValueCandidates::new(complete::models))]
        alias: String,
        /// a count like 1500, 500k or 2M
        tokens: String,
        #[arg(long, add = ArgValueCandidates::new(complete::vms))]
        vm: Option<String>,
    },
    /// stop metering an alias, or the whole VM if no alias is given
    Unlimited {
        #[arg(add = ArgValueCandidates::new(complete::models))]
        alias: Option<String>,
        #[arg(long, add = ArgValueCandidates::new(complete::vms))]
        vm: Option<String>,
    },
    /// meter an alias again, or the whole VM if no alias is given
    Limited {
        #[arg(add = ArgValueCandidates::new(complete::models))]
        alias: Option<String>,
        #[arg(long, add = ArgValueCandidates::new(complete::vms))]
        vm: Option<String>,
    },
}

/// `soda gateway enable|disable`.
pub fn gateway(action: GatewayAction) -> anyhow::Result<()> {
    let (enable, vm) = match action {
        GatewayAction::Enable { vm } => (true, vm),
        GatewayAction::Disable { vm } => (false, vm),
    };
    let vm = resolve_vm(vm)?;
    apply_edit(&vm, |file| {
        if !file
            .set_gateway_enabled(enable)
            .map_err(|e| anyhow::anyhow!(e))?
        {
            return Ok(None);
        }
        let policy = file.policy().map_err(|e| anyhow::anyhow!(e))?;
        if enable && !policy.allows_service(sodabox_common::policy::INFERENCE_SERVICE) {
            println!(
                "note: the guest can't reach it yet; grant access with `soda allow service inference --vm {vm}`"
            );
        }
        Ok(Some(format!(
            "gateway {}",
            if enable { "enabled" } else { "disabled" }
        )))
    })
}

/// `soda provider ls|show`.
pub fn provider(action: ProviderAction) -> anyhow::Result<()> {
    match action {
        ProviderAction::Ls => {
            let names = provider::list()?;
            if names.is_empty() {
                println!(
                    "no providers in {}",
                    sodabox_common::paths::providers_dir().display()
                );
                return Ok(());
            }
            for name in names {
                match Provider::load(&name) {
                    Ok(p) => println!(
                        "{name:<20} {:<8} {:<40} {}",
                        p.spec.api,
                        p.spec.base_url,
                        auth_source(&p)
                    ),
                    Err(e) => println!("{name:<20} invalid: {e}"),
                }
            }
            Ok(())
        }
        ProviderAction::Show { name } => {
            // Validates the file too; it holds no secret, only where to get one.
            Provider::load(&name).map_err(|e| anyhow::anyhow!(e))?;
            print!(
                "{}",
                std::fs::read_to_string(sodabox_common::paths::provider_path(&name))?
            );
            Ok(())
        }
    }
}

/// Where a provider's credential comes from, without the credential.
fn auth_source(p: &Provider) -> String {
    match &p.spec.auth {
        None => "no auth".to_string(),
        Some(a) => match (&a.command, &a.env) {
            (Some(cmd), _) => format!("command: {}", cmd.first().map_or("", String::as_str)),
            (_, Some(var)) => format!("env: {var}"),
            _ => "auth: ?".to_string(),
        },
    }
}

/// `soda model ls|add|rm`.
pub fn model(action: ModelAction) -> anyhow::Result<()> {
    match action {
        ModelAction::Ls { vm } => {
            let vm = resolve_vm(vm)?;
            let policy = VmPolicy::load(&vm)?;
            if policy.models.is_empty() {
                println!("'{vm}' has no model aliases (add one with `soda model add`)");
                return Ok(());
            }
            for m in &policy.models {
                let api = match Provider::load(&m.provider) {
                    Ok(p) => p.spec.api.to_string(),
                    Err(_) => "missing provider".to_string(),
                };
                let mode = if policy.is_metered(&m.alias) {
                    "limited"
                } else {
                    "unlimited"
                };
                println!(
                    "{:<24} -> {}/{}  ({api}, {mode})",
                    m.alias, m.provider, m.model
                );
            }
            Ok(())
        }
        ModelAction::Add {
            alias,
            target,
            initial_quota,
            vm,
        } => {
            let vm = resolve_vm(vm)?;
            let (provider_name, upstream) = target.split_once('/').ok_or_else(|| {
                anyhow::anyhow!("target must be <provider>/<model>, e.g. local/llama3.2")
            })?;
            let initial = initial_quota
                .as_deref()
                .map(quota::parse_tokens)
                .transpose()
                .map_err(|e| anyhow::anyhow!(e))?;
            if let Err(e) = Provider::load(provider_name) {
                println!("warning: {e}");
            }
            apply_edit(&vm, |file| {
                let change = file
                    .set_model(&alias, provider_name, upstream, initial)
                    .map_err(|e| anyhow::anyhow!(e))?;
                Ok(match change {
                    ModelChange::Added => Some(format!("added {alias} -> {target}")),
                    ModelChange::Repointed => Some(format!(
                        "re-pointed {alias} -> {target} (its balance is kept)"
                    )),
                    ModelChange::Unchanged => None,
                })
            })
        }
        ModelAction::Rm { alias, vm } => {
            let vm = resolve_vm(vm)?;
            apply_edit(&vm, |file| {
                if !file.remove_model(&alias).map_err(|e| anyhow::anyhow!(e))? {
                    anyhow::bail!("'{vm}' has no model alias '{alias}'");
                }
                Ok(Some(format!(
                    "removed {alias} (its quota history stays in the ledger)"
                )))
            })
        }
    }
}

/// `soda quota show|grant|unlimited|limited`.
pub fn quota(action: QuotaAction) -> anyhow::Result<()> {
    match action {
        QuotaAction::Show { vm } => show(&resolve_vm(vm)?),
        QuotaAction::Grant { alias, tokens, vm } => {
            let vm = resolve_vm(vm)?;
            grant(&vm, &alias, &tokens)
        }
        QuotaAction::Unlimited { alias, vm } => {
            set_mode(&resolve_vm(vm)?, alias, QuotaMode::Unlimited)
        }
        QuotaAction::Limited { alias, vm } => set_mode(&resolve_vm(vm)?, alias, QuotaMode::Limited),
    }
}

fn set_mode(vm: &str, alias: Option<String>, mode: QuotaMode) -> anyhow::Result<()> {
    let what = match &alias {
        Some(a) => format!("'{a}'"),
        None => format!("all aliases on '{vm}'"),
    };
    let word = match mode {
        QuotaMode::Unlimited => "unlimited",
        QuotaMode::Limited => "limited",
    };
    apply_edit(vm, |file| {
        let changed = file
            .set_quota_mode(alias.as_deref(), mode)
            .map_err(|e| anyhow::anyhow!(e))?;
        Ok(changed.then(|| format!("quota for {what}: {word}")))
    })
}

fn grant(vm: &str, alias: &str, tokens: &str) -> anyhow::Result<()> {
    if !sodabox_common::vm::VmMeta::path(vm).is_file() {
        anyhow::bail!("no such VM '{vm}' — run `soda create {vm}` first");
    }
    let n = quota::parse_tokens(tokens).map_err(|e| anyhow::anyhow!(e))?;
    let delta = i64::try_from(n).map_err(|_| anyhow::anyhow!("token count too large"))?;
    let policy = VmPolicy::load(vm)?;
    if policy.model(alias).is_none() {
        println!("warning: '{vm}' has no model alias '{alias}' yet; the grant waits for it");
    }
    let ledger = Ledger::for_vm(vm);
    ledger.append(&Entry {
        ts: now_ts(),
        alias: alias.to_string(),
        delta,
        reason: Reason::Grant,
        tokens: None,
    })?;
    let balance = ledger.load()?.get(alias).map_or(0, |b| b.balance);
    println!("granted {n} tokens to '{alias}' on '{vm}' (balance {balance})");

    rt()?.block_on(async {
        let mut client = match ControlClient::connect(vm).await {
            Ok(c) => c,
            Err(e) if is_not_running(&e) => return Ok(()),
            Err(e) => anyhow::bail!("connecting to '{vm}' control socket: {e}"),
        };
        match client.request(&Request::QuotaReload).await? {
            Response::Ok => {
                println!("applied live to running VM '{vm}'");
                Ok(())
            }
            Response::Error { msg } => {
                println!("note: the running VM did not reload its quota: {msg}");
                Ok(())
            }
            other => anyhow::bail!("unexpected response from '{vm}': {other:?}"),
        }
    })
}

fn show(vm: &str) -> anyhow::Result<()> {
    let policy = VmPolicy::load(vm)?;
    // The running gateway's view is the live one; otherwise read the ledger.
    let live = rt()?.block_on(async {
        let mut c = ControlClient::connect(vm).await.ok()?;
        match c.request(&Request::QuotaGet).await.ok()? {
            Response::Quota { balances } => Some(balances),
            _ => None,
        }
    });
    let balances = match live {
        Some(b) => b,
        None => Ledger::for_vm(vm).load()?,
    };
    print_balances(&policy, &balances);
    Ok(())
}

fn print_balances(policy: &VmPolicy, balances: &Balances) {
    let gateway = policy.gateway.as_ref().is_some_and(|g| g.enabled);
    let access = policy.allows_service(sodabox_common::policy::INFERENCE_SERVICE);
    println!(
        "gateway: {}, guest access: {}",
        if gateway { "enabled" } else { "disabled" },
        if access { "granted" } else { "not granted" }
    );
    println!(
        "{:<24} {:>12} {:>12} {:>12} {:>12}",
        "ALIAS", "BALANCE", "GRANTED", "USED", "UNMETERED"
    );
    let mut aliases: Vec<&str> = policy.models.iter().map(|m| m.alias.as_str()).collect();
    // Removed aliases still have a history; show it too.
    for a in balances.keys() {
        if !aliases.contains(&a.as_str()) {
            aliases.push(a);
        }
    }
    for alias in aliases {
        let b = balances.get(alias).cloned().unwrap_or_default();
        let model = policy.model(alias);
        let balance = if model.is_some() && !policy.is_metered(alias) {
            "unlimited".to_string()
        } else if !b.initialized {
            // The initial balance is written on first use.
            let initial = model.and_then(|m| m.initial_quota).unwrap_or(0) as i64;
            (b.balance + initial).to_string()
        } else {
            b.balance.to_string()
        };
        let note = if model.is_none() { "  (removed)" } else { "" };
        println!(
            "{alias:<24} {balance:>12} {:>12} {:>12} {:>12}{note}",
            b.granted, b.used, b.unmetered
        );
    }
}
