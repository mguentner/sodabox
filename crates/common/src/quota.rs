//! Token quota ledger (ADR-0020).
//!
//! Each VM has a token balance per model alias. Balances are state, not
//! policy, so they live in an append-only ledger in the VM's data dir
//! ([`paths::quota_ledger_path`]), one JSON object per line. The balance of an
//! alias is the sum of its deltas. The ledger is also the audit trail of what
//! was granted and used, and it survives restarts, so restarting a VM never
//! refills it.
//!
//! Two processes append: the supervisor (initial balances and usage) and the
//! CLI (grants). Each entry is one `write` on an `O_APPEND` file, so lines
//! never interleave.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::paths;

/// Why an entry was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Reason {
    /// The alias's first use: its `initial_quota` (often 0).
    Initial,
    /// Tokens granted by the user.
    Grant,
    /// Tokens used by a request on a metered alias (negative delta).
    Usage,
    /// Tokens used while the alias was unlimited: recorded, delta 0.
    Unmetered,
}

/// One ledger line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub ts: u64,
    pub alias: String,
    pub delta: i64,
    pub reason: Reason,
    /// Tokens a usage entry stands for (for `unmetered`, where delta is 0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<u64>,
}

/// One alias's state, summed from the ledger.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Balance {
    /// Tokens left. Can be negative: a request is never cut off mid-stream.
    pub balance: i64,
    /// Whether the `initial` entry has been written.
    pub initialized: bool,
    /// Total tokens granted (including the initial balance).
    pub granted: u64,
    /// Total metered tokens used.
    pub used: u64,
    /// Total tokens used while unlimited.
    pub unmetered: u64,
}

impl Balance {
    /// Fold one ledger entry into the balance.
    pub fn apply(&mut self, e: &Entry) {
        self.balance = self.balance.saturating_add(e.delta);
        match e.reason {
            Reason::Initial => {
                self.initialized = true;
                self.granted = self.granted.saturating_add(e.delta.max(0) as u64);
            }
            Reason::Grant => self.granted = self.granted.saturating_add(e.delta.max(0) as u64),
            Reason::Usage => self.used = self.used.saturating_add(e.delta.unsigned_abs()),
            Reason::Unmetered => {
                self.unmetered = self.unmetered.saturating_add(e.tokens.unwrap_or(0))
            }
        }
    }
}

/// Balances by alias.
pub type Balances = BTreeMap<String, Balance>;

/// A VM's ledger file.
#[derive(Debug, Clone)]
pub struct Ledger {
    path: PathBuf,
}

impl Ledger {
    /// The ledger of `vm`.
    pub fn for_vm(vm: &str) -> Ledger {
        Ledger::at(paths::quota_ledger_path(vm))
    }

    pub fn at(path: impl Into<PathBuf>) -> Ledger {
        Ledger { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append `entry` as one line and flush it to disk.
    pub fn append(&self, entry: &Entry) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(entry)?;
        line.push(b'\n');
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        // One write per line, so concurrent appenders never interleave.
        f.write_all(&line)?;
        f.sync_data()
    }

    /// Sum the ledger into balances. A missing file is an empty ledger. A
    /// malformed line is an error: guessing a balance could hand out tokens
    /// that were never granted (fail closed).
    pub fn load(&self) -> std::io::Result<Balances> {
        let f = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Balances::new()),
            Err(e) => return Err(e),
        };
        let mut balances = Balances::new();
        for (i, line) in std::io::BufReader::new(f).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: Entry = serde_json::from_str(&line).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{} line {}: {e}", self.path.display(), i + 1),
                )
            })?;
            balances
                .entry(entry.alias.clone())
                .or_default()
                .apply(&entry);
        }
        Ok(balances)
    }
}

/// Parse a token count as typed on the command line: `1500`, `500k`, `2M`,
/// `1.5m` (k = 1,000, m = 1,000,000).
pub fn parse_tokens(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let (num, mult) = match t.char_indices().last() {
        Some((i, 'k' | 'K')) => (&t[..i], 1_000.0),
        Some((i, 'm' | 'M')) => (&t[..i], 1_000_000.0),
        _ => (t, 1.0),
    };
    let n: f64 = num
        .parse()
        .map_err(|_| format!("invalid token count '{s}': use e.g. 1500, 500k or 2M"))?;
    let v = n * mult;
    if !(v.is_finite() && v >= 0.0 && v <= i64::MAX as f64) || v.fract() != 0.0 {
        return Err(format!("invalid token count '{s}'"));
    }
    Ok(v as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(alias: &str, delta: i64, reason: Reason, tokens: Option<u64>) -> Entry {
        Entry {
            ts: 1,
            alias: alias.into(),
            delta,
            reason,
            tokens,
        }
    }

    fn temp_ledger(name: &str) -> Ledger {
        let dir = std::env::temp_dir().join(format!("sodabox-quota-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Ledger::at(dir.join("quota.jsonl"))
    }

    #[test]
    fn missing_ledger_is_empty() {
        assert!(temp_ledger("missing").load().unwrap().is_empty());
    }

    #[test]
    fn balance_sums_grants_and_usage_and_may_go_negative() {
        let l = temp_ledger("sum");
        l.append(&entry("foo", 0, Reason::Initial, None)).unwrap();
        l.append(&entry("foo", 1000, Reason::Grant, None)).unwrap();
        l.append(&entry("foo", -1200, Reason::Usage, Some(1200)))
            .unwrap();
        let b = &l.load().unwrap()["foo"];
        assert_eq!(b.balance, -200);
        assert!(b.initialized);
        assert_eq!((b.granted, b.used), (1000, 1200));
    }

    #[test]
    fn unmetered_usage_leaves_the_balance_alone() {
        let l = temp_ledger("unmetered");
        l.append(&entry("foo", 500, Reason::Initial, None)).unwrap();
        l.append(&entry("foo", 0, Reason::Unmetered, Some(9000)))
            .unwrap();
        let b = &l.load().unwrap()["foo"];
        assert_eq!(b.balance, 500);
        assert_eq!(b.unmetered, 9000);
    }

    #[test]
    fn grants_before_first_use_do_not_initialize() {
        let l = temp_ledger("pregrant");
        l.append(&entry("foo", 100, Reason::Grant, None)).unwrap();
        let b = &l.load().unwrap()["foo"];
        assert_eq!(b.balance, 100);
        assert!(!b.initialized);
    }

    #[test]
    fn malformed_line_fails_closed() {
        let l = temp_ledger("bad");
        l.append(&entry("foo", 100, Reason::Grant, None)).unwrap();
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(l.path())
            .unwrap();
        f.write_all(b"{not json\n").unwrap();
        assert!(l.load().is_err());
    }

    #[test]
    fn token_counts() {
        assert_eq!(parse_tokens("1500"), Ok(1500));
        assert_eq!(parse_tokens("500k"), Ok(500_000));
        assert_eq!(parse_tokens("2M"), Ok(2_000_000));
        assert_eq!(parse_tokens("1.5m"), Ok(1_500_000));
        assert!(parse_tokens("").is_err());
        assert!(parse_tokens("-5").is_err());
        assert!(parse_tokens("1.5").is_err());
        assert!(parse_tokens("lots").is_err());
    }
}
