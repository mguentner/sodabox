//! The gateway's view of the quota ledger: balances in memory, every change
//! appended to the ledger first (ADR-0020).

use sodabox_common::event::now_ts;
use sodabox_common::quota::{Balances, Entry, Ledger, Reason};

pub struct QuotaBook {
    ledger: Ledger,
    balances: Balances,
}

impl QuotaBook {
    /// Load `ledger`. A ledger that can't be read is an error: the gateway
    /// must not start with guessed balances.
    pub fn open(ledger: Ledger) -> std::io::Result<QuotaBook> {
        let balances = ledger.load()?;
        Ok(QuotaBook { ledger, balances })
    }

    /// Re-read the ledger, e.g. after the CLI appended a grant.
    pub fn reload(&mut self) -> std::io::Result<()> {
        self.balances = self.ledger.load()?;
        Ok(())
    }

    pub fn balances(&self) -> &Balances {
        &self.balances
    }

    pub fn balance(&self, alias: &str) -> i64 {
        self.balances.get(alias).map_or(0, |b| b.balance)
    }

    /// Write the alias's `initial` entry on its first use.
    pub fn ensure_initialized(&mut self, alias: &str, initial: u64) -> std::io::Result<()> {
        if self.balances.get(alias).is_some_and(|b| b.initialized) {
            return Ok(());
        }
        self.record(Entry {
            ts: now_ts(),
            alias: alias.to_string(),
            delta: i64::try_from(initial).unwrap_or(i64::MAX),
            reason: Reason::Initial,
            tokens: None,
        })
    }

    /// Book `tokens` used by a request: subtracted if `metered`, otherwise
    /// recorded as unmetered. The in-memory balance changes even if the
    /// ledger write fails, so enforcement stays correct while the VM runs.
    pub fn book(&mut self, alias: &str, tokens: u64, metered: bool) -> std::io::Result<()> {
        let entry = if metered {
            Entry {
                ts: now_ts(),
                alias: alias.to_string(),
                delta: -i64::try_from(tokens).unwrap_or(i64::MAX),
                reason: Reason::Usage,
                tokens: Some(tokens),
            }
        } else {
            Entry {
                ts: now_ts(),
                alias: alias.to_string(),
                delta: 0,
                reason: Reason::Unmetered,
                tokens: Some(tokens),
            }
        };
        let written = self.ledger.append(&entry);
        self.balances
            .entry(alias.to_string())
            .or_default()
            .apply(&entry);
        written
    }

    fn record(&mut self, entry: Entry) -> std::io::Result<()> {
        self.ledger.append(&entry)?;
        self.balances
            .entry(entry.alias.clone())
            .or_default()
            .apply(&entry);
        Ok(())
    }
}
