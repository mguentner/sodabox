//! `soda logs <vm>` — print a VM's persisted event log
//! (ADR-0009). The supervisor appends every stream event as newline-delimited
//! JSON to `events.log` in the persistent data dir (see
//! `sodabox_supervisor::eventlog`); this reads that log — including the rotated
//! `events.log.1` predecessor — and renders it for post-hoc audit, so it works
//! whether or not the VM is currently running.

use std::path::Path;

use sodabox_common::event::{DnsVerdict, Event, Verdict};
use sodabox_common::{paths, vm::VmMeta};

/// `soda logs <vm> [-n N] [--json]`. Prints oldest-first. `lines` limits to the
/// last N records (across both files); `json` prints the JSON lines (see
/// [`json_safe`]) instead of the human-readable rendering.
pub fn run(name: &str, lines: Option<usize>, json: bool) -> anyhow::Result<()> {
    if !VmMeta::path(name).is_file() {
        anyhow::bail!("no such VM '{name}' — run `soda create {name}` first");
    }

    // Oldest first: the rotated predecessor precedes the current log.
    let mut records: Vec<String> = Vec::new();
    read_into(&paths::event_log_prev_path(name), &mut records)?;
    read_into(&paths::event_log_path(name), &mut records)?;

    if records.is_empty() {
        println!("no events logged for '{name}' yet");
        return Ok(());
    }

    let start = lines.map(|n| records.len().saturating_sub(n)).unwrap_or(0);
    for raw in &records[start..] {
        if json {
            println!("{}", json_safe(raw));
        } else {
            println!("{}", render(raw));
        }
    }
    Ok(())
}

/// Append every non-empty line of `path` to `out`. A missing file is not an error
/// (the log may not exist yet, or never rotated), only a real read error is.
fn read_into(path: &Path, out: &mut Vec<String>) -> anyhow::Result<()> {
    match std::fs::read_to_string(path) {
        Ok(body) => {
            out.extend(body.lines().filter(|l| !l.is_empty()).map(str::to_string));
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::anyhow!("reading {}: {e}", path.display())),
    }
}

/// Render one stored JSON record as a human-readable audit line. A line that
/// doesn't parse (e.g. a torn final write from a live VM) is shown verbatim with
/// a `?` marker rather than dropped, so nothing is silently hidden. Records carry
/// guest-controlled text (a DNS name can hold any byte), so control characters
/// are shown escaped, for the same reason, and never reach the terminal.
fn render(raw: &str) -> String {
    let line = match serde_json::from_str::<Event>(raw) {
        Ok(ev) => render_event(&ev),
        Err(_) => format!("{:<20} ?        {raw}", "?"),
    };
    let mut out = String::with_capacity(line.len());
    for c in line.chars() {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// A stored JSON line, safe to print to a terminal and still the same JSON.
/// `serde_json` leaves C1 controls such as U+009B (a CSI on some terminals) raw,
/// so every control character becomes a `\uXXXX` escape. In a valid record they
/// can only occur inside strings, where that escape means the same character.
fn json_safe(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        if c.is_control() {
            out.push_str(&format!("\\u{:04x}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

/// The detail of an inference event, shared with the TUI:
/// `alias -> provider/model  200  in 1200 out 300  850ms`.
pub(crate) fn inference_detail(ev: &Event) -> Option<String> {
    let Event::Inference {
        alias,
        provider,
        model,
        status,
        tokens,
        complete,
        latency_ms,
        ..
    } = ev
    else {
        return None;
    };
    let mut d = alias.clone();
    if let (Some(p), Some(m)) = (provider, model) {
        d.push_str(&format!(" -> {p}/{m}"));
    }
    d.push_str(&format!(
        "  {status}  in {} out {}",
        tokens.input, tokens.output
    ));
    if tokens.cache_read > 0 {
        d.push_str(&format!(" (cached {})", tokens.cache_read));
    }
    d.push_str(&format!("  {latency_ms}ms"));
    if !complete {
        d.push_str("  (partial)");
    }
    if tokens.estimated {
        d.push_str("  (tokens estimated)");
    }
    Some(d)
}

/// `<ts>  <TAG>  <detail>` for one event, mirroring the TUI's tags in plain text.
fn render_event(ev: &Event) -> String {
    let (ts, tag, detail) = match ev {
        Event::Egress {
            ts,
            verdict,
            proto,
            daddr,
            dport,
            rule,
        } => {
            let tag = match verdict {
                Verdict::Allowed => "ALLOW",
                Verdict::Blocked => "BLOCK",
            };
            let mut d = format!("{proto} {daddr}:{dport}");
            if let Some(r) = rule {
                d.push_str(&format!(" ({r})"));
            }
            (*ts, tag, d)
        }
        Event::Dns {
            ts,
            verdict,
            qname,
            answers,
            ttl,
        } => {
            let tag = match verdict {
                DnsVerdict::Allowed => "DNS-OK",
                DnsVerdict::Refused => "DNS-REF",
            };
            let d = if answers.is_empty() {
                qname.clone()
            } else {
                format!("{qname} -> {} (ttl {ttl})", answers.join(","))
            };
            (*ts, tag, d)
        }
        Event::Inference { ts, verdict, .. } => {
            let tag = match verdict {
                Verdict::Allowed => "INFER",
                Verdict::Blocked => "INFER-NO",
            };
            (*ts, tag, inference_detail(ev).unwrap_or_default())
        }
        Event::QuotaExhausted { ts, alias } => {
            (*ts, "QUOTA", format!("{alias}: token quota used up"))
        }
        Event::Policy { ts, version } => (*ts, "POLICY", format!("v{version}")),
        Event::RequestPending {
            ts,
            proto,
            destination,
            port,
            via,
            expires_ts,
            ..
        } => {
            let where_to = match port {
                Some(p) => format!("{destination}:{p}"),
                None => destination.clone(),
            };
            let origin = sodabox_common::request::origin_label(*port, via.as_deref())
                .map(|o| format!(" {o}"))
                .unwrap_or_default();
            (
                *ts,
                "REQ",
                format!("hold {proto} {where_to}{origin} (expires {expires_ts})"),
            )
        }
        Event::RequestResolved { ts, id, verdict } => {
            (*ts, "REQ-DONE", format!("request #{id} {verdict}"))
        }
        Event::Lifecycle { ts, state } => (*ts, "LIFECYCLE", state.clone()),
        Event::Dropped { ts, count } => (*ts, "DROPPED", format!("{count} events")),
    };
    format!("{}  {tag:<9} {detail}", fmt_ts(ts))
}

/// A full `YYYY-MM-DDTHH:MM:SSZ` UTC timestamp from Unix seconds. Unlike the TUI
/// (time-of-day only), an audit log can span days, so it carries the date — done
/// by hand to avoid a chrono dependency for one formatter.
fn fmt_ts(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Civil (Gregorian) date from a count of days since the Unix epoch
/// (1970-01-01 = day 0). Howard Hinnant's `civil_from_days`, valid for the whole
/// range we'll ever stamp. Returns `(year, month [1..=12], day [1..=31])`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_ts_renders_a_known_epoch() {
        // 2026-09-09T00:00:00Z (matches the project "today"); a round day plus a
        // known time-of-day exercises both the civil-date and clock arithmetic.
        assert_eq!(fmt_ts(1_788_912_000), "2026-09-09T00:00:00Z");
        assert_eq!(fmt_ts(0), "1970-01-01T00:00:00Z");
        assert_eq!(fmt_ts(1_788_912_000 + 3661), "2026-09-09T01:01:01Z");
    }

    #[test]
    fn render_formats_each_variant_and_survives_garbage() {
        let block = serde_json::to_string(&Event::Egress {
            ts: 0,
            verdict: Verdict::Blocked,
            proto: "tcp".into(),
            daddr: "203.0.113.1".into(),
            dport: 443,
            rule: None,
        })
        .unwrap();
        let line = render(&block);
        assert!(line.contains("BLOCK"), "{line}");
        assert!(line.contains("tcp 203.0.113.1:443"), "{line}");

        let dns = serde_json::to_string(&Event::Dns {
            ts: 0,
            verdict: DnsVerdict::Allowed,
            qname: "example.com".into(),
            answers: vec!["93.184.216.34".into()],
            ttl: 300,
        })
        .unwrap();
        assert!(render(&dns).contains("example.com -> 93.184.216.34 (ttl 300)"));

        // A torn/garbage line is surfaced with a `?` marker, not dropped.
        assert!(render("{not json").contains('?'));
    }

    /// A query name a guest can really send: label bytes are kept as-is.
    const HOSTILE: &str = "x\u{7}\u{1b}]52;c;Zm9v\u{7}\u{9b}2J.evil.test";

    fn hostile_records() -> Vec<String> {
        [
            Event::Dns {
                ts: 0,
                verdict: DnsVerdict::Refused,
                qname: HOSTILE.into(),
                answers: Vec::new(),
                ttl: 0,
            },
            Event::RequestPending {
                ts: 0,
                id: 1,
                proto: "dns".into(),
                destination: HOSTILE.into(),
                port: None,
                via: None,
                expires_ts: 30,
            },
            Event::RequestPending {
                ts: 0,
                id: 2,
                proto: "tcp".into(),
                destination: "203.0.113.5".into(),
                port: Some(443),
                via: Some(HOSTILE.into()),
                expires_ts: 30,
            },
        ]
        .iter()
        .map(|e| serde_json::to_string(e).unwrap())
        .collect()
    }

    #[test]
    fn render_says_where_a_held_address_came_from() {
        let line = |via: Option<&str>| {
            render(
                &serde_json::to_string(&Event::RequestPending {
                    ts: 0,
                    id: 1,
                    proto: "tcp".into(),
                    destination: "203.0.113.5".into(),
                    port: Some(443),
                    via: via.map(str::to_string),
                    expires_ts: 30,
                })
                .unwrap(),
            )
        };
        assert!(
            line(Some("example.com")).contains("hold tcp 203.0.113.5:443 via example.com"),
            "{}",
            line(Some("example.com"))
        );
        assert!(
            line(None).contains("hold tcp 203.0.113.5:443 no recent lookup"),
            "{}",
            line(None)
        );
    }

    #[test]
    fn render_shows_control_characters_escaped() {
        for raw in hostile_records() {
            let line = render(&raw);
            assert!(!line.contains(char::is_control), "{line:?}");
            // Still visible for the audit, not silently dropped.
            assert!(line.contains(r"\u{1b}]52;c;Zm9v"), "{line}");
        }
        // The fallback for an unparsable line prints it too.
        let line = render("{torn \u{1b}]52;");
        assert!(!line.contains(char::is_control), "{line:?}");
    }

    #[test]
    fn json_output_has_no_control_characters_and_means_the_same() {
        for raw in hostile_records() {
            // The premise: serde_json alone leaves the C1 control in.
            assert!(raw.contains('\u{9b}'), "{raw:?}");
            let safe = json_safe(&raw);
            assert!(!safe.contains(char::is_control), "{safe:?}");
            let (a, b): (serde_json::Value, serde_json::Value) = (
                serde_json::from_str(&raw).unwrap(),
                serde_json::from_str(&safe).unwrap(),
            );
            assert_eq!(a, b);
        }
    }
}
