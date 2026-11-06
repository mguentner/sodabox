//! `soda tui <vm>` — live terminal monitor (ADR-0009).
//!
//! Built on a control-socket `subscribe`, a ratatui render loop and bounded
//! buffers for backpressure, it shows two tabs (`1`/`2`, `←`/`→`):
//!
//! - **Network**
//!   - **Egress Requests** (ADR-0021) — destinations no rule matched, held
//!     up to 30 s for interactive approval: `a`/Enter approves (which adds the
//!     persistent rule), `d` denies; the countdown fades white → yellow →
//!     orange → red → dark red → purple. A new request raises an OSC 9
//!     notification and/or the terminal bell, cycled with `n`
//!     (`off|notification|bell|all`, persisted in `tui.toml`).
//!   - **Egress** — flow verdicts (proto, dst:port, matched rule).
//!   - **DNS** — query verdicts (name, resolved IPs, TTL).
//!   - **Policy** — the live policy version, its allowlist and its blocklist.
//!   - **Status** — the sodabox logo beside VM state, configured CPU/RAM, and
//!     uptime. The logo is the PNG itself, placed over the panel's cells via
//!     the kitty graphics protocol (kitty, Ghostty, WezTerm, Konsole, foot, …)
//!     and scaled to the panel's lines; terminals that don't answer the
//!     protocol probe get the fields alone.
//! - **Inference** (ADR-0020)
//!   - **Inference** — gateway requests (alias → upstream, status, tokens) and
//!     used-up quotas.
//!   - **Gateway** — whether the gateway is on and reachable, and each alias
//!     with its balance (`∞` while unlimited). `g` grants tokens to the
//!     highlighted alias (a prompt in the footer), `m` switches it between
//!     limited and unlimited.
//!   - **Status**, as on the other tab.
//!
//! Quick-actions: the focused flow panel has a selectable cursor
//! (`Tab` switches panels, `↑`/`↓` move it), and `a`/`Enter` allows the
//! highlighted **blocked** destination — an egress `BLOCK` becomes an `ip` allow
//! of its proto and dst:port on the spot, a DNS `REFUSED` opens a popup asking
//! what its name should grant (ADR-0021). Like `soda allow`, that edits `policy.toml` and pushes
//! the whole new policy via `PolicySet` (the supervisor rejects raw single-rule edits so the
//! CLI stays the sole writer of `policy.toml`); the result shows in the footer.
//! While a row is held the panel is frozen on it: new events land below the
//! window instead of sliding the content under the cursor.
//!
//! `u` toggles the **unique** view on both flow panels: one row per destination
//! (egress `proto daddr:dport`, DNS query name) with its latest verdict and a hit
//! count, in first-seen order — a deduplicated list to build a profile from.
//!
//! Egress and DNS get their own bounded buffers so a flood of one can't starve
//! the other's panel. Policy rules aren't on the event feed (events only carry
//! the version bump), so they're fetched with a `policy.get` request and
//! re-fetched whenever a `Policy` event reports a new version. Uptime is derived
//! from the control socket's mtime (created when the supervisor bound it at boot).
//!
//! Backpressure is handled at two stages — the supervisor's broadcast ring drops
//! the oldest events under load and reports the count via [`Event::Dropped`], and
//! on top of that each panel's buffer caps what the TUI retains. Both losses sum
//! into one visible "dropped" tally so a gap is never silent.

use std::collections::{HashMap, VecDeque};
use std::io::Write as IoWrite;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use ratatui::crossterm::event::{self, Event as TermEvent, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};
use ratatui::Frame;
use tokio::sync::mpsc;

use sodabox_common::allowlist::{is_public_ip, PortSpec};
use sodabox_common::blocklist::overridden_by;
use sodabox_common::event::{DnsVerdict, Event, RefusalReason, Verdict};
use sodabox_common::paths;
use sodabox_common::policy::{
    BlocklistEntry, DomainScope, GatewayConfig, ModelAlias, PolicyFile, QuotaMode, Rule, VmPolicy,
};
use sodabox_common::protocol::{Request, Response};
use sodabox_common::quota::{self, Balances, Entry, Ledger, Reason};
use sodabox_common::request::{origin_label, PendingRequest};
use sodabox_common::vm::VmMeta;
use sodabox_supervisor::control::{ControlClient, EventStream};

/// Per-panel retention. A tail only shows a screenful; this bounds memory well
/// above any visible window while staying tiny.
const PANEL_CAPACITY: usize = 2048;
/// The longest name a request row shows (see [`name_tail`]).
const MAX_VIA_CHARS: usize = 32;
/// The allow popup's widest: the choices then fit on one line, with room for
/// some ports.
const POPUP_WIDTH: u16 = 88;
/// The longest port list the allow popup takes.
const MAX_PORT_FIELD: usize = 64;

/// The sodabox logo (`assets/logo_120x256.png`), embedded for the Status
/// panel: transmitted once over the kitty graphics protocol and placed over
/// the panel's cells every frame (see [`detect_graphics`]).
const LOGO_PNG: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../assets/logo_120x256.png"
));
/// Graphics-protocol id under which the logo is transmitted and placed.
const LOGO_ID: u32 = 1;
/// The logo PNG's pixel size — the aspect reference for cell sizing.
const LOGO_W: u32 = 120;
const LOGO_H: u32 = 256;

/// How long the graphics-protocol probe waits for the terminal's reply. Generous
/// for slow links: a terminal that answers ends the wait at once, and a reply
/// missing this deadline would decode as keystrokes in the event loop.
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);

/// Width the status lines need beside the logo — the longest field,
/// `uptime  365d 23:59:59`, plus a little slack.
const STATUS_TEXT_WIDTH: u16 = 22;

/// Cell columns the logo spans at `rows` cell rows, keeping its aspect:
/// terminal cells are about twice as tall as wide, so the 120×256 image
/// needs `rows × 2 × 120 / 256` columns.
fn logo_cols(rows: u16) -> u16 {
    ((u32::from(rows) * 2 * LOGO_W + LOGO_H / 2) / LOGO_H) as u16
}

/// Redraw cadence. Events are coalesced between frames (ingested as they arrive,
/// painted on this tick), so a burst of thousands/sec costs one redraw per
/// interval rather than one per event.
const REDRAW_INTERVAL: Duration = Duration::from_millis(100);

/// A bounded FIFO of the most recent `T`. [`push`](Bounded::push) returns `true`
/// when it had to evict the oldest element to stay within capacity, so the caller
/// can account for the drop.
pub struct Bounded<T> {
    buf: VecDeque<T>,
    cap: usize,
}

impl<T> Bounded<T> {
    fn new(cap: usize) -> Self {
        Self {
            buf: VecDeque::new(),
            cap: cap.max(1),
        }
    }

    /// Append `v`, evicting the oldest element at capacity. Returns whether an
    /// eviction happened.
    fn push(&mut self, v: T) -> bool {
        let evicted = self.buf.len() >= self.cap;
        if evicted {
            self.buf.pop_front();
        }
        self.buf.push_back(v);
        evicted
    }

    fn iter(&self) -> impl DoubleEndedIterator<Item = &T> {
        self.buf.iter()
    }

    fn len(&self) -> usize {
        self.buf.len()
    }
}

/// The distinct destinations a flow panel has seen, in first-seen order, each
/// with its most recent event and a hit count — the unique view. Kept apart from
/// the tail buffer so a chatty destination can't evict a rare one from it; at
/// capacity the oldest-seen destination is forgotten.
pub struct Distinct {
    rows: VecDeque<DistinctRow>,
    /// Destination key → sequence number of its row (position = seq − `base`).
    index: HashMap<String, u64>,
    /// Sequence number of `rows[0]`.
    base: u64,
    cap: usize,
}

struct DistinctRow {
    key: String,
    latest: Event,
    hits: u64,
}

impl Distinct {
    fn new(cap: usize) -> Self {
        Self {
            rows: VecDeque::new(),
            index: HashMap::new(),
            base: 0,
            cap: cap.max(1),
        }
    }

    /// Count `ev` against its destination. Returns whether it opened a new row
    /// (a repeat only refreshes the existing row in place).
    fn record(&mut self, ev: &Event) -> bool {
        let Some(key) = distinct_key(ev) else {
            return false;
        };
        if let Some(&seq) = self.index.get(&key) {
            let row = &mut self.rows[(seq - self.base) as usize];
            row.latest = ev.clone();
            row.hits += 1;
            return false;
        }
        if self.rows.len() >= self.cap {
            if let Some(old) = self.rows.pop_front() {
                self.index.remove(&old.key);
                self.base += 1;
            }
        }
        self.index
            .insert(key.clone(), self.base + self.rows.len() as u64);
        self.rows.push_back(DistinctRow {
            key,
            latest: ev.clone(),
            hits: 1,
        });
        true
    }

    fn len(&self) -> usize {
        self.rows.len()
    }
}

/// What makes two flow events "the same destination" in the unique view: the
/// egress `proto daddr:dport`, or the DNS query name (case- and trailing-dot-
/// insensitive). `None` for events that aren't flows.
fn distinct_key(ev: &Event) -> Option<String> {
    match ev {
        Event::Egress {
            proto,
            daddr,
            dport,
            ..
        } => Some(format!("{proto} {daddr}:{dport}")),
        Event::Dns { qname, .. } => Some(strip_trailing_dot(qname).to_ascii_lowercase()),
        Event::Inference { alias, .. } | Event::QuotaExhausted { alias, .. } => {
            Some(format!("inference {alias}"))
        }
        _ => None,
    }
}

/// One flow panel (Egress or DNS): its event tail, the distinct-destination
/// table behind the unique view, and the cursor + window into whichever view is
/// shown. `sel` and `scroll` are offsets from the newest (bottom) row; `scroll`
/// is the bottom visible row, so 0 is following the tail.
pub struct FlowPanel {
    tail: Bounded<Event>,
    distinct: Distinct,
    /// Cursor (`None` follows the tail, no selection).
    sel: Option<usize>,
    scroll: usize,
}

impl FlowPanel {
    fn new(cap: usize) -> Self {
        Self {
            tail: Bounded::new(cap),
            distinct: Distinct::new(cap),
            sel: None,
            scroll: 0,
        }
    }

    /// Append an event to both views. Returns whether the tail had to evict.
    /// While the cursor is held, a row landing at the bottom of the shown view
    /// pushes the cursor and window up by one so both stay on the same content.
    fn push(&mut self, ev: Event, unique: bool) -> bool {
        let new_row = self.distinct.record(&ev);
        let evicted = self.tail.push(ev);
        if let Some(s) = self.sel {
            if new_row || !unique {
                self.sel = Some((s + 1).min(self.len(unique) - 1));
                self.scroll += 1;
            }
        }
        evicted
    }

    /// Rows in the shown view.
    fn len(&self, unique: bool) -> usize {
        if unique {
            self.distinct.len()
        } else {
            self.tail.len()
        }
    }

    /// The shown view's rows newest-first: each event, plus its hit count in the
    /// unique view.
    fn rows(&self, unique: bool) -> Box<dyn Iterator<Item = (&Event, Option<u64>)> + '_> {
        if unique {
            Box::new(
                self.distinct
                    .rows
                    .iter()
                    .rev()
                    .map(|r| (&r.latest, Some(r.hits))),
            )
        } else {
            Box::new(self.tail.iter().rev().map(|e| (e, None)))
        }
    }

    /// Drop the cursor and return to following the tail.
    fn release(&mut self) {
        self.sel = None;
        self.scroll = 0;
    }
}

/// Where a flow panel's window sits (offset of its bottom row from the newest)
/// after keeping cursor `sel` in view: it only scrolls once the cursor would
/// leave the window, never shows blank space above the oldest row, and snaps
/// back to the tail when nothing is selected.
fn scroll_window(scroll: usize, sel: Option<usize>, height: usize, len: usize) -> usize {
    let Some(sel) = sel else {
        return 0;
    };
    let height = height.max(1);
    let scroll = if sel < scroll {
        sel
    } else if sel >= scroll + height {
        sel + 1 - height
    } else {
        scroll
    };
    scroll.min(len.saturating_sub(height))
}

/// The live policy as the TUI knows it: the version (kept current from the event
/// feed), and the rules, model aliases and gateway settings (fetched separately
/// via `policy.get`).
#[derive(Default)]
struct PolicyView {
    version: u32,
    rules: Vec<Rule>,
    blocklist: Vec<BlocklistEntry>,
    models: Vec<ModelAlias>,
    gateway: Option<GatewayConfig>,
}

impl From<VmPolicy> for PolicyView {
    fn from(p: VmPolicy) -> Self {
        Self {
            version: p.version,
            rules: p.rules,
            blocklist: p.blocklist,
            models: p.models,
            gateway: p.gateway,
        }
    }
}

impl PolicyView {
    /// How many rows the Policy panel's cursor moves over.
    fn rows(&self) -> usize {
        self.rules.len() + self.blocklist.len()
    }

    /// The row at a Policy panel cursor position.
    fn row(&self, at: usize) -> Option<PolicyRow<'_>> {
        match self.rules.get(at) {
            Some(rule) => Some(PolicyRow::Rule(rule)),
            None => self
                .blocklist
                .get(at - self.rules.len())
                .map(PolicyRow::Blocked),
        }
    }

    /// Whether this VM uses the inference gateway, so its panels are shown.
    fn gateway_used(&self) -> bool {
        self.gateway.as_ref().is_some_and(|g| g.enabled) || !self.models.is_empty()
    }

    /// Whether `alias` is metered (see [`VmPolicy::is_metered`]).
    fn is_metered(&self, alias: &str) -> bool {
        let vm = self.gateway.as_ref().map(|g| g.quota).unwrap_or_default();
        let own = self
            .models
            .iter()
            .find(|m| m.alias == alias)
            .and_then(|m| m.quota)
            .unwrap_or_default();
        vm.is_limited() && own.is_limited()
    }
}

/// Which panel the selection cursor is on. Egress/DNS are the flow panels (allow
/// a just-blocked destination); Policy is the rule list and blocklist (revoke a
/// selected rule, unblock a selected entry). Inference (gateway requests) and Gateway (the alias table: grant
/// tokens, switch metering) are on the Inference tab.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Focus {
    Requests,
    Egress,
    Dns,
    Inference,
    Policy,
    Gateway,
}

/// The two tabs: the network (egress, DNS, policy) and the inference gateway
/// (its requests and the alias table), switched with `1`/`2` or `←`/`→`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tab {
    Network,
    Inference,
}

/// The footer's input line for granting tokens to an alias (`g`).
struct GrantPrompt {
    alias: String,
    input: String,
}

/// A destination the user chose to allow from a highlighted blocked row.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AllowTarget {
    /// DNS `REFUSED` or a held dns request → let the name resolve (subdomains
    /// scope), no egress.
    Resolve(String),
    /// Egress `BLOCK` or a held tcp/udp request → allow exactly what its row
    /// shows.
    Flow {
        ip: String,
        port: u16,
        proto: String,
    },
    /// The name and what it resolves to (subdomains scope), on these ports: one
    /// `domain` rule per grant.
    Domain { name: String, grants: Vec<Grant> },
}

/// The ports and protocol of one `domain` rule; `None` means any.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Grant {
    ports: Option<String>,
    proto: Option<String>,
}

impl Grant {
    fn new(ports: Option<&str>, proto: Option<&str>) -> Grant {
        Grant {
            ports: ports.map(str::to_string),
            proto: proto.map(str::to_string),
        }
    }
}

/// The choices of the allow popup, in display order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AllowChoice {
    /// What the row grants with no name involved: see [`AllowPopup::narrow`].
    Narrow,
    Https,
    HttpHttps,
    AllPorts,
    Tcp,
    Udp,
}

const ALLOW_CHOICES: [AllowChoice; 6] = [
    AllowChoice::Narrow,
    AllowChoice::Https,
    AllowChoice::HttpHttps,
    AllowChoice::AllPorts,
    AllowChoice::Tcp,
    AllowChoice::Udp,
];

/// The popup asking what allowing a name should grant (ADR-0021), open over the
/// panels until confirmed or cancelled.
struct AllowPopup {
    /// The held request being decided; `None` for a refused row on the DNS panel,
    /// which has nothing to release.
    request: Option<PendingRequest>,
    /// The name a `domain` rule would be for.
    name: String,
    /// The narrowest grant: resolving the name, or the row's own IP and port.
    narrow: AllowTarget,
    choice: AllowChoice,
    tcp_ports: String,
    udp_ports: String,
    /// Why the last confirm was turned down.
    error: Option<String>,
}

impl AllowPopup {
    /// A popup for `name`, with the choice that grants the row what it asks for
    /// preselected: HTTPS for a dns row, else the row's own port.
    fn new(request: Option<PendingRequest>, name: String, narrow: AllowTarget) -> AllowPopup {
        let mut popup = AllowPopup {
            request,
            name,
            narrow,
            choice: AllowChoice::Https,
            tcp_ports: String::new(),
            udp_ports: String::new(),
            error: None,
        };
        if let AllowTarget::Flow { port, proto, .. } = &popup.narrow {
            let (port, proto) = (*port, proto.clone());
            let tcp = proto == "tcp";
            popup.choice = match port {
                443 => AllowChoice::Https,
                80 if tcp => AllowChoice::HttpHttps,
                _ if tcp => AllowChoice::Tcp,
                _ => AllowChoice::Udp,
            };
            if tcp {
                popup.tcp_ports = port.to_string();
            } else {
                popup.udp_ports = port.to_string();
            }
        }
        popup
    }

    /// The port field under the cursor, if the choice has one.
    fn field(&mut self) -> Option<&mut String> {
        match self.choice {
            AllowChoice::Tcp => Some(&mut self.tcp_ports),
            AllowChoice::Udp => Some(&mut self.udp_ports),
            _ => None,
        }
    }

    /// Move the cursor along the choices, wrapping around.
    fn step(&mut self, forward: bool) {
        let n = ALLOW_CHOICES.len();
        let at = ALLOW_CHOICES
            .iter()
            .position(|c| *c == self.choice)
            .unwrap_or(0);
        self.choice = ALLOW_CHOICES[(at + if forward { 1 } else { n - 1 }) % n];
        self.error = None;
    }

    /// What the current choice would add. An empty port field is refused here:
    /// the policy reads no ports as *any* port, which is its own choice.
    fn target(&self) -> Result<AllowTarget, String> {
        let domain = |grants| AllowTarget::Domain {
            name: self.name.clone(),
            grants,
        };
        let listed = |ports: &str, proto| {
            let ports = ports.trim();
            if ports.is_empty() {
                return Err("enter ports, e.g. 443,8000-8100".to_string());
            }
            PortSpec::parse(Some(ports))?;
            Ok(domain(vec![Grant::new(Some(ports), Some(proto))]))
        };
        match self.choice {
            AllowChoice::Narrow => Ok(self.narrow.clone()),
            // No proto on 443: HTTP/3 is HTTPS too, and runs over UDP.
            AllowChoice::Https => Ok(domain(vec![Grant::new(Some("443"), None)])),
            AllowChoice::HttpHttps => Ok(domain(vec![
                Grant::new(Some("80"), Some("tcp")),
                Grant::new(Some("443"), None),
            ])),
            AllowChoice::AllPorts => Ok(domain(vec![Grant::new(None, None)])),
            AllowChoice::Tcp => listed(&self.tcp_ports, "tcp"),
            AllowChoice::Udp => listed(&self.udp_ports, "udp"),
        }
    }
}

/// The name a popup for `req` would offer a `domain` rule on, if any: a dns row's
/// own name, or the name an address came from. An address with no recent lookup
/// has no name to offer, and a non-public one can't be opened through a name, so
/// those rows approve directly.
fn request_allow_name(req: &PendingRequest) -> Option<String> {
    match req.port {
        None => Some(strip_trailing_dot(&req.destination)),
        Some(_) => req
            .via
            .clone()
            .filter(|_| req.destination.parse().is_ok_and(is_public_ip)),
    }
}

/// The rule approving `req` adds (ADR-0021): resolving the name for a dns
/// request (the only kind without a port), else the row's proto and ip:port.
fn request_allow_target(req: &PendingRequest) -> AllowTarget {
    match req.port {
        Some(port) => AllowTarget::Flow {
            ip: req.destination.clone(),
            port,
            proto: req.proto.clone(),
        },
        None => AllowTarget::Resolve(req.destination.clone()),
    }
}

/// The choices of the block popup, in display order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockChoice {
    /// The row's own IP, protocol and port.
    Address,
    /// The name its address came from, on the row's protocol and port.
    NamePort,
    /// All of that name, lookups included.
    Name,
}

const BLOCK_CHOICES: [BlockChoice; 3] = [
    BlockChoice::Address,
    BlockChoice::NamePort,
    BlockChoice::Name,
];

/// The popup asking what denying an address with a name should record (ADR-0021).
/// A name returns several addresses, so the name on the row's port is preselected:
/// recording the address alone would leave its siblings asking.
struct BlockPopup {
    request: PendingRequest,
    name: String,
    choice: BlockChoice,
}

impl BlockPopup {
    fn step(&mut self, forward: bool) {
        let n = BLOCK_CHOICES.len();
        let at = BLOCK_CHOICES
            .iter()
            .position(|c| *c == self.choice)
            .unwrap_or(0);
        self.choice = BLOCK_CHOICES[(at + if forward { 1 } else { n - 1 }) % n];
    }

    fn entry(&self) -> BlocklistEntry {
        let name = |ports: Option<String>, proto: Option<String>| BlocklistEntry::Domain {
            name: self.name.clone(),
            scope: DomainScope::Exact,
            ports,
            proto,
        };
        let port = self.request.port.map(|p| p.to_string());
        let proto = Some(self.request.proto.clone());
        match self.choice {
            BlockChoice::Address => BlocklistEntry::Ip {
                cidr: self.request.destination.clone(),
                ports: port,
                proto,
            },
            BlockChoice::NamePort => name(port, proto),
            BlockChoice::Name => name(None, None),
        }
    }
}

/// What denying `req` records when there is nothing to ask: the exact name of a
/// dns row, or the protocol, address and port of an address row.
fn request_block_entry(req: &PendingRequest) -> BlocklistEntry {
    match req.port {
        Some(port) => BlocklistEntry::Ip {
            cidr: req.destination.clone(),
            ports: Some(port.to_string()),
            proto: Some(req.proto.clone()),
        },
        None => BlocklistEntry::Domain {
            name: strip_trailing_dot(&req.destination),
            scope: DomainScope::Exact,
            ports: None,
            proto: None,
        },
    }
}

/// The rules `target` adds, to find what they override on the blocklist.
fn allow_target_rules(target: &AllowTarget) -> Vec<Rule> {
    match target {
        AllowTarget::Resolve(name) => vec![Rule::Resolve {
            name: name.clone(),
            scope: DomainScope::Subdomains,
        }],
        AllowTarget::Flow { ip, port, proto } => vec![Rule::Ip {
            cidr: ip.clone(),
            ports: Some(port.to_string()),
            proto: Some(proto.clone()),
        }],
        AllowTarget::Domain { name, grants } => grants
            .iter()
            .map(|g| Rule::Domain {
                name: name.clone(),
                scope: DomainScope::Subdomains,
                ports: g.ports.clone(),
                proto: g.proto.clone(),
            })
            .collect(),
    }
}

/// A row of the Policy panel: the two lists share one cursor, allowlist first.
#[derive(Debug, PartialEq, Eq)]
enum PolicyRow<'a> {
    Rule(&'a Rule),
    Blocked(&'a BlocklistEntry),
}

/// A line of the Policy panel below its version header.
enum PolicyLine {
    /// A section title.
    Header(&'static str),
    /// A placeholder for an empty section.
    Note(&'static str),
    /// An entry, by its cursor position.
    Row(usize),
}

/// The Policy panel's lines, both sections in full.
fn policy_lines(rules: usize, blocked: usize) -> Vec<PolicyLine> {
    let mut lines = vec![PolicyLine::Header("Allowlist")];
    if rules == 0 {
        lines.push(PolicyLine::Note("(deny-all)"));
    }
    lines.extend((0..rules).map(PolicyLine::Row));
    lines.push(PolicyLine::Header("Blocklist"));
    if blocked == 0 {
        lines.push(PolicyLine::Note("(empty)"));
    }
    lines.extend((rules..rules + blocked).map(PolicyLine::Row));
    lines
}

/// Which of `lines` fit in `room` rows, keeping the selected one in view. Past the
/// top of a section its title is repeated first, so a row can always be told apart
/// from the other list's. `room` must leave one row for the "…" indicator if this
/// returns fewer lines than there are.
fn policy_window(lines: &[PolicyLine], room: usize, sel: Option<usize>) -> Vec<usize> {
    if lines.len() <= room {
        return (0..lines.len()).collect();
    }
    let cap = room.saturating_sub(1).max(1);
    let sel_at = sel
        .and_then(|s| {
            lines
                .iter()
                .position(|l| matches!(l, PolicyLine::Row(r) if *r == s))
        })
        .unwrap_or(0);
    let section_of = |at: usize| {
        lines[..=at]
            .iter()
            .rposition(|l| matches!(l, PolicyLine::Header(_)))
            .unwrap_or(0)
    };
    // Too short to spare a row for a repeated title.
    if cap < 2 {
        return vec![sel_at];
    }
    // The selected line last, with its title or whatever fits above it.
    let body = cap - 1;
    let start = (sel_at + 1)
        .saturating_sub(body)
        .min(lines.len().saturating_sub(body));
    let section = section_of(start);
    if section == start {
        return (start..(start + cap).min(lines.len())).collect();
    }
    let mut window = vec![section];
    window.extend(start..(start + body).min(lines.len()));
    window
}

/// A blocklist entry as a concise one-liner for the panel, like [`fmt_rule`].
fn fmt_block(entry: &BlocklistEntry) -> String {
    match entry {
        BlocklistEntry::Ip { cidr, ports, proto } => {
            let mut s = format!("ip {cidr}");
            if let Some(p) = ports {
                s.push_str(&format!(":{p}"));
            }
            if let Some(pr) = proto {
                s.push_str(&format!("/{pr}"));
            }
            s
        }
        BlocklistEntry::Domain {
            name,
            scope,
            ports,
            proto,
        } => {
            let mut s = format!("domain {name} ({})", scope_str(*scope));
            if let Some(p) = ports {
                s.push_str(&format!(" :{p}"));
            }
            if let Some(pr) = proto {
                s.push_str(&format!("/{pr}"));
            }
            s
        }
    }
}

/// A transient footer message (the outcome of the last quick-action).
struct Notice {
    text: String,
    error: bool,
}

/// What the TUI emits on a new [`Event::RequestPending`] (ADR-0021): the OSC 9
/// "growl" notification, the terminal bell, both, or neither. Cycled with
/// `n`, persisted in `tui.toml` so it survives restarts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum NotifyMode {
    Off,
    Notification,
    Bell,
    All,
}

impl NotifyMode {
    fn as_str(self) -> &'static str {
        match self {
            NotifyMode::Off => "off",
            NotifyMode::Notification => "notification",
            NotifyMode::Bell => "bell",
            NotifyMode::All => "all",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "off" => Some(NotifyMode::Off),
            "notification" => Some(NotifyMode::Notification),
            "bell" => Some(NotifyMode::Bell),
            "all" => Some(NotifyMode::All),
            _ => None,
        }
    }

    fn next(self) -> Self {
        match self {
            NotifyMode::Off => NotifyMode::Notification,
            NotifyMode::Notification => NotifyMode::Bell,
            NotifyMode::Bell => NotifyMode::All,
            NotifyMode::All => NotifyMode::Off,
        }
    }

    fn notification(self) -> bool {
        matches!(self, NotifyMode::Notification | NotifyMode::All)
    }

    fn bell(self) -> bool {
        matches!(self, NotifyMode::Bell | NotifyMode::All)
    }
}

/// Where the notify mode persists: `$XDG_CONFIG_HOME/sodabox/tui.toml`.
fn notify_path() -> PathBuf {
    paths::config_dir().join("tui.toml")
}

fn load_notify_from(path: &std::path::Path) -> NotifyMode {
    let Ok(text) = std::fs::read_to_string(path) else {
        return NotifyMode::All;
    };
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("notify") {
            let rest = rest.trim().trim_start_matches('=').trim().trim_matches('"');
            if let Some(mode) = NotifyMode::parse(rest) {
                return mode;
            }
        }
    }
    NotifyMode::All
}

/// Best-effort: an unwritable config dir just means the mode resets next run.
fn save_notify_to(path: &std::path::Path, mode: NotifyMode) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(path, format!("notify = \"{}\"\n", mode.as_str()));
}

/// Raise the user's attention for a new pending request (ADR-0021): the
/// OSC 9 "growl" notification and/or the terminal bell, per `mode`. Written
/// straight to stdout between frames — the TUI owns the terminal.
fn notify_terminal(mode: NotifyMode, msg: &str) {
    let mut out = std::io::stdout();
    if mode.notification() {
        // OSC 9: ESC ] 9 ; <message> BEL
        let _ = write!(out, "\x1b]9;{msg}\x07");
    }
    if mode.bell() {
        let _ = write!(out, "\x07");
    }
    let _ = out.flush();
}

/// Probe for the kitty graphics protocol (kitty, Ghostty, WezTerm, Konsole,
/// foot, …): ask the terminal to load a dummy 1×1 image and race its reply
/// against the primary device attributes — a graphics reply first means the
/// protocol is supported, the spec's own detection recipe. Runs in the raw
/// mode `ratatui::init` already set, before the event loop owns stdin.
fn detect_graphics() -> bool {
    use std::io::{IsTerminal, Write};
    use std::os::fd::AsFd;

    if !std::io::stdin().is_terminal() {
        return false;
    }
    let mut out = std::io::stdout();
    // GI query (dummy RGBA pixel) + primary DA: graphics-capable terminals
    // answer the query immediately, before the DA reply.
    if out
        .write_all(b"\x1b_Gi=31,s=1,v=1,a=q,t=d,f=24;AAAA\x1b\\\x1b[c")
        .is_err()
    {
        return false;
    }
    let _ = out.flush();

    // A duplicate of the descriptor as a `File`: `Stdin` buffers, and could
    // keep bytes past the reply where crossterm's reader never sees them.
    let Ok(stdin) = std::io::stdin().as_fd().try_clone_to_owned() else {
        return false;
    };
    read_probe_reply(std::fs::File::from(stdin), PROBE_TIMEOUT)
}

/// Read the probe's reply from `input`, on the calling thread so that no reader
/// is left competing with the event loop for keys, and until the DA reply that
/// always comes last: anything left unread would reach the key handler, where
/// the reply's bytes decode as keystrokes. Keys typed during the probe go with
/// it — they were pressed before the panels they would act on were drawn.
/// A reply later than `timeout` still lands in the event loop.
fn read_probe_reply(mut input: impl std::io::Read + std::os::fd::AsFd, timeout: Duration) -> bool {
    use nix::errno::Errno;
    use nix::poll::{poll, PollFd, PollFlags};

    let deadline = Instant::now() + timeout;
    let mut seen = Vec::new();
    let mut buf = [0u8; 64];
    while !has_da_reply(&seen) {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        // Rounded up, so the last fraction of a millisecond doesn't spin.
        let millis = u16::try_from(left.as_millis() + 1).unwrap_or(u16::MAX);
        let mut fds = [PollFd::new(input.as_fd(), PollFlags::POLLIN)];
        match poll(&mut fds, millis) {
            Ok(0) => break,
            Ok(_) | Err(Errno::EINTR) => {}
            Err(_) => break,
        }
        if !fds[0].revents().is_some_and(|r| !r.is_empty()) {
            continue;
        }
        match input.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => seen.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    has_graphics_reply(&seen)
}

/// Does the probe's accumulated reply contain a graphics answer (ESC _ G …)?
/// Any answer — even an error — means the terminal speaks the protocol.
fn has_graphics_reply(seen: &[u8]) -> bool {
    find(seen, b"\x1b_G").is_some()
}

/// Does it contain a primary-device-attributes answer (ESC [ ? … c) — what a
/// terminal without the graphics protocol replies with?
fn has_da_reply(seen: &[u8]) -> bool {
    find(seen, b"\x1b[?").is_some_and(|p| seen[p + 3..].contains(&b'c'))
}

/// First index of `needle` in `hay`.
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Transmit the logo PNG once, base64-chunked over the graphics protocol
/// (`a=t` with an id, no placement yet — frames place it). `q=2` silences the
/// acks; chunks stay well under any terminal's escape-length limit.
fn transmit_logo() {
    let b64 = base64(LOGO_PNG);
    let bytes = b64.as_bytes();
    let mut out = std::io::stdout();
    let mut pos = 0;
    let mut first = true;
    while pos < bytes.len() {
        let end = (pos + 4096).min(bytes.len());
        let last = end == bytes.len();
        let m = if last { 0 } else { 1 };
        if first {
            let _ = write!(
                out,
                "\x1b_Ga=t,i={LOGO_ID},f=100,q=2,m={m};{}\x1b\\",
                String::from_utf8_lossy(&bytes[pos..end])
            );
        } else {
            let _ = write!(
                out,
                "\x1b_Gm={m};{}\x1b\\",
                String::from_utf8_lossy(&bytes[pos..end])
            );
        }
        pos = end;
        first = false;
    }
    let _ = out.flush();
}

/// Place the transmitted logo (see [`transmit_logo`]) at the rect the last
/// frame recorded, in cells: cursor to the top-left cell, then the placement
/// command with the cell rectangle — the terminal letterboxes the PNG into
/// it, so the aspect ratio survives. `q=2` keeps the terminal from acking on
/// stdin; the cursor is hidden, so the placement's cursor move is invisible
/// and the next frame repositions it anyway. A frame with no room for the logo
/// takes the placement down — the terminal would keep showing it otherwise —
/// but keeps the image data (lowercase `d=i`) for when it fits again.
fn place_logo(out: &mut impl IoWrite, app: &mut App) {
    match app.logo_place {
        Some(rect) => {
            let _ = write!(
                out,
                "\x1b[{};{}H\x1b_Ga=p,i={LOGO_ID},p=1,q=2,c={},r={}\x1b\\",
                rect.y + 1,
                rect.x + 1,
                rect.width,
                rect.height
            );
            app.logo_placed = true;
        }
        None if app.logo_placed => {
            let _ = write!(out, "\x1b_Ga=d,d=i,i={LOGO_ID},p=1,q=2\x1b\\");
            app.logo_placed = false;
        }
        None => return,
    }
    let _ = out.flush();
}

/// Free the transmitted logo on the way out — the uppercase `d=I` drops the
/// image data too. Runs while the alternate screen is still up, since images
/// are per screen and the main one may hold another program's image under this
/// id. `q=2` keeps any reply from landing on the shell's prompt after exit.
fn delete_logo() {
    let mut out = std::io::stdout();
    let _ = write!(out, "\x1b_Ga=d,d=I,i={LOGO_ID},q=2\x1b\\");
    let _ = out.flush();
}

/// Standard base64 (RFC 4648) — the graphics protocol's payload encoding.
/// Hand-rolled: it is all the protocol needs beyond the escapes themselves.
fn base64(data: &[u8]) -> String {
    const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(TBL[(n >> 18) as usize] as char);
        out.push(TBL[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            TBL[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TBL[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// The monitor's UI state.
pub struct App {
    vm: String,
    /// Configured resources from `meta.toml` (`?` if it couldn't be read).
    cpus: Option<u32>,
    mem: Option<String>,
    /// Boot reference for uptime (control-socket mtime); `None` if unavailable.
    boot: Option<SystemTime>,
    egress: FlowPanel,
    dns: FlowPanel,
    /// Parked egress requests (ADR-0021), id-ordered, with their expiry.
    requests: Vec<PendingRequest>,
    /// The highlighted request's id (`None` = no selection). An id, not an
    /// index: rows expire on their own, and approving adds a persistent rule.
    request_sel: Option<u64>,
    /// What a new pending request emits (OSC 9 / bell), cycled with `n`.
    notify: NotifyMode,
    /// Where `notify` persists.
    notify_path: PathBuf,
    /// A queued request verdict to apply after the select.
    pending_resolve: Option<(PendingRequest, AllowTarget)>,
    /// The allow popup, when open: it takes the keys and covers the panels.
    allow_popup: Option<AllowPopup>,
    /// An open block popup; while it is, keys go to it.
    block_popup: Option<BlockPopup>,
    /// Blocklist entries a new allow rule overrides, waiting for the user to say
    /// whether they go; while this is set, keys go to it.
    unblock_confirm: Option<Vec<BlocklistEntry>>,
    /// A blocklist entry to add after the select.
    pending_block: Option<BlocklistEntry>,
    /// Blocklist entries to remove after the select.
    pending_unblock: Option<Vec<BlocklistEntry>>,
    /// Set when `requests` may have missed events; re-fetched after the select.
    requests_dirty: bool,
    /// A notification to emit after the select (set by `ingest`).
    notify_msg: Option<String>,
    /// The tab shown.
    tab: Tab,
    /// Inference gateway requests and refusals (ADR-0020).
    inference: FlowPanel,
    /// Token balances by alias, from the gateway (`QuotaGet`).
    quota: Balances,
    /// Set when an inference event may have changed a balance.
    quota_dirty: bool,
    /// Cursor into `policy.models` on the Gateway panel.
    gateway_sel: Option<usize>,
    /// An open grant prompt; while it is, keys go to it.
    prompt: Option<GrantPrompt>,
    /// A grant (alias, tokens) to apply after the select.
    pending_grant: Option<(String, u64)>,
    /// A metering switch (alias, new mode) to apply after the select.
    pending_metering: Option<(String, QuotaMode)>,
    /// Show one row per destination on the flow panels (`u`) instead of the tail.
    unique: bool,
    policy: PolicyView,
    /// Set when a `Policy` event reports a version we haven't fetched rules for.
    policy_dirty: bool,
    /// Live VM state (`running`/`stopping`/…), updated from `Lifecycle` events.
    state: String,
    /// Total events lost to backpressure (supervisor ring + our own eviction).
    dropped: u64,
    /// Which panel the cursor is on.
    focus: Focus,
    /// Cursor into the Policy panel's rows, `policy.rules` then `policy.blocklist`
    /// (top-down index; `None` = no selection). Unlike the flow panels' cursors
    /// this is a plain list index, not an offset-from-newest.
    policy_sel: Option<usize>,
    /// A quick-action requested this frame, applied (async) after the select.
    pending_allow: Option<AllowTarget>,
    /// A revoke quick-action (the target `spec` for `remove_matching`) requested on
    /// the Policy panel this frame, applied (async) after the select.
    pending_revoke: Option<String>,
    /// The last quick-action's outcome, shown in the footer.
    notice: Option<Notice>,
    /// Whether the terminal answered the graphics-protocol probe: the Status
    /// logo is then transmitted once and placed as a real PNG over the panel.
    graphics: bool,
    /// Where the last frame put the Status logo — the graphics-protocol
    /// placement rect, applied between frames.
    logo_place: Option<Rect>,
    /// Whether the terminal currently shows a logo placement.
    logo_placed: bool,
    /// Set when the event stream closes (VM stopped).
    disconnected: bool,
    should_quit: bool,
}

impl App {
    fn new(
        vm: &str,
        meta: Option<VmMeta>,
        boot: Option<SystemTime>,
        policy: PolicyView,
        state: String,
        notify_path: PathBuf,
    ) -> Self {
        Self {
            vm: vm.to_string(),
            cpus: meta.as_ref().map(|m| m.cpus),
            mem: meta.map(|m| m.mem),
            boot,
            egress: FlowPanel::new(PANEL_CAPACITY),
            dns: FlowPanel::new(PANEL_CAPACITY),
            requests: Vec::new(),
            request_sel: None,
            notify: load_notify_from(&notify_path),
            notify_path,
            pending_resolve: None,
            allow_popup: None,
            block_popup: None,
            unblock_confirm: None,
            pending_block: None,
            pending_unblock: None,
            requests_dirty: false,
            notify_msg: None,
            tab: Tab::Network,
            inference: FlowPanel::new(PANEL_CAPACITY),
            quota: Balances::new(),
            quota_dirty: true,
            gateway_sel: None,
            prompt: None,
            pending_grant: None,
            pending_metering: None,
            unique: false,
            policy,
            policy_dirty: false,
            state,
            dropped: 0,
            focus: Focus::Egress,
            policy_sel: None,
            pending_allow: None,
            pending_revoke: None,
            notice: None,
            should_quit: false,
            disconnected: false,
            graphics: false,
            logo_place: None,
            logo_placed: false,
        }
    }

    /// Fold one live event into display state, routing it to the right panel and
    /// keeping the derived version/state/drop tallies current.
    fn ingest(&mut self, ev: Event) {
        match ev {
            Event::Egress { .. } => {
                if self.egress.push(ev, self.unique) {
                    self.dropped = self.dropped.saturating_add(1);
                }
            }
            // Gateway requests change balances; re-fetch them after this event.
            Event::Inference { .. } | Event::QuotaExhausted { .. } => {
                self.quota_dirty = true;
                if self.inference.push(ev, self.unique) {
                    self.dropped = self.dropped.saturating_add(1);
                }
            }
            Event::Dns { .. } => {
                if self.dns.push(ev, self.unique) {
                    self.dropped = self.dropped.saturating_add(1);
                }
            }
            // A parked request joined or left the table (ADR-0021). The pending
            // side also queues the terminal notification (OSC 9/bell).
            Event::RequestPending {
                id,
                proto,
                destination,
                port,
                via,
                expires_ts,
                ..
            } => {
                if self.requests.iter().any(|r| r.id == id) {
                    return;
                }
                self.requests.push(PendingRequest {
                    id,
                    proto,
                    destination,
                    port,
                    via,
                    expires_ts,
                });
                self.queue_request_notification();
            }
            Event::RequestResolved { id, .. } => {
                self.requests.retain(|r| r.id != id);
                self.drop_stale_request_sel();
            }
            Event::Policy { version, .. } => {
                // Show the new version immediately; flag a rules re-fetch.
                if version != self.policy.version {
                    self.policy.version = version;
                    self.policy_dirty = true;
                }
            }
            Event::Lifecycle { state, .. } => self.state = state,
            Event::Dropped { count, .. } => {
                self.dropped = self.dropped.saturating_add(count);
                // The gap may have swallowed request events.
                self.requests_dirty = true;
            }
        }
    }

    fn uptime(&self) -> Option<Duration> {
        self.boot
            .and_then(|b| SystemTime::now().duration_since(b).ok())
    }

    /// The focused flow panel, or `None` when the Policy or Gateway panel is
    /// focused (they hold rules and aliases, not events).
    fn focused_flow(&self) -> Option<&FlowPanel> {
        match self.focus {
            Focus::Egress => Some(&self.egress),
            Focus::Dns => Some(&self.dns),
            Focus::Inference => Some(&self.inference),
            Focus::Policy | Focus::Gateway | Focus::Requests => None,
        }
    }

    fn focused_flow_mut(&mut self) -> Option<&mut FlowPanel> {
        match self.focus {
            Focus::Egress => Some(&mut self.egress),
            Focus::Dns => Some(&mut self.dns),
            Focus::Inference => Some(&mut self.inference),
            Focus::Policy | Focus::Gateway | Focus::Requests => None,
        }
    }

    #[cfg(test)]
    fn sel(&self) -> Option<usize> {
        match self.focus {
            Focus::Egress => self.egress.sel,
            Focus::Dns => self.dns.sel,
            Focus::Inference => self.inference.sel,
            Focus::Requests => self.request_sel_index(),
            Focus::Policy => self.policy_sel,
            Focus::Gateway => self.gateway_sel,
        }
    }

    /// Move the cursor toward older rows (up the screen) in a flow panel. Starts
    /// at the newest row and clamps at the oldest retained one. A no-op on the
    /// Policy panel (see [`App::policy_select`]).
    fn select_older(&mut self) {
        let unique = self.unique;
        let Some(p) = self.focused_flow_mut() else {
            return;
        };
        let len = p.len(unique);
        if len == 0 {
            return;
        }
        p.sel = Some(p.sel.map_or(0, |o| (o + 1).min(len - 1)));
    }

    /// Move the cursor toward newer rows; past the newest it releases back to
    /// tail-following (no selection). A no-op on the Policy panel.
    fn select_newer(&mut self) {
        let Some(p) = self.focused_flow_mut() else {
            return;
        };
        match p.sel {
            Some(0) | None => p.release(),
            Some(o) => p.sel = Some(o - 1),
        }
    }

    /// Switch both flow panels between the tail and the unique view. Cursors
    /// index rows of the shown view, so they're released rather than carried over.
    fn toggle_unique(&mut self) {
        self.unique = !self.unique;
        self.egress.release();
        self.dns.release();
        self.inference.release();
    }

    /// Move the Policy-panel cursor by `delta` rows, clamped to the two lists;
    /// the first move from no-selection lands on the first row.
    fn policy_select(&mut self, delta: i32) {
        let len = self.policy.rows();
        if len == 0 {
            self.policy_sel = None;
            return;
        }
        self.policy_sel = Some(match self.policy_sel {
            None => 0,
            Some(cur) => (cur as i32 + delta).clamp(0, len as i32 - 1) as usize,
        });
    }

    /// Keep the Policy cursor valid after the lists change (e.g. a revoke removed
    /// rows or a re-fetch shrank a list).
    fn clamp_policy_sel(&mut self) {
        let len = self.policy.rows();
        self.policy_sel = match self.policy_sel {
            _ if len == 0 => None,
            Some(i) => Some(i.min(len - 1)),
            None => None,
        };
    }

    /// Move the focus to the next panel of the current tab.
    fn toggle_focus(&mut self) {
        self.focus = match self.focus {
            Focus::Requests => Focus::Egress,
            Focus::Egress => Focus::Dns,
            Focus::Dns => Focus::Policy,
            Focus::Policy => Focus::Requests,
            Focus::Inference => Focus::Gateway,
            Focus::Gateway => Focus::Inference,
        };
    }

    /// Move the Requests-panel cursor by `delta` rows, clamped to the request
    /// list; the first move from no-selection lands on the newest request
    /// (last row — the panel shows oldest at the top).
    fn request_select(&mut self, delta: i32) {
        let len = self.requests.len();
        if len == 0 {
            self.request_sel = None;
            return;
        }
        let next = match self.request_sel_index() {
            None => len - 1,
            Some(cur) => (cur as i32 + delta).clamp(0, len as i32 - 1) as usize,
        };
        self.request_sel = Some(self.requests[next].id);
    }

    /// Queue the terminal notification for a new request. Static text: the
    /// destination is guest-controlled, and this reaches the terminal as a raw
    /// escape sequence.
    fn queue_request_notification(&mut self) {
        self.notify_msg = Some(format!("{} has new egress requests", self.vm));
    }

    /// Clear the cursor if its request is gone. Never slide onto a neighbor: the
    /// next approve must act on a row the user picked.
    fn drop_stale_request_sel(&mut self) {
        if self.request_sel_index().is_none() {
            self.request_sel = None;
        }
    }

    /// Replace the rows with the supervisor's live list, after events were lost.
    fn sync_requests(&mut self, live: Vec<PendingRequest>) {
        if live
            .iter()
            .any(|r| !self.requests.iter().any(|known| known.id == r.id))
        {
            self.queue_request_notification();
        }
        self.requests = live;
        self.drop_stale_request_sel();
    }

    /// Remove rows past their expiry, whose `RequestResolved` must have been lost
    /// (the supervisor's sweep is what normally removes them).
    fn prune_expired_requests(&mut self, now: u64) {
        self.requests.retain(|r| r.expires_ts >= now);
        self.drop_stale_request_sel();
    }

    /// The highlighted request's row in `requests`.
    fn request_sel_index(&self) -> Option<usize> {
        let id = self.request_sel?;
        self.requests.iter().position(|r| r.id == id)
    }

    /// The highlighted pending request, or `None` when none is selected.
    fn selected_request(&self) -> Option<PendingRequest> {
        self.request_sel_index().map(|i| self.requests[i].clone())
    }

    /// Show `tab`, focusing its first panel.
    fn show_tab(&mut self, tab: Tab) {
        if self.tab != tab {
            self.tab = tab;
            self.focus = match tab {
                Tab::Network => Focus::Egress,
                Tab::Inference => Focus::Inference,
            };
        }
    }

    /// Move the Gateway-panel cursor by `delta` aliases, clamped; the first
    /// move from no selection lands on the first alias.
    fn gateway_select(&mut self, delta: i32) {
        let len = self.policy.models.len();
        self.gateway_sel = match (len, self.gateway_sel) {
            (0, _) => None,
            (_, None) => Some(0),
            (_, Some(cur)) => Some((cur as i32 + delta).clamp(0, len as i32 - 1) as usize),
        };
    }

    /// Keep the Gateway cursor valid after the alias list changes.
    fn clamp_gateway_sel(&mut self) {
        let len = self.policy.models.len();
        self.gateway_sel = match self.gateway_sel {
            _ if len == 0 => None,
            Some(i) => Some(i.min(len - 1)),
            None => None,
        };
    }

    /// The alias under the Gateway-panel cursor.
    fn selected_alias(&self) -> Result<&ModelAlias, &'static str> {
        self.gateway_sel
            .and_then(|i| self.policy.models.get(i))
            .ok_or("select an alias first (↑/↓)")
    }

    /// A balance as shown: `∞` while unlimited; otherwise the ledger balance,
    /// plus the alias's initial quota if its first use hasn't written it yet.
    fn balance_label(&self, alias: &ModelAlias) -> String {
        if !self.policy.is_metered(&alias.alias) {
            return "∞".to_string();
        }
        let b = self.quota.get(&alias.alias).cloned().unwrap_or_default();
        quota::shown_balance(&b, alias.initial_quota.unwrap_or(0)).to_string()
    }

    /// The event under the cursor in the focused flow panel, if any.
    /// In the unique view that's the destination's latest event, so a row whose
    /// most recent verdict is a block is still actionable.
    fn selected_event(&self) -> Option<&Event> {
        let p = self.focused_flow()?;
        p.rows(self.unique).nth(p.sel?).map(|(ev, _)| ev)
    }

    /// Ask whether the blocklist entries `target`'s rules now override should go.
    /// An allow rule wins either way, but they would come back into force if the
    /// rule were revoked.
    fn offer_unblock(&mut self, target: &AllowTarget) {
        let rules = allow_target_rules(target);
        let overridden: Vec<BlocklistEntry> = overridden_by(&rules, &self.policy.blocklist)
            .into_iter()
            .cloned()
            .collect();
        if !overridden.is_empty() {
            self.unblock_confirm = Some(overridden);
        }
    }

    /// The row under the Policy-panel cursor, if any.
    fn selected_policy_row(&self) -> Option<PolicyRow<'_>> {
        self.policy_sel.and_then(|i| self.policy.row(i))
    }

    /// What allowing the highlighted row would do — or why it can't. Only a
    /// *blocked* destination is actionable (allowing an already-allowed flow is a
    /// no-op the UI declines rather than issue a redundant policy bump).
    fn selected_allow_target(&self) -> Result<AllowTarget, &'static str> {
        match self.selected_event() {
            None => Err("select a row first (↑/↓)"),
            Some(Event::Egress {
                verdict: Verdict::Blocked,
                proto,
                daddr,
                dport,
                ..
            }) => Ok(AllowTarget::Flow {
                ip: daddr.clone(),
                port: *dport,
                proto: proto.clone(),
            }),
            Some(Event::Egress { .. }) => Err("that flow is already allowed"),
            Some(Event::Dns {
                verdict: DnsVerdict::Refused,
                qname,
                ..
            }) => Ok(AllowTarget::Resolve(strip_trailing_dot(qname))),
            Some(Event::Dns { .. }) => Err("that query is already allowed"),
            Some(_) => Err("nothing to allow on that row"),
        }
    }
}

/// DNS query names are often fully-qualified with a trailing dot, which the
/// domain-rule validator rejects; drop it so the allow lands cleanly.
fn strip_trailing_dot(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_string()
}

/// `soda tui <vm>` entry point. Builds a small runtime, connects + subscribes,
/// then runs the render loop until the user quits.
pub fn run(vm: &str) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        // Seed the panels before entering the alternate screen: static config
        // from meta.toml, the boot reference for uptime, and an initial status +
        // policy probe on throwaway connections (subscribe consumes its client).
        let meta = VmMeta::load(vm).ok();
        let boot = boot_time(vm);
        let (state, _pv) = fetch_status(vm).await.unwrap_or_else(|| ("?".into(), 0));
        let policy = fetch_policy(vm)
            .await
            .map(PolicyView::from)
            .unwrap_or_default();

        let client = match ControlClient::connect(vm).await {
            Ok(c) => c,
            Err(e) => anyhow::bail!(
                "cannot connect to '{vm}' — is it running? (`soda start {vm} --net`): {e}"
            ),
        };
        let (ack, stream) = client.subscribe().await?;
        match ack {
            Response::Ok => {}
            Response::Error { msg } => anyhow::bail!("subscribe refused by '{vm}': {msg}"),
            other => anyhow::bail!("unexpected subscribe ack from '{vm}': {other:?}"),
        }

        let mut app = App::new(vm, meta, boot, policy, state, notify_path());
        // Seed the Egress Requests panel with whatever is already parked
        // (ADR-0021); live events keep it current from here on.
        app.requests = fetch_requests(vm).await.unwrap_or_default();
        let mut terminal = ratatui::init();
        // The Status logo: probe for the graphics protocol and, where it
        // answers, transmit the PNG once — every frame places it.
        app.graphics = detect_graphics();
        if app.graphics {
            transmit_logo();
        }
        let res = event_loop(&mut terminal, &mut app, stream).await;
        // Free the terminal's copy of the logo, on the screen that holds it.
        if app.graphics {
            delete_logo();
        }
        ratatui::restore();
        res
    })
}

/// The control socket's mtime — written when the supervisor bound it at boot —
/// is a good-enough VM-start reference for an uptime display.
fn boot_time(vm: &str) -> Option<SystemTime> {
    std::fs::metadata(paths::control_sock_path(vm))
        .ok()?
        .modified()
        .ok()
}

/// Best-effort `status` probe on a short-lived connection.
async fn fetch_status(vm: &str) -> Option<(String, u32)> {
    let mut c = ControlClient::connect(vm).await.ok()?;
    match c.request(&Request::Status).await.ok()? {
        Response::Status {
            state,
            policy_version,
        } => Some((state, policy_version)),
        _ => None,
    }
}

/// Best-effort `policy.get` on a short-lived connection (the policy panel's rules
/// aren't on the event feed).
async fn fetch_policy(vm: &str) -> Option<VmPolicy> {
    let mut c = ControlClient::connect(vm).await.ok()?;
    match c.request(&Request::PolicyGet).await.ok()? {
        Response::Policy { policy } => Some(policy),
        _ => None,
    }
}

/// Apply a quick-action: add `target` to `vm`'s persisted policy, validate,
/// version-bump, save `policy.toml`, and push the whole new policy live via
/// `PolicySet` — the same edit-then-push path as `soda allow`, so the file and
/// the live allowlist never split-brain. Returns the new policy (so the panel can
/// refresh without a round trip) and a human summary. An add that duplicates an
/// existing rule writes nothing and bumps no version, but still pushes: a rule in
/// the file isn't necessarily live (a failed push, a hand edit), and approving a
/// request against one the supervisor lacks would be refused by the proxy.
async fn apply_allow(vm: &str, target: &AllowTarget) -> anyhow::Result<(VmPolicy, String)> {
    let _lock = PolicyFile::lock(vm)?;
    let mut file = PolicyFile::load(vm).map_err(|e| anyhow::anyhow!("reading policy: {e}"))?;
    let (added, summary) = match target {
        AllowTarget::Resolve(name) => (
            file.add_resolve(name, DomainScope::Subdomains)
                .map_err(|e| anyhow::anyhow!(e))?,
            format!("allowed resolving {name}"),
        ),
        AllowTarget::Flow { ip, port, proto } => (
            file.add_ip_for_proto(ip, Some(&port.to_string()), Some(proto))
                .map_err(|e| anyhow::anyhow!(e))?,
            format!("allowed {proto} {ip}:{port}"),
        ),
        AllowTarget::Domain { name, grants } => {
            let mut added = false;
            for g in grants {
                added |= file
                    .add_domain_for_proto(
                        name,
                        DomainScope::Subdomains,
                        g.ports.as_deref(),
                        g.proto.as_deref(),
                    )
                    .map_err(|e| anyhow::anyhow!(e))?;
            }
            (added, format!("allowed {name}"))
        }
    };
    let policy = if added {
        save_bumped(vm, &mut file)?
    } else {
        file.policy().map_err(|e| anyhow::anyhow!(e))?
    };

    let mut client = ControlClient::connect(vm)
        .await
        .map_err(|e| anyhow::anyhow!("connecting to control socket: {e}"))?;
    match client
        .request(&Request::PolicySet {
            policy: policy.clone(),
        })
        .await?
    {
        Response::Ok if !added => Ok((policy, "already allowed".into())),
        Response::Ok => Ok((policy.clone(), format!("{summary} (v{})", policy.version))),
        Response::Error { msg } => anyhow::bail!("supervisor rejected: {msg}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

/// Validate that the edited policy compiles (fail-closed), bump its version and
/// save `policy.toml` — comments preserved — returning the saved policy.
fn save_bumped(vm: &str, file: &mut PolicyFile) -> anyhow::Result<VmPolicy> {
    use sodabox_common::allowlist::Allowlist;

    let policy = file
        .policy()
        .map_err(|e| anyhow::anyhow!("invalid policy: {e}"))?;
    Allowlist::from_policy(&policy).map_err(|e| anyhow::anyhow!("invalid policy: {e}"))?;
    policy
        .validate_models()
        .map_err(|e| anyhow::anyhow!("invalid policy: {e}"))?;
    file.set_version(policy.version + 1);
    file.save(vm)
        .map_err(|e| anyhow::anyhow!("writing policy.toml: {e}"))?;
    file.policy().map_err(|e| anyhow::anyhow!(e))
}

/// Add `entry` to the blocklist and push the policy live, which is what denying a
/// request does (ADR-0021): the supervisor's sweep refuses the row and any others
/// the entry covers, with this as their reason. A duplicate writes nothing but
/// still pushes, like [`apply_allow`]. A row that expired in the meantime still
/// records: the decision was about the destination, not that one attempt.
async fn apply_block(vm: &str, entry: &BlocklistEntry) -> anyhow::Result<(VmPolicy, String)> {
    let _lock = PolicyFile::lock(vm)?;
    let mut file = PolicyFile::load(vm).map_err(|e| anyhow::anyhow!("reading policy: {e}"))?;
    let added = file.add_blocklist(entry).map_err(|e| anyhow::anyhow!(e))?;
    let policy = if added {
        save_bumped(vm, &mut file)?
    } else {
        file.policy().map_err(|e| anyhow::anyhow!(e))?
    };
    push_policy(vm, &policy).await?;
    let summary = format!("blocked {} (v{})", fmt_block(entry), policy.version);
    Ok((policy, summary))
}

/// Remove `entries` from the blocklist and push the policy live.
async fn apply_unblock(vm: &str, entries: &[BlocklistEntry]) -> anyhow::Result<(VmPolicy, String)> {
    let _lock = PolicyFile::lock(vm)?;
    let mut file = PolicyFile::load(vm).map_err(|e| anyhow::anyhow!("reading policy: {e}"))?;
    let removed = file
        .remove_blocklist(|e| entries.contains(e))
        .map_err(|e| anyhow::anyhow!(e))?;
    let policy = if removed > 0 {
        save_bumped(vm, &mut file)?
    } else {
        file.policy().map_err(|e| anyhow::anyhow!(e))?
    };
    push_policy(vm, &policy).await?;
    let summary = format!("unblocked {removed} (v{})", policy.version);
    Ok((policy, summary))
}

/// Push the whole policy to the supervisor.
async fn push_policy(vm: &str, policy: &VmPolicy) -> anyhow::Result<()> {
    let mut client = ControlClient::connect(vm)
        .await
        .map_err(|e| anyhow::anyhow!("connecting to control socket: {e}"))?;
    match client
        .request(&Request::PolicySet {
            policy: policy.clone(),
        })
        .await?
    {
        Response::Ok => Ok(()),
        Response::Error { msg } => anyhow::bail!("supervisor rejected: {msg}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

/// Apply a revoke quick-action: remove every rule matching `spec` from
/// `vm`'s persisted policy, validate, version-bump, save `policy.toml`, and push
/// the whole new policy live via `PolicySet` — the same edit-then-push path as
/// `soda revoke`, so the file and the live allowlist never split-brain (the live
/// swap also purges a removed domain's ephemerals). Returns the new policy
/// (so the panel refreshes without a round trip) and a human summary. A `spec`
/// that matches nothing short-circuits with no version bump.
async fn apply_revoke(vm: &str, spec: &str) -> anyhow::Result<(VmPolicy, String)> {
    let _lock = PolicyFile::lock(vm)?;
    let mut file = PolicyFile::load(vm).map_err(|e| anyhow::anyhow!("reading policy: {e}"))?;
    let removed = file.remove_matching(spec).map_err(|e| anyhow::anyhow!(e))?;
    if removed == 0 {
        // Nothing persisted matched (e.g. the panel was stale) — no-op.
        return Ok((
            file.policy().map_err(|e| anyhow::anyhow!(e))?,
            format!("no rule matching '{spec}'"),
        ));
    }

    // A removal can't introduce a bad rule, but keep the same discipline.
    let policy = save_bumped(vm, &mut file)?;

    let mut client = ControlClient::connect(vm)
        .await
        .map_err(|e| anyhow::anyhow!("connecting to control socket: {e}"))?;
    match client
        .request(&Request::PolicySet {
            policy: policy.clone(),
        })
        .await?
    {
        Response::Ok => {
            let plural = if removed == 1 { "rule" } else { "rules" };
            Ok((
                policy.clone(),
                format!("revoked {spec} ({removed} {plural}) (v{})", policy.version),
            ))
        }
        Response::Error { msg } => anyhow::bail!("supervisor rejected: {msg}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

/// Best-effort `QuotaGet`: the gateway's live balances.
async fn fetch_quota(vm: &str) -> Option<Balances> {
    let mut c = ControlClient::connect(vm).await.ok()?;
    match c.request(&Request::QuotaGet).await.ok()? {
        Response::Quota { balances } => Some(balances),
        _ => None,
    }
}

/// Best-effort `RequestList` (ADR-0021): the parked requests a freshly
/// started TUI should show without waiting for new ones.
async fn fetch_requests(vm: &str) -> Option<Vec<PendingRequest>> {
    let mut c = ControlClient::connect(vm).await.ok()?;
    match c.request(&Request::RequestList).await.ok()? {
        Response::Requests { requests } => Some(requests),
        _ => None,
    }
}

/// Approve a request (ADR-0021): first add the persistent allowlist rule `target`
/// describes (the same quick-allow path as `soda allow` — approve *is* a rule, so
/// the held flow proceeds through the normal allow path), then resolve the parked
/// request over the control socket. Resolving an id that expired in between is
/// `Ok` (idempotent), so this first checks the request is still pending: a stale
/// row must not add a persistent rule or report an approval that admitted nothing.
/// Returns the new policy (so the panel refreshes) and a summary.
async fn apply_resolve(
    vm: &str,
    req: &PendingRequest,
    target: &AllowTarget,
) -> anyhow::Result<(VmPolicy, String)> {
    let live = fetch_requests(vm)
        .await
        .ok_or_else(|| anyhow::anyhow!("couldn't list pending requests"))?;
    if !live.iter().any(|r| r.id == req.id) {
        anyhow::bail!("request #{} is no longer pending", req.id);
    }
    let (policy, summary) = apply_allow(vm, target).await?;
    // A `domain` rule picked on an address row isn't resolved here: the sweep
    // releases this row and its siblings once it has restored their permits,
    // and only if the rule covers them. Approving now would fail the proxy's
    // re-check.
    if matches!(target, AllowTarget::Domain { .. }) && req.port.is_some() {
        return Ok((policy, summary));
    }

    let mut client = ControlClient::connect(vm)
        .await
        .map_err(|e| anyhow::anyhow!("connecting to control socket: {e}"))?;
    match client
        .request(&Request::RequestResolve {
            id: req.id,
            allow: true,
        })
        .await?
    {
        Response::Ok => {
            let where_to = match req.port {
                Some(p) => format!("{}:{p}", req.destination),
                None => req.destination.clone(),
            };
            Ok((policy, format!("approved {where_to} (request #{})", req.id)))
        }
        Response::Error { msg } => anyhow::bail!("supervisor rejected: {msg}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

/// Grant `tokens` to `alias`: append to the quota ledger and have the running
/// gateway re-read it, the same as `soda quota grant` (ADR-0020).
async fn apply_grant(vm: &str, alias: &str, tokens: u64) -> anyhow::Result<String> {
    let delta = i64::try_from(tokens).map_err(|_| anyhow::anyhow!("token count too large"))?;
    Ledger::for_vm(vm).append(&Entry {
        ts: sodabox_common::event::now_ts(),
        alias: alias.to_string(),
        delta,
        reason: Reason::Grant,
        tokens: None,
        estimated: false,
    })?;
    let mut client = ControlClient::connect(vm)
        .await
        .map_err(|e| anyhow::anyhow!("connecting to control socket: {e}"))?;
    match client.request(&Request::QuotaReload).await? {
        Response::Ok => Ok(format!("granted {tokens} tokens to '{alias}'")),
        Response::Error { msg } => anyhow::bail!("granted, but the gateway didn't reload: {msg}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

/// Switch `alias` to `mode` (limited/unlimited): edit `policy.toml` and push it
/// live, the same as `soda quota unlimited|limited <alias>`.
async fn apply_metering(
    vm: &str,
    alias: &str,
    mode: QuotaMode,
) -> anyhow::Result<(VmPolicy, String)> {
    let _lock = PolicyFile::lock(vm)?;
    let mut file = PolicyFile::load(vm).map_err(|e| anyhow::anyhow!("reading policy: {e}"))?;
    file.set_quota_mode(Some(alias), mode)
        .map_err(|e| anyhow::anyhow!(e))?;
    let policy = save_bumped(vm, &mut file)?;
    let word = match mode {
        QuotaMode::Unlimited => "unlimited",
        QuotaMode::Limited => "limited",
    };
    let mut client = ControlClient::connect(vm)
        .await
        .map_err(|e| anyhow::anyhow!("connecting to control socket: {e}"))?;
    match client
        .request(&Request::PolicySet {
            policy: policy.clone(),
        })
        .await?
    {
        Response::Ok => {
            let summary = format!("'{alias}' is now {word} (v{})", policy.version);
            Ok((policy, summary))
        }
        Response::Error { msg } => anyhow::bail!("supervisor rejected: {msg}"),
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
}

/// The render loop. Ingests events as fast as they arrive, reads keyboard input
/// off a blocking reader thread, and repaints on a fixed tick so bursts coalesce.
async fn event_loop(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    mut stream: EventStream,
) -> anyhow::Result<()> {
    let mut keys = spawn_input_reader();
    let mut redraw = tokio::time::interval(REDRAW_INTERVAL);

    draw_frame(terminal, app)?;
    loop {
        tokio::select! {
            ev = stream.recv(), if !app.disconnected => match ev {
                Ok(Some(e)) => app.ingest(e),
                Ok(None) | Err(_) => {
                    app.disconnected = true;
                    app.state = "stopped".into();
                }
            },
            key = keys.recv() => match key {
                Some(k) => handle_key(app, k),
                None => app.should_quit = true, // input thread gone
            },
            _ = redraw.tick() => {
                app.prune_expired_requests(sodabox_common::event::now_ts());
                draw_frame(terminal, app)?;
            }
        }

        // A quick-action (`a`/Enter on a blocked row): edit + push live, then
        // reflect the result in the footer and the policy panel. Done here, off
        // the sync key handler, since it awaits a control-socket round trip.
        if let Some(target) = app.pending_allow.take() {
            match apply_allow(&app.vm, &target).await {
                Ok((policy, summary)) => {
                    app.policy = PolicyView::from(policy);
                    app.clamp_policy_sel();
                    app.offer_unblock(&target);
                    app.notice = Some(Notice {
                        text: summary,
                        error: false,
                    });
                }
                Err(e) => {
                    app.notice = Some(Notice {
                        text: e.to_string(),
                        error: true,
                    })
                }
            }
        }

        // Denying a request records it (`d` on the Egress Requests panel, through
        // the popup on an address with a name), and a blocklist row or a confirmed
        // offer takes entries away again: edit + push live, as below.
        let blocklist_edit = if let Some(entry) = app.pending_block.take() {
            Some(apply_block(&app.vm, &entry).await)
        } else if let Some(entries) = app.pending_unblock.take() {
            Some(apply_unblock(&app.vm, &entries).await)
        } else {
            None
        };
        if let Some(result) = blocklist_edit {
            match result {
                Ok((policy, summary)) => {
                    app.policy = PolicyView::from(policy);
                    app.clamp_policy_sel();
                    app.notice = Some(Notice {
                        text: summary,
                        error: false,
                    });
                }
                Err(e) => {
                    app.notice = Some(Notice {
                        text: e.to_string(),
                        error: true,
                    })
                }
            }
        }

        // A revoke quick-action on the Policy panel (`d`/Enter): remove + push live,
        // then reflect the result in the footer and refresh the panel.
        if let Some(spec) = app.pending_revoke.take() {
            match apply_revoke(&app.vm, &spec).await {
                Ok((policy, summary)) => {
                    app.policy = PolicyView::from(policy);
                    app.clamp_policy_sel();
                    app.notice = Some(Notice {
                        text: summary,
                        error: false,
                    });
                }
                Err(e) => {
                    app.notice = Some(Notice {
                        text: e.to_string(),
                        error: true,
                    })
                }
            }
        }

        // An approval (ADR-0021: `a`/Enter on the Egress Requests panel): add the
        // rule then resolve the held request over the control socket.
        if let Some((req, target)) = app.pending_resolve.take() {
            match apply_resolve(&app.vm, &req, &target).await {
                Ok((policy, summary)) => {
                    app.policy = PolicyView::from(policy);
                    app.clamp_policy_sel();
                    app.offer_unblock(&target);
                    app.notice = Some(Notice {
                        text: summary,
                        error: false,
                    });
                }
                Err(e) => {
                    app.notice = Some(Notice {
                        text: e.to_string(),
                        error: true,
                    });
                    // The row may be stale (see `apply_resolve`).
                    app.requests_dirty = true;
                }
            }
        }

        // Events were lost, or an approve hit a stale row: take the supervisor's
        // list. Before the notification below, which this may queue.
        if app.requests_dirty && !app.disconnected {
            if let Some(live) = fetch_requests(&app.vm).await {
                app.sync_requests(live);
            }
            app.requests_dirty = false;
        }

        // A new parked request queued a notification (ADR-0021): OSC 9 and/or
        // the bell, per the `n`-cycled mode. Off the sync ingest so the raw
        // escape sequences land between frames.
        if let Some(msg) = app.notify_msg.take() {
            notify_terminal(app.notify, &msg);
        }

        // A policy version bump means the rules may have changed; re-fetch them
        // (a quick local IPC round trip) outside the panel render.
        if app.policy_dirty && !app.disconnected {
            if let Some(p) = fetch_policy(&app.vm).await {
                app.policy = PolicyView::from(p);
                app.clamp_policy_sel();
                app.clamp_gateway_sel();
            }
            app.policy_dirty = false;
        }

        // Gateway quick-actions (`g` grant, `m` metering on the Gateway panel).
        if let Some((alias, tokens)) = app.pending_grant.take() {
            app.notice = Some(match apply_grant(&app.vm, &alias, tokens).await {
                Ok(text) => Notice { text, error: false },
                Err(e) => Notice {
                    text: e.to_string(),
                    error: true,
                },
            });
            app.quota_dirty = true;
        }
        if let Some((alias, mode)) = app.pending_metering.take() {
            match apply_metering(&app.vm, &alias, mode).await {
                Ok((policy, text)) => {
                    app.policy = PolicyView::from(policy);
                    app.clamp_gateway_sel();
                    app.notice = Some(Notice { text, error: false });
                }
                Err(e) => {
                    app.notice = Some(Notice {
                        text: e.to_string(),
                        error: true,
                    })
                }
            }
        }

        // Balances changed (a request finished, or a grant): re-fetch them.
        if app.quota_dirty && !app.disconnected && app.policy.gateway_used() {
            if let Some(q) = fetch_quota(&app.vm).await {
                app.quota = q;
            }
            app.quota_dirty = false;
        }

        if app.should_quit {
            break;
        }
    }
    Ok(())
}

/// Paint one frame and, when the terminal speaks the graphics protocol, put
/// the logo image over the cells the frame reserved for it. Repeating the
/// same placement id every frame lets the terminal swap it in place without
/// flicker — and follow resizes.
fn draw_frame(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> anyhow::Result<()> {
    terminal.draw(|f| draw(f, app))?;
    if app.graphics {
        place_logo(&mut std::io::stdout(), app);
    }
    Ok(())
}

/// Spawn a blocking thread that forwards key presses onto a channel. crossterm's
/// `read()` blocks, so it lives off the async runtime; it exits when the receiver
/// drops (loop ends) or the process does.
fn spawn_input_reader() -> mpsc::Receiver<KeyPress> {
    let (tx, rx) = mpsc::channel(64);
    std::thread::spawn(move || loop {
        match event::read() {
            Ok(TermEvent::Key(k)) if k.kind == KeyEventKind::Press => {
                if tx
                    .blocking_send(KeyPress {
                        code: k.code,
                        mods: k.modifiers,
                    })
                    .is_err()
                {
                    break;
                }
            }
            Ok(_) => {}      // resize/mouse/etc. — the tick redraw handles reflow
            Err(_) => break, // stdin closed
        }
    });
    rx
}

/// A key press decoupled from crossterm's event type so the loop stays testable.
struct KeyPress {
    code: KeyCode,
    mods: KeyModifiers,
}

/// Key bindings: quit (`q`/`Esc`/`Ctrl-C`), switch tab (`1`/`2`, `←`/`→`),
/// switch panel within the tab (`Tab`), move the cursor (`↑`/`↓`, `k`/`j`),
/// toggle the unique view of the flow panels (`u`). On the Egress/DNS panels
/// `a`/Enter allows the highlighted blocked destination; on the Policy panel
/// `d`/Enter revokes the highlighted rule or unblocks the highlighted entry; on the
/// Gateway panel `g`/Enter grants tokens to the highlighted alias and `m` switches
/// it between limited and unlimited. While the grant prompt, a popup or the unblock
/// question is open, keys go to it instead.
fn handle_key(app: &mut App, k: KeyPress) {
    if app.prompt.is_some() {
        prompt_key(app, k);
        return;
    }
    if app.allow_popup.is_some() {
        allow_popup_key(app, k);
        return;
    }
    if app.block_popup.is_some() {
        block_popup_key(app, k);
        return;
    }
    if app.unblock_confirm.is_some() {
        unblock_confirm_key(app, k);
        return;
    }
    match k.code {
        KeyCode::Char('c') if k.mods.contains(KeyModifiers::CONTROL) => app.should_quit = true,
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
        KeyCode::Char('1') | KeyCode::Left => app.show_tab(Tab::Network),
        KeyCode::Char('2') | KeyCode::Right => app.show_tab(Tab::Inference),
        KeyCode::Tab | KeyCode::BackTab => app.toggle_focus(),
        KeyCode::Char('u') => app.toggle_unique(),
        KeyCode::Up | KeyCode::Char('k') => match app.focus {
            Focus::Policy => app.policy_select(-1),
            Focus::Gateway => app.gateway_select(-1),
            Focus::Requests => app.request_select(-1),
            _ => app.select_older(),
        },
        KeyCode::Down | KeyCode::Char('j') => match app.focus {
            Focus::Policy => app.policy_select(1),
            Focus::Gateway => app.gateway_select(1),
            Focus::Requests => app.request_select(1),
            _ => app.select_newer(),
        },
        // `a` allows (Egress/DNS/Requests); `d` denies (Requests), revokes or
        // unblocks (Policy); `g` grants and `m` switches metering (Gateway); `n` cycles the
        // pending-request notification mode (off|notification|bell|all).
        // Enter is "act on the selection".
        KeyCode::Char('n') => {
            app.notify = app.notify.next();
            save_notify_to(&app.notify_path, app.notify);
            app.notice = Some(Notice {
                text: format!("notifications: {}", app.notify.as_str()),
                error: false,
            });
        }
        KeyCode::Char('a') if matches!(app.focus, Focus::Egress | Focus::Dns) => request_allow(app),
        KeyCode::Char('a') if app.focus == Focus::Requests => request_approve(app),
        KeyCode::Char('d') if app.focus == Focus::Policy => request_policy_remove(app),
        KeyCode::Char('d') if app.focus == Focus::Requests => request_block(app),
        KeyCode::Char('g') if app.focus == Focus::Gateway => open_grant_prompt(app),
        KeyCode::Char('m') if app.focus == Focus::Gateway => request_metering(app),
        KeyCode::Enter => match app.focus {
            Focus::Policy => request_policy_remove(app),
            Focus::Gateway => open_grant_prompt(app),
            Focus::Egress | Focus::Dns => request_allow(app),
            Focus::Requests => request_approve(app),
            Focus::Inference => {}
        },
        _ => {}
    }
}

/// Keys while the grant prompt is open: a token count like `500k` or `2M`,
/// Enter to grant, Esc to cancel.
fn prompt_key(app: &mut App, k: KeyPress) {
    let Some(prompt) = app.prompt.as_mut() else {
        return;
    };
    match k.code {
        KeyCode::Esc => app.prompt = None,
        KeyCode::Char('c') if k.mods.contains(KeyModifiers::CONTROL) => app.prompt = None,
        KeyCode::Backspace => {
            prompt.input.pop();
        }
        KeyCode::Char(c)
            if (c.is_ascii_digit() || "kKmM.".contains(c)) && prompt.input.len() < 16 =>
        {
            prompt.input.push(c)
        }
        KeyCode::Enter => match quota::parse_tokens(&prompt.input) {
            Ok(0) | Err(_) => {
                app.notice = Some(Notice {
                    text: "enter a token count like 1500, 500k or 2M".into(),
                    error: true,
                })
            }
            Ok(n) => {
                app.pending_grant = Some((prompt.alias.clone(), n));
                app.prompt = None;
            }
        },
        _ => {}
    }
}

/// Keys while the allow popup is open: `←`/`→` or `Tab` move between the choices,
/// typing edits the port field of TCP and UDP, Enter confirms, Esc cancels.
fn allow_popup_key(app: &mut App, k: KeyPress) {
    let Some(popup) = app.allow_popup.as_mut() else {
        return;
    };
    match k.code {
        KeyCode::Esc => app.allow_popup = None,
        KeyCode::Char('c') if k.mods.contains(KeyModifiers::CONTROL) => app.allow_popup = None,
        KeyCode::Left | KeyCode::BackTab => popup.step(false),
        KeyCode::Right | KeyCode::Tab => popup.step(true),
        KeyCode::Backspace => {
            if let Some(field) = popup.field() {
                field.pop();
            }
            popup.error = None;
        }
        KeyCode::Char(c) if c.is_ascii_digit() || c == ',' || c == '-' => {
            if let Some(field) = popup.field() {
                if field.len() < MAX_PORT_FIELD {
                    field.push(c);
                }
            }
            popup.error = None;
        }
        KeyCode::Enter => match popup.target() {
            Err(e) => popup.error = Some(e),
            Ok(target) => {
                match popup.request.take() {
                    Some(req) => app.pending_resolve = Some((req, target)),
                    None => app.pending_allow = Some(target),
                }
                app.allow_popup = None;
            }
        },
        _ => {}
    }
}

/// Keys while the block popup is open: `←`/`→` or `Tab` move between the choices,
/// Enter confirms, Esc cancels without deciding, leaving the row counting down.
fn block_popup_key(app: &mut App, k: KeyPress) {
    let Some(popup) = app.block_popup.as_mut() else {
        return;
    };
    match k.code {
        KeyCode::Esc => app.block_popup = None,
        KeyCode::Char('c') if k.mods.contains(KeyModifiers::CONTROL) => app.block_popup = None,
        KeyCode::Left | KeyCode::BackTab => popup.step(false),
        KeyCode::Right | KeyCode::Tab => popup.step(true),
        KeyCode::Enter => {
            app.pending_block = Some(popup.entry());
            app.block_popup = None;
        }
        _ => {}
    }
}

/// Keys while the unblock question is open: only `y` removes anything. Enter
/// doesn't answer, since it just confirmed the allow that raised the question.
fn unblock_confirm_key(app: &mut App, k: KeyPress) {
    match k.code {
        KeyCode::Char('y') => app.pending_unblock = app.unblock_confirm.take(),
        KeyCode::Char('n') | KeyCode::Esc => app.unblock_confirm = None,
        KeyCode::Char('c') if k.mods.contains(KeyModifiers::CONTROL) => app.unblock_confirm = None,
        _ => {}
    }
}

/// Open the grant prompt for the highlighted alias.
fn open_grant_prompt(app: &mut App) {
    match app.selected_alias() {
        Ok(m) => {
            app.prompt = Some(GrantPrompt {
                alias: m.alias.clone(),
                input: String::new(),
            });
            app.notice = None;
        }
        Err(msg) => {
            app.notice = Some(Notice {
                text: msg.to_string(),
                error: true,
            })
        }
    }
}

/// Queue switching the highlighted alias between limited and unlimited.
fn request_metering(app: &mut App) {
    match app.selected_alias() {
        Ok(m) => {
            let mode = if m.quota == Some(QuotaMode::Unlimited) {
                QuotaMode::Limited
            } else {
                QuotaMode::Unlimited
            };
            app.pending_metering = Some((m.alias.clone(), mode));
        }
        Err(msg) => {
            app.notice = Some(Notice {
                text: msg.to_string(),
                error: true,
            })
        }
    }
}

/// Queue an allow of the highlighted blocked flow, or surface why it can't.
fn request_allow(app: &mut App) {
    match app.selected_allow_target() {
        // A refused name: ask what allowing it should grant.
        Ok(AllowTarget::Resolve(name)) => {
            let narrow = AllowTarget::Resolve(name.clone());
            app.allow_popup = Some(AllowPopup::new(None, name, narrow));
        }
        // Defer the actual edit+push to the async loop; capture the target now.
        Ok(target) => app.pending_allow = Some(target),
        Err(msg) => {
            app.notice = Some(Notice {
                text: msg.to_string(),
                error: true,
            })
        }
    }
}

/// Queue removing the highlighted Policy panel row: revoking a rule, unblocking an
/// entry. Only that entry: unlike rules, they differ by what they refuse.
fn request_policy_remove(app: &mut App) {
    match app.selected_policy_row() {
        Some(PolicyRow::Rule(rule)) => app.pending_revoke = Some(rule.target().to_string()),
        Some(PolicyRow::Blocked(entry)) => app.pending_unblock = Some(vec![entry.clone()]),
        None => {
            app.notice = Some(Notice {
                text: "select a rule first (↑/↓)".into(),
                error: true,
            })
        }
    }
}

/// The highlighted pending egress request, or a notice that there is none.
fn selected_request_or_notice(app: &mut App) -> Option<PendingRequest> {
    let req = app.selected_request();
    if req.is_none() {
        app.notice = Some(Notice {
            text: "no pending request selected".into(),
            error: true,
        });
    }
    req
}

/// Queue approving the highlighted pending egress request (ADR-0021). Applied in
/// the async loop: first the persistent rule (the quick-allow path), then resolving
/// the request over the control socket. A row with a name asks what to grant first.
fn request_approve(app: &mut App) {
    let Some(req) = selected_request_or_notice(app) else {
        return;
    };
    let narrow = request_allow_target(&req);
    match request_allow_name(&req) {
        Some(name) => app.allow_popup = Some(AllowPopup::new(Some(req), name, narrow)),
        None => app.pending_resolve = Some((req, narrow)),
    }
}

/// Queue denying the highlighted pending egress request, which records it on the
/// blocklist (ADR-0021). An address with a name asks whether to record the address
/// or the name; a dns row is its exact name and an address with no name is itself,
/// so there is nothing to ask.
fn request_block(app: &mut App) {
    let Some(req) = selected_request_or_notice(app) else {
        return;
    };
    match req.port.and_then(|_| request_allow_name(&req)) {
        Some(name) => {
            app.block_popup = Some(BlockPopup {
                request: req,
                name,
                choice: BlockChoice::NamePort,
            })
        }
        None => app.pending_block = Some(request_block_entry(&req)),
    }
}

/// Paint one frame: header, four panels, footer.
///
/// ```text
/// ┌ header ─────────────────────────────┐
/// │ Egress            │ Status          │
/// │                   ├─────────────────┤
/// │───────────────────│ Policy          │
/// │ DNS               │                 │
/// └ footer ─────────────────────────────┘
/// ```
///
/// Takes `app` mutably only to settle each flow panel's scroll window against
/// the panel's actual height.
///
/// Panels show guest-controlled text (a DNS name can hold any byte), and the
/// widgets copy control characters into cells, which the backend then writes to
/// the terminal as escape sequences. So the finished frame is scrubbed here,
/// whichever panel the text landed in.
fn draw(f: &mut Frame, app: &mut App) {
    draw_panels(f, app);
    if let Some(popup) = &app.allow_popup {
        render_allow_popup(f, popup);
        // The logo is an image above the cells, and would cover the popup.
        app.logo_place = None;
    }
    if let Some(popup) = &app.block_popup {
        render_block_popup(f, popup);
        app.logo_place = None;
    }
    if let Some(entries) = &app.unblock_confirm {
        render_unblock_confirm(f, entries);
        app.logo_place = None;
    }
    for cell in &mut f.buffer_mut().content {
        if cell.symbol().contains(char::is_control) {
            cell.set_symbol("?");
        }
    }
}

fn draw_panels(f: &mut Frame, app: &mut App) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(f.area());

    f.render_widget(header(app), outer[0]);

    // The alias table needs more width than the policy list.
    let split = match app.tab {
        Tab::Network => [Constraint::Percentage(60), Constraint::Percentage(40)],
        Tab::Inference => [Constraint::Percentage(55), Constraint::Percentage(45)],
    };
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(split)
        .split(outer[1]);

    if app.tab == Tab::Inference {
        // Inference tab: the gateway's requests on the left; status and the
        // alias table on the right.
        let right = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(6), Constraint::Min(1)])
            .split(body[1]);
        render_flow_panel(
            f,
            body[0],
            "Inference",
            &mut app.inference,
            app.focus == Focus::Inference,
            app.unique,
        );
        render_status_panel(f, right[0], app);
        render_gateway_panel(f, right[1], app);
        f.render_widget(footer(app), outer[2]);
        return;
    }

    let left = Layout::default()
        .direction(Direction::Vertical)
        // The Egress Requests panel (ADR-2021) sits above Egress; a fixed small
        // height keeps the flow panels legible when no request is pending.
        .constraints([
            Constraint::Length(6),
            Constraint::Min(3),
            Constraint::Min(3),
        ])
        .split(body[0]);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(6), Constraint::Min(1)])
        .split(body[1]);

    render_requests_panel(f, left[0], app);
    render_flow_panel(
        f,
        left[1],
        "Egress",
        &mut app.egress,
        app.focus == Focus::Egress,
        app.unique,
    );
    render_flow_panel(
        f,
        left[2],
        "DNS",
        &mut app.dns,
        app.focus == Focus::Dns,
        app.unique,
    );
    render_status_panel(f, right[0], app);
    render_policy_panel(f, right[1], app);

    f.render_widget(footer(app), outer[2]);
}

/// The allow popup, centered over the panels (see [`AllowPopup`]).
fn render_allow_popup(f: &mut Frame, popup: &AllowPopup) {
    let chosen = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD | Modifier::REVERSED);
    let hint = Style::default().fg(Color::DarkGray);

    let mut options = Vec::new();
    for choice in ALLOW_CHOICES {
        if !options.is_empty() {
            options.push(Span::styled(" | ", hint));
        }
        let selected = choice == popup.choice;
        let cursor = if selected { "▏" } else { "" };
        let label = match choice {
            AllowChoice::Narrow => match popup.narrow {
                AllowTarget::Flow { .. } => "This IP:port only".to_string(),
                _ => "Resolve only".to_string(),
            },
            AllowChoice::Https => "HTTPS".to_string(),
            AllowChoice::HttpHttps => "HTTP+HTTPS".to_string(),
            AllowChoice::AllPorts => "all ports".to_string(),
            AllowChoice::Tcp => format!("TCP [{}{cursor}]", popup.tcp_ports),
            AllowChoice::Udp => format!("UDP [{}{cursor}]", popup.udp_ports),
        };
        options.push(if selected {
            Span::styled(format!(" {label} "), chosen)
        } else {
            Span::raw(format!(" {label} "))
        });
    }
    let options = Line::from(options);

    let bottom = match &popup.error {
        Some(e) => Line::from(Span::styled(
            format!(" {e}"),
            Style::default().fg(Color::Red),
        )),
        None if matches!(popup.choice, AllowChoice::Tcp | AllowChoice::Udp) => {
            Line::from(Span::styled(
                " type ports, e.g. 443,8000-8100 · ←/→ choose · Esc cancel",
                hint,
            ))
        }
        None => Line::from(Span::styled(
            " ←/→ choose · Enter confirm · Esc cancel",
            hint,
        )),
    };

    let what = match (&popup.narrow, &popup.request) {
        (AllowTarget::Flow { ip, port, proto }, _) => {
            format!("{proto} {ip}:{port} via {}", name_tail(&popup.name))
        }
        _ => name_tail(&popup.name),
    };
    let mut title = vec![Span::raw(format!(" allow {what} "))];
    if let Some(req) = &popup.request {
        title.push(popup_countdown(req));
    }
    render_popup(f, Line::from(title), options, true, bottom);
}

/// A popup title's countdown of the request being decided.
fn popup_countdown(req: &PendingRequest) -> Span<'static> {
    let remaining = req
        .expires_ts
        .saturating_sub(sodabox_common::event::now_ts());
    Span::styled(
        format!("{remaining}s "),
        Style::default().fg(ttl_color(remaining)),
    )
}

/// The frame of a popup, centered over the panels: `title` on the border, `body`
/// wrapped inside, then a `[confirm]` marker if it has one, then the `bottom` hint.
fn render_popup(f: &mut Frame, title: Line, body: Line, confirm: bool, bottom: Line) {
    let area = f.area();
    let width = area.width.min(POPUP_WIDTH);
    let inner_width = width.saturating_sub(2).max(1);
    let option_rows = (body.width() as u16).div_ceil(inner_width) + 1;
    let height = area.height.min(option_rows + 4);
    let rect = Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    };
    let block = Block::bordered()
        .border_style(Style::default().fg(Color::Yellow))
        .title(title);

    let inner = block.inner(rect);
    f.render_widget(Clear, rect);
    f.render_widget(block, rect);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(inner);
    f.render_widget(Paragraph::new(body).wrap(Wrap { trim: true }), rows[0]);
    if confirm {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "[confirm] ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )))
            .alignment(ratatui::layout::Alignment::Right),
            rows[1],
        );
    }
    f.render_widget(Paragraph::new(bottom), rows[2]);
}

/// The block popup (see [`BlockPopup`]).
fn render_block_popup(f: &mut Frame, popup: &BlockPopup) {
    let chosen = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD | Modifier::REVERSED);
    let hint = Style::default().fg(Color::DarkGray);
    let req = &popup.request;
    let port = req.port.unwrap_or_default();

    let mut options = Vec::new();
    for choice in BLOCK_CHOICES {
        if !options.is_empty() {
            options.push(Span::styled(" | ", hint));
        }
        let label = match choice {
            BlockChoice::Address => "This IP:port only".to_string(),
            BlockChoice::NamePort => format!("This name on {} {port}", req.proto),
            BlockChoice::Name => "All of this name".to_string(),
        };
        options.push(if choice == popup.choice {
            Span::styled(format!(" {label} "), chosen)
        } else {
            Span::raw(format!(" {label} "))
        });
    }

    let title = Line::from(vec![
        Span::raw(format!(
            " block {} {}:{port} via {} ",
            req.proto,
            req.destination,
            name_tail(&popup.name)
        )),
        popup_countdown(req),
    ]);
    let bottom = Line::from(Span::styled(
        " ←/→ choose · Enter confirm · Esc cancel",
        hint,
    ));
    render_popup(f, title, Line::from(options), true, bottom);
}

/// The question whether the blocklist entries a new allow rule overrides should go.
fn render_unblock_confirm(f: &mut Frame, entries: &[BlocklistEntry]) {
    let hint = Style::default().fg(Color::DarkGray);
    let listed: Vec<String> = entries.iter().map(fmt_block).collect();
    let bottom = Line::from(Span::styled(" y remove · n keep", hint));
    render_popup(
        f,
        Line::from(" this rule overrides blocklist entries: remove them? "),
        Line::from(listed.join(" · ")),
        false,
        bottom,
    );
}

fn header(app: &App) -> Paragraph<'static> {
    let state_color = match app.state.as_str() {
        "running" => Color::Green,
        "stopped" => Color::Red,
        _ => Color::Yellow,
    };
    let tab = |n: &str, name: &str, on: bool| {
        let style = if on {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD | Modifier::REVERSED)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        Span::styled(format!(" {n} {name} "), style)
    };
    let mut spans = vec![
        Span::styled(
            format!(" sodabox {} ", app.vm),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        tab("1", "Network", app.tab == Tab::Network),
        tab("2", "Inference", app.tab == Tab::Inference),
        Span::raw(" ["),
        Span::styled(app.state.clone(), Style::default().fg(state_color)),
        Span::raw(format!(
            "  egress {}  dns {}  inference {}",
            app.egress.tail.len(),
            app.dns.tail.len(),
            app.inference.tail.len()
        )),
        Span::raw(format!("  requests {}", app.requests.len())),
        Span::raw(format!("  notify {}", app.notify.as_str())),
    ];
    if app.dropped > 0 {
        spans.push(Span::styled(
            format!("  dropped {}", app.dropped),
            Style::default().fg(Color::Red),
        ));
    }
    spans.push(Span::raw("]"));
    Paragraph::new(Line::from(spans))
}

/// The Egress Requests panel (ADR-0021): one row per parked request with its
/// destination and a countdown of the remaining TTL, colored white → yellow →
/// orange → red → dark red → purple as the 30 s run out. `a`/Enter approves
/// the highlighted request, `d` denies it.
fn render_requests_panel(f: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Requests;
    let len = app.requests.len();
    let sel_index = app.request_sel_index();
    let mut title = " Egress Requests".to_string();
    if let Some(sel) = sel_index {
        title.push_str(&format!(" {}/{len}", sel + 1));
    }
    title.push_str(if focused { " ◂ " } else { " " });
    let border = if focused {
        Color::Yellow
    } else {
        Color::DarkGray
    };
    let block = Block::bordered()
        .border_style(Style::default().fg(border))
        .title(title);
    let inner = block.inner(area);
    f.render_widget(block, area);

    if app.requests.is_empty() {
        let line = Line::from(Span::styled(
            " none held",
            Style::default().fg(Color::DarkGray),
        ));
        f.render_widget(Paragraph::new(line), inner);
        return;
    }

    let now = sodabox_common::event::now_ts();
    let height = inner.height as usize;
    // Show the window's end (newest last); with more requests than rows, the
    // cursor stays visible by scrolling from the selection.
    let start = match sel_index {
        Some(sel) if len > height => sel
            .saturating_sub(height.saturating_sub(1))
            .min(len - height),
        _ => len.saturating_sub(height),
    };
    let lines: Vec<Line> = app
        .requests
        .iter()
        .enumerate()
        .skip(start)
        .take(height)
        .map(|(i, req)| {
            let remaining = req.expires_ts.saturating_sub(now);
            let where_to = match req.port {
                Some(p) => format!("{}:{p}", req.destination),
                None => req.destination.clone(),
            };
            let countdown = Span::styled(
                format!("{remaining:>2}s"),
                Style::default().fg(ttl_color(remaining)),
            );
            let mut spans = vec![
                Span::raw(format!(" {:<3} ", req.proto)),
                Span::raw(where_to),
                Span::raw("  "),
            ];
            spans.push(countdown);
            // Last, so a narrow panel clips this rather than the countdown. Dim:
            // it's a hint about the guest's lookups, not a verified identity.
            let via = req.via.as_deref().map(name_tail);
            if let Some(origin) = origin_label(req.port, via.as_deref()) {
                spans.push(Span::styled(
                    format!("  {origin}"),
                    Style::default().fg(Color::DarkGray),
                ));
            }
            let line = Line::from(spans);
            if Some(i) == sel_index {
                Line::styled(
                    line.spans
                        .iter()
                        .map(|s| s.content.to_string())
                        .collect::<String>(),
                    Style::default().add_modifier(Modifier::REVERSED),
                )
            } else {
                line
            }
        })
        .collect();
    f.render_widget(Paragraph::new(lines), inner);
}

/// `name`, cut to [`MAX_VIA_CHARS`] from the front if longer. The end of a name is
/// the part that says who runs it: a guest could look up
/// `github.com.<padding>.evil.test` to get a reassuring start past the panel's edge.
fn name_tail(name: &str) -> String {
    let len = name.chars().count();
    if len <= MAX_VIA_CHARS {
        return name.to_string();
    }
    let tail: String = name.chars().skip(len - (MAX_VIA_CHARS - 1)).collect();
    format!("…{tail}")
}

/// The countdown's color ramp (ADR-0021): white → yellow → orange → red →
/// dark red → purple as the 30 s TTL runs down (purple = about to be deleted).
fn ttl_color(remaining: u64) -> Color {
    match remaining {
        20.. => Color::White,
        15..=19 => Color::Yellow,
        10..=14 => Color::Rgb(255, 140, 0),
        6..=9 => Color::Red,
        3..=5 => Color::Rgb(139, 0, 0),
        _ => Color::Magenta,
    }
}

/// Egress/DNS panel: a bordered box showing the window of the current view
/// (tail or unique) that keeps the cursor visible — the newest rows when nothing
/// is selected. When `focused`, the border brightens and the cursor row is
/// highlighted; the title carries the view and, while a row is held, its position.
fn render_flow_panel(
    f: &mut Frame,
    area: Rect,
    title: &str,
    panel: &mut FlowPanel,
    focused: bool,
    unique: bool,
) {
    let len = panel.len(unique);
    let mut title = format!(" {title}");
    if unique {
        title.push_str(" · unique");
    }
    if let Some(off) = panel.sel {
        title.push_str(&format!(" {}/{len}", len - off));
    }
    title.push_str(if focused { " ◂ " } else { " " });
    let border = if focused {
        Color::Yellow
    } else {
        Color::DarkGray
    };
    let block = Block::bordered()
        .border_style(Style::default().fg(border))
        .title(title);
    let inner_h = block.inner(area).height as usize;

    panel.scroll = scroll_window(panel.scroll, panel.sel, inner_h, len);
    let sel = panel.sel;

    // The window's rows, paired with their offset-from-newest (0 = newest).
    let mut visible: Vec<(usize, (&Event, Option<u64>))> = panel
        .rows(unique)
        .enumerate()
        .skip(panel.scroll)
        .take(inner_h)
        .collect();
    // Display oldest at the top, newest at the bottom.
    visible.reverse();
    let lines: Vec<Line> = visible
        .into_iter()
        .map(|(off, (ev, hits))| {
            let mut line = event_line(ev);
            if let Some(n) = hits {
                line.spans.push(Span::styled(
                    format!("  ×{n}"),
                    Style::default().fg(Color::DarkGray),
                ));
            }
            if focused && sel == Some(off) {
                line.style(Style::default().add_modifier(Modifier::REVERSED))
            } else {
                line
            }
        })
        .collect();
    f.render_widget(Paragraph::new(lines).block(block), area);
}

/// The Status panel's lines: VM state, configured CPU/RAM, and uptime.
fn status_lines(app: &App) -> Vec<Line<'static>> {
    let field = |k: &str| Span::styled(format!("{k:<8}"), Style::default().fg(Color::DarkGray));
    let state_color = match app.state.as_str() {
        "running" => Color::Green,
        "stopped" => Color::Red,
        _ => Color::Yellow,
    };
    let cpu = app
        .cpus
        .map(|c| format!("{c} vCPU"))
        .unwrap_or_else(|| "?".into());
    let mem = app.mem.clone().unwrap_or_else(|| "?".into());
    let uptime = app.uptime().map(fmt_uptime).unwrap_or_else(|| "?".into());
    vec![
        Line::from(vec![
            field("state"),
            Span::styled(app.state.clone(), Style::default().fg(state_color)),
        ]),
        Line::from(vec![field("cpu"), Span::raw(cpu)]),
        Line::from(vec![field("mem"), Span::raw(mem)]),
        Line::from(vec![field("uptime"), Span::raw(uptime)]),
    ]
}

/// The Status panel: the VM's state, configured CPU/RAM, and uptime beside
/// the sodabox logo, which sits at the panel's right edge. The logo's height
/// is constrained to the lines' — its placement rectangle is the panel's
/// inner height, whatever that is. Terminals that don't answer the
/// graphics-protocol probe get the fields alone.
fn render_status_panel(f: &mut Frame, area: Rect, app: &mut App) {
    let block = Block::bordered().title(" Status ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    // The logo only where the status lines still fit beside it.
    let cols = logo_cols(inner.height);
    let logo_area = (cols > 0 && inner.width >= cols + 1 + STATUS_TEXT_WIDTH).then_some(Rect {
        x: inner.x + inner.width - cols,
        y: inner.y,
        width: cols,
        height: inner.height,
    });
    app.logo_place = if app.graphics { logo_area } else { None };
    // The lines fill the left, one cell clear of the logo (or the whole panel).
    let text = match logo_area {
        Some(a) => Rect {
            width: inner.width - a.width - 1,
            ..inner
        },
        None => inner,
    };
    f.render_widget(Paragraph::new(status_lines(app)), text);
}

/// Policy panel: version header then one line per rule. When focused the border
/// brightens and the row at the cursor is highlighted; the list scrolls to keep
/// the selection visible and shows a position indicator when it overflows.
fn render_policy_panel(f: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Policy;
    let border = if focused {
        Color::Yellow
    } else {
        Color::DarkGray
    };
    let title = if focused { " Policy ◂ " } else { " Policy " };
    let block = Block::bordered()
        .border_style(Style::default().fg(border))
        .title(title);
    let inner_h = block.inner(area).height as usize;

    let mut lines: Vec<Line> = vec![Line::from(vec![
        Span::styled("version ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            app.policy.version.to_string(),
            Style::default().fg(Color::Cyan),
        ),
    ])];

    // Rows left below the version header; the window reserves one for the "…"
    // indicator when the lists don't fully fit, and keeps the selected row in view.
    let room = inner_h.saturating_sub(1).max(1);
    let dim = Style::default().fg(Color::DarkGray);
    let all = policy_lines(app.policy.rules.len(), app.policy.blocklist.len());
    let window = policy_window(&all, room, app.policy_sel);
    let mut shown = Vec::new();
    for &at in &window {
        lines.push(match &all[at] {
            PolicyLine::Header(title) => Line::from(Span::styled(
                *title,
                Style::default().add_modifier(Modifier::BOLD),
            )),
            PolicyLine::Note(note) => Line::from(Span::styled(*note, dim)),
            PolicyLine::Row(row) => {
                shown.push(*row);
                let text = match app.policy.row(*row) {
                    Some(PolicyRow::Rule(r)) => fmt_rule(r),
                    Some(PolicyRow::Blocked(e)) => fmt_block(e),
                    None => String::new(),
                };
                let mut line = Line::from(format!("  {text}"));
                if focused && app.policy_sel == Some(*row) {
                    line = line.style(Style::default().add_modifier(Modifier::REVERSED));
                }
                line
            }
        });
    }
    if window.len() < all.len() {
        if let (Some(first), Some(last)) = (shown.first(), shown.last()) {
            lines.push(Line::from(Span::styled(
                format!("… {}–{} of {}", first + 1, last + 1, app.policy.rows()),
                dim,
            )));
        }
    }
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn footer(app: &App) -> Paragraph<'static> {
    // The grant prompt takes over the footer while it's open.
    if let Some(p) = &app.prompt {
        return Paragraph::new(Line::from(vec![
            Span::styled(
                format!(" grant tokens to '{}': ", p.alias),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("{}▏", p.input), Style::default().fg(Color::Yellow)),
            Span::styled(
                "  e.g. 500k or 2M · Enter grant · Esc cancel ",
                Style::default().fg(Color::DarkGray),
            ),
        ]));
    }
    let mut spans = Vec::new();
    if let Some(n) = &app.notice {
        let color = if n.error { Color::Red } else { Color::Green };
        spans.push(Span::styled(
            format!(" {} ", n.text),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ));
    }
    // The action keys depend on the focused panel (Enter acts on it).
    let action = match app.focus {
        Focus::Egress | Focus::Dns => "a allow  ",
        Focus::Requests => "a approve  d deny  ",
        Focus::Policy => match app.selected_policy_row() {
            Some(PolicyRow::Blocked(_)) => "d unblock  ",
            _ => "d revoke  ",
        },
        Focus::Gateway => "g grant  m unlimited/limited  ",
        Focus::Inference => "",
    };
    let view = if app.unique { "u all" } else { "u unique" };
    spans.push(Span::styled(
        format!(" 1/2 tab  Tab panel  ↑/↓ select  {action}{view}  q quit "),
        Style::default().fg(Color::DarkGray),
    ));
    Paragraph::new(Line::from(spans))
}

/// Gateway panel: whether the gateway is on and reachable, then one row per
/// alias with its upstream and balance (`∞` while unlimited, red once used
/// up). When focused, the cursor row is highlighted.
fn render_gateway_panel(f: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Gateway;
    let border = if focused {
        Color::Yellow
    } else {
        Color::DarkGray
    };
    let title = if focused {
        " Gateway ◂ "
    } else {
        " Gateway "
    };
    let block = Block::bordered()
        .border_style(Style::default().fg(border))
        .title(title);
    let dim = Style::default().fg(Color::DarkGray);

    if !app.policy.gateway_used() {
        let lines = vec![
            Line::from(Span::styled("not used by this VM", dim)),
            Line::from(Span::styled(
                format!("soda gateway enable --vm {}", app.vm),
                dim,
            )),
        ];
        f.render_widget(Paragraph::new(lines).block(block), area);
        return;
    }

    let on = app.policy.gateway.as_ref().is_some_and(|g| g.enabled);
    let access = app.policy.rules.iter().any(|r| {
        matches!(r, Rule::Service { name } if name == sodabox_common::policy::INFERENCE_SERVICE)
    });
    let flag = |ok: bool, yes: &str, no: &str| {
        let (text, color) = if ok {
            (yes, Color::Green)
        } else {
            (no, Color::Red)
        };
        Span::styled(text.to_string(), Style::default().fg(color))
    };
    let mut lines = vec![Line::from(vec![
        flag(on, "on", "off"),
        Span::styled(" · access ", dim),
        flag(access, "granted", "not granted"),
    ])];
    // The alias column is as wide as the longest alias, so the upstream
    // still fits in a narrow panel.
    let w = app
        .policy
        .models
        .iter()
        .map(|m| m.alias.chars().count())
        .max()
        .unwrap_or(0)
        .clamp(5, 24);
    lines.push(Line::from(Span::styled(
        format!("{:<w$} {:>9} {:>9}  upstream", "alias", "balance", "used"),
        dim,
    )));
    for (idx, m) in app.policy.models.iter().enumerate() {
        let used = app.quota.get(&m.alias).map_or(0, |b| b.used + b.unmetered);
        let balance = app.balance_label(m);
        let empty = app.policy.is_metered(&m.alias) && balance.parse::<i64>().is_ok_and(|b| b <= 0);
        let mut line = Line::from(vec![
            Span::raw(format!("{:<w$} ", m.alias)),
            Span::styled(
                format!("{balance:>9}"),
                Style::default().fg(if empty { Color::Red } else { Color::Cyan }),
            ),
            Span::raw(format!(" {used:>9}  ")),
            Span::styled(format!("{}/{}", m.provider, m.model), dim),
        ]);
        if focused && app.gateway_sel == Some(idx) {
            line = line.style(Style::default().add_modifier(Modifier::REVERSED));
        }
        lines.push(line);
    }
    if app.policy.models.is_empty() {
        lines.push(Line::from(Span::styled(
            "(no aliases: soda model add)",
            dim,
        )));
    }
    f.render_widget(Paragraph::new(lines).block(block), area);
}

/// Render one flow event as a colored line (egress or DNS).
fn event_line(ev: &Event) -> Line<'static> {
    match ev {
        Event::Egress {
            ts,
            verdict,
            proto,
            daddr,
            dport,
            rule,
            reason,
        } => {
            let (tag, color) = match verdict {
                Verdict::Allowed => ("ALLOW", Color::Green),
                Verdict::Blocked => ("BLOCK", Color::Red),
            };
            let mut spans = vec![ts_span(*ts), tag_span(tag, color)];
            spans.extend(reason_span(*reason));
            spans.push(Span::raw(format!("{proto} {daddr}:{dport}")));
            if let Some(r) = rule {
                spans.push(Span::styled(
                    format!("  ({r})"),
                    Style::default().fg(Color::DarkGray),
                ));
            }
            Line::from(spans)
        }
        Event::Dns {
            ts,
            verdict,
            qname,
            answers,
            ttl,
            reason,
        } => {
            let (tag, color) = match verdict {
                DnsVerdict::Allowed => ("OK", Color::Green),
                DnsVerdict::Refused => ("REFUSED", Color::Red),
            };
            let detail = if answers.is_empty() {
                qname.clone()
            } else {
                format!("{qname} -> {} (ttl {ttl})", answers.join(","))
            };
            let mut spans = vec![ts_span(*ts), tag_span(tag, color)];
            spans.extend(reason_span(*reason));
            spans.push(Span::raw(detail));
            Line::from(spans)
        }
        Event::Inference { ts, verdict, .. } => {
            let color = match verdict {
                Verdict::Allowed => Color::Green,
                Verdict::Blocked => Color::Red,
            };
            Line::from(vec![
                ts_span(*ts),
                tag_span("INFER", color),
                Span::raw(crate::logs::inference_detail(ev).unwrap_or_default()),
            ])
        }
        Event::QuotaExhausted { ts, alias } => Line::from(vec![
            ts_span(*ts),
            tag_span("QUOTA", Color::Red),
            Span::raw(format!("{alias}: token quota used up")),
        ]),
        // Not routed to a flow panel, but render defensively.
        Event::Policy { ts, version } => Line::from(vec![
            ts_span(*ts),
            tag_span("POLICY", Color::Cyan),
            Span::raw(format!("v{version}")),
        ]),
        // Not routed to a flow panel (the Egress Requests panel owns them,
        // ADR-0021), but render defensively.
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
            let origin = origin_label(*port, via.as_deref())
                .map(|o| format!(" {o}"))
                .unwrap_or_default();
            Line::from(vec![
                ts_span(*ts),
                tag_span("REQ", Color::Yellow),
                Span::raw(format!(
                    "hold {proto} {where_to}{origin} (expires {expires_ts})"
                )),
            ])
        }
        Event::RequestResolved { ts, id, verdict } => Line::from(vec![
            ts_span(*ts),
            tag_span("REQ-DONE", Color::Yellow),
            Span::raw(format!("request #{id} {verdict}")),
        ]),
        Event::Lifecycle { ts, state } => Line::from(vec![
            ts_span(*ts),
            tag_span("LIFECYCLE", Color::Yellow),
            Span::raw(state.clone()),
        ]),
        Event::Dropped { ts, count } => Line::from(vec![
            ts_span(*ts),
            tag_span("DROPPED", Color::Red),
            Span::raw(format!("{count} events")),
        ]),
    }
}

/// A single policy rule as a concise one-liner for the panel.
fn fmt_rule(r: &Rule) -> String {
    match r {
        Rule::Ip { cidr, ports, proto } => {
            let mut s = format!("ip {cidr}");
            if let Some(p) = ports {
                s.push_str(&format!(":{p}"));
            }
            if let Some(pr) = proto {
                s.push_str(&format!("/{pr}"));
            }
            s
        }
        Rule::Domain {
            name,
            scope,
            ports,
            proto,
        } => {
            let mut s = format!("domain {name} ({})", scope_str(*scope));
            if let Some(p) = ports {
                s.push_str(&format!(" :{p}"));
            }
            if let Some(pr) = proto {
                s.push_str(&format!("/{pr}"));
            }
            s
        }
        Rule::Resolve { name, scope } => format!("resolve {name} ({})", scope_str(*scope)),
        Rule::Service { name } => format!("service {name}"),
    }
}

fn scope_str(s: DomainScope) -> &'static str {
    match s {
        DomainScope::Subdomains => "subdomains",
        DomainScope::Exact => "exact",
        DomainScope::Wildcard => "wildcard",
    }
}

/// `HH:MM:SS`, or `Nd HH:MM:SS` past a day — an uptime display.
fn fmt_uptime(d: Duration) -> String {
    let secs = d.as_secs();
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    if days > 0 {
        format!("{days}d {h:02}:{m:02}:{s:02}")
    } else {
        format!("{h:02}:{m:02}:{s:02}")
    }
}

/// `HH:MM:SS` (UTC) time-of-day from Unix seconds — no chrono dep for a monitor
/// timestamp.
fn ts_span(ts: u64) -> Span<'static> {
    let s = ts % 86_400;
    Span::styled(
        format!("{:02}:{:02}:{:02} ", s / 3600, (s % 3600) / 60, s % 60),
        Style::default().fg(Color::DarkGray),
    )
}

/// Why a row was refused, right after its tag: a long name gets cut off at the
/// panel's edge, and must not take the reason with it.
fn reason_span(reason: Option<RefusalReason>) -> Option<Span<'static>> {
    reason.map(|r| Span::styled(format!("{} ", r.label()), Style::default().fg(Color::Red)))
}

fn tag_span(tag: &str, color: Color) -> Span<'static> {
    Span::styled(
        format!(" {tag:<8} "),
        Style::default().fg(color).add_modifier(Modifier::BOLD),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn egress(ts: u64) -> Event {
        Event::Egress {
            ts,
            verdict: Verdict::Blocked,
            proto: "tcp".into(),
            daddr: "203.0.113.1".into(),
            dport: 443,
            rule: None,
            reason: None,
        }
    }

    /// What allowing a blocked row for 203.0.113.1:443 adds: that flow only.
    fn blocked_target() -> AllowTarget {
        AllowTarget::Flow {
            ip: "203.0.113.1".into(),
            port: 443,
            proto: "tcp".into(),
        }
    }

    fn dns(ts: u64) -> Event {
        Event::Dns {
            ts,
            verdict: DnsVerdict::Allowed,
            qname: "example.com".into(),
            answers: vec!["93.184.216.34".into()],
            ttl: 300,
            reason: None,
        }
    }

    fn request_pending(ts: u64, id: u64, proto: &str) -> Event {
        Event::RequestPending {
            ts,
            id,
            proto: proto.into(),
            destination: if proto == "dns" {
                "maybe.test".into()
            } else {
                "203.0.113.5".into()
            },
            port: if proto == "dns" { None } else { Some(443) },
            via: None,
            expires_ts: ts + 30,
        }
    }

    #[test]
    fn pending_requests_join_the_panel_and_queue_a_notification() {
        let mut a = app();
        a.ingest(request_pending(0, 1, "tcp"));
        a.ingest(request_pending(0, 2, "dns"));
        // A duplicate (e.g. a replayed event) must not double the row.
        a.ingest(request_pending(0, 1, "tcp"));
        assert_eq!(a.requests.len(), 2);
        // Static text only: the destination is guest-controlled.
        assert_eq!(
            a.notify_msg.as_deref(),
            Some("demo has new egress requests")
        );

        // Resolution removes the row and keeps the cursor on its request.
        a.request_sel = Some(2);
        a.ingest(Event::RequestResolved {
            ts: 1,
            id: 1,
            verdict: "approved".into(),
        });
        assert_eq!(a.requests.len(), 1);
        assert_eq!(a.request_sel, Some(2));
        a.ingest(Event::RequestResolved {
            ts: 2,
            id: 2,
            verdict: "expired".into(),
        });
        assert!(a.requests.is_empty());
        assert_eq!(a.request_sel, None);
    }

    #[test]
    fn request_approve_and_deny_key_queue_the_action() {
        let mut a = app();
        a.ingest(request_pending(0, 1, "tcp"));
        a.ingest(request_pending(0, 2, "dns"));
        a.focus = Focus::Requests;

        // No selection yet: the first `j` lands on the newest request.
        press(&mut a, KeyCode::Char('j'));
        assert_eq!(a.request_sel, Some(2));
        press(&mut a, KeyCode::Char('k'));
        assert_eq!(a.request_sel, Some(1));

        // An address with no recent lookup has no name to ask about.
        press(&mut a, KeyCode::Enter);
        assert!(a.allow_popup.is_none());
        assert_eq!(a.pending_resolve.as_ref().map(|(r, _)| r.id), Some(1));
        a.pending_resolve = None;

        // Denying a dns row records its exact name, with nothing to ask.
        press(&mut a, KeyCode::Char('j'));
        press(&mut a, KeyCode::Char('d'));
        assert!(a.allow_popup.is_none() && a.block_popup.is_none());
        assert!(a.pending_resolve.is_none());
        assert!(matches!(
            a.pending_block,
            Some(BlocklistEntry::Domain {
                scope: DomainScope::Exact,
                ports: None,
                proto: None,
                ..
            })
        ));
    }

    #[test]
    fn denying_an_address_with_no_name_records_exactly_what_the_row_shows() {
        let mut a = app_with_address_row("203.0.113.5", 22, "tcp", None);
        press(&mut a, KeyCode::Char('d'));
        assert!(a.block_popup.is_none());
        assert_eq!(
            a.pending_block.take(),
            Some(BlocklistEntry::Ip {
                cidr: "203.0.113.5".into(),
                ports: Some("22".into()),
                proto: Some("tcp".into()),
            })
        );
    }

    /// A non-public address can't be judged through a name, as when approving.
    #[test]
    fn denying_a_non_public_address_records_the_address() {
        let mut a = app_with_address_row("192.168.1.1", 443, "tcp", Some("example.com"));
        press(&mut a, KeyCode::Char('d'));
        assert!(a.block_popup.is_none());
        assert!(matches!(a.pending_block, Some(BlocklistEntry::Ip { .. })));
    }

    #[test]
    fn denying_an_address_with_a_name_asks_and_prefers_the_name_on_that_port() {
        let mut a = app_with_address_row("203.0.113.5", 443, "udp", Some("example.com"));
        press(&mut a, KeyCode::Char('d'));
        assert!(a.pending_block.is_none());
        assert_eq!(
            a.block_popup.as_ref().unwrap().choice,
            BlockChoice::NamePort
        );

        // Keys go to the popup, and Esc leaves the row undecided.
        press(&mut a, KeyCode::Esc);
        assert!(a.block_popup.is_none() && a.pending_block.is_none() && !a.should_quit);

        press(&mut a, KeyCode::Char('d'));
        press(&mut a, KeyCode::Enter);
        assert_eq!(
            a.pending_block.take(),
            Some(BlocklistEntry::Domain {
                name: "example.com".into(),
                scope: DomainScope::Exact,
                ports: Some("443".into()),
                proto: Some("udp".into()),
            })
        );

        press(&mut a, KeyCode::Char('d'));
        press(&mut a, KeyCode::Right);
        press(&mut a, KeyCode::Enter);
        assert_eq!(
            a.pending_block.take(),
            Some(BlocklistEntry::Domain {
                name: "example.com".into(),
                scope: DomainScope::Exact,
                ports: None,
                proto: None,
            })
        );

        press(&mut a, KeyCode::Char('d'));
        press(&mut a, KeyCode::Left);
        press(&mut a, KeyCode::Enter);
        assert_eq!(
            a.pending_block.take(),
            Some(BlocklistEntry::Ip {
                cidr: "203.0.113.5".into(),
                ports: Some("443".into()),
                proto: Some("udp".into()),
            })
        );
    }

    #[test]
    fn the_block_popup_renders_over_the_panels() {
        let mut a = app_with_address_row("203.0.113.5", 443, "udp", Some("example.com"));
        press(&mut a, KeyCode::Char('d'));
        let mut term = ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 24)).unwrap();
        term.draw(|f| draw(f, &mut a)).unwrap();
        let text: String = term
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(text.contains("via example.com"), "{text}");
        assert!(text.contains("This name on udp 443"), "{text}");
    }

    fn blocked(name: &str) -> BlocklistEntry {
        BlocklistEntry::Domain {
            name: name.into(),
            scope: DomainScope::Exact,
            ports: None,
            proto: None,
        }
    }

    /// Allowing a blocked name asks, and nothing goes without a `y`.
    #[test]
    fn an_allow_that_overrides_an_entry_asks_before_removing_it() {
        let mut a = app();
        a.policy.blocklist = vec![blocked("example.com"), blocked("other.test")];
        let target = domain_target("example.com", &[(Some("443"), None)]);

        a.offer_unblock(&target);
        assert_eq!(a.unblock_confirm, Some(vec![blocked("example.com")]));

        // Enter just confirmed the allow; it is no answer to this.
        press(&mut a, KeyCode::Enter);
        press(&mut a, KeyCode::Char('q'));
        assert!(a.unblock_confirm.is_some() && !a.should_quit);
        assert!(a.pending_unblock.is_none());

        press(&mut a, KeyCode::Char('n'));
        assert!(a.unblock_confirm.is_none() && a.pending_unblock.is_none());

        a.offer_unblock(&target);
        press(&mut a, KeyCode::Char('y'));
        assert!(a.unblock_confirm.is_none());
        assert_eq!(a.pending_unblock, Some(vec![blocked("example.com")]));
    }

    #[test]
    fn an_allow_that_overrides_nothing_does_not_ask() {
        let mut a = app();
        a.policy.blocklist = vec![BlocklistEntry::Domain {
            name: "example.com".into(),
            scope: DomainScope::Exact,
            ports: Some("443".into()),
            proto: Some("udp".into()),
        }];
        a.offer_unblock(&domain_target("example.com", &[(Some("443"), Some("tcp"))]));
        assert!(a.unblock_confirm.is_none());
    }

    #[test]
    fn the_policy_cursor_runs_through_both_lists_and_removes_by_kind() {
        let mut a = app_with_rules(vec![ip_rule("203.0.113.0/24")]);
        a.policy.blocklist = vec![blocked("a.test"), blocked("b.test")];
        a.focus = Focus::Policy;

        // Nothing selected yet: declined with a notice.
        press(&mut a, KeyCode::Char('d'));
        assert!(a.pending_revoke.is_none() && a.pending_unblock.is_none());
        assert!(a.notice.is_some());

        press(&mut a, KeyCode::Char('j'));
        press(&mut a, KeyCode::Char('d'));
        assert_eq!(a.pending_revoke.take().as_deref(), Some("203.0.113.0/24"));
        assert!(a.pending_unblock.is_none());

        // Only the entry under the cursor goes.
        press(&mut a, KeyCode::Char('j'));
        press(&mut a, KeyCode::Char('j'));
        press(&mut a, KeyCode::Char('d'));
        assert_eq!(a.pending_unblock.take(), Some(vec![blocked("b.test")]));
        assert!(a.pending_revoke.is_none());

        // The cursor stops at the end of the blocklist, and follows it shrinking.
        press(&mut a, KeyCode::Char('j'));
        assert_eq!(a.policy_sel, Some(2));
        a.policy.blocklist.pop();
        a.clamp_policy_sel();
        assert_eq!(a.policy_sel, Some(1));
    }

    fn rendered_policy(a: &mut App, height: u16) -> String {
        let mut term =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(60, height)).unwrap();
        term.draw(|f| render_policy_panel(f, f.area(), a)).unwrap();
        let buf = term.backend().buffer().clone();
        buf.content
            .chunks(60)
            .map(|row| row.iter().map(|c| c.symbol()).collect::<String>() + "\n")
            .collect()
    }

    /// An empty allowlist must not hide the blocklist.
    #[test]
    fn the_policy_panel_shows_both_sections_even_with_no_rules() {
        let mut a = app();
        a.policy.blocklist = vec![blocked("a.test")];
        let text = rendered_policy(&mut a, 10);
        assert!(
            text.contains("Allowlist") && text.contains("(deny-all)"),
            "{text}"
        );
        assert!(
            text.contains("Blocklist") && text.contains("a.test"),
            "{text}"
        );
    }

    /// Scrolled past its title, a row still says which list it is on.
    #[test]
    fn a_short_policy_panel_keeps_the_selection_and_its_section_in_view() {
        let rules = (1..=6).map(|n| ip_rule(&format!("10.0.0.{n}"))).collect();
        let mut a = app_with_rules(rules);
        a.policy.blocklist = (1..=6).map(|n| blocked(&format!("b{n}.test"))).collect();
        a.focus = Focus::Policy;

        // Last of the blocklist.
        a.policy_sel = Some(11);
        let text = rendered_policy(&mut a, 7);
        assert!(text.contains("b6.test"), "{text}");
        assert!(
            text.contains("Blocklist") && !text.contains("Allowlist"),
            "{text}"
        );
        assert!(text.contains("of 12"), "{text}");

        // Last of the allowlist.
        a.policy_sel = Some(5);
        let text = rendered_policy(&mut a, 7);
        assert!(text.contains("10.0.0.6"), "{text}");
        assert!(text.contains("Allowlist"), "{text}");

        // Every position stays visible, down to one row besides the version.
        for height in 4..12 {
            for sel in 0..12 {
                a.policy_sel = Some(sel);
                let text = rendered_policy(&mut a, height);
                let want = match sel {
                    0..=5 => format!("10.0.0.{}", sel + 1),
                    _ => format!("b{}.test", sel - 5),
                };
                assert!(text.contains(&want), "height {height} sel {sel}: {text}");
            }
        }
    }

    #[test]
    fn the_footer_names_what_d_does_on_the_selected_row() {
        let footer_text = |a: &App| -> String {
            let mut term =
                ratatui::Terminal::new(ratatui::backend::TestBackend::new(100, 1)).unwrap();
            term.draw(|f| f.render_widget(footer(a), f.area())).unwrap();
            term.backend()
                .buffer()
                .content
                .iter()
                .map(|c| c.symbol())
                .collect()
        };
        let mut a = app_with_rules(vec![ip_rule("10.0.0.1")]);
        a.policy.blocklist = vec![blocked("a.test")];
        a.focus = Focus::Policy;
        a.policy_sel = Some(0);
        assert!(footer_text(&a).contains("d revoke"));
        a.policy_sel = Some(1);
        assert!(footer_text(&a).contains("d unblock"));
    }

    /// The Requests panel with one held address row selected.
    fn app_with_address_row(destination: &str, port: u16, proto: &str, via: Option<&str>) -> App {
        let mut a = app();
        a.ingest(Event::RequestPending {
            ts: 0,
            id: 1,
            proto: proto.into(),
            destination: destination.into(),
            port: Some(port),
            via: via.map(Into::into),
            expires_ts: 30,
        });
        a.focus = Focus::Requests;
        a.request_sel = Some(1);
        a
    }

    fn domain_target(name: &str, grants: &[(Option<&str>, Option<&str>)]) -> AllowTarget {
        AllowTarget::Domain {
            name: name.into(),
            grants: grants.iter().map(|(p, t)| Grant::new(*p, *t)).collect(),
        }
    }

    /// `a` then Enter is the common case: a dns row opens with HTTPS picked, TCP
    /// and UDP on 443 alike, and queues it against the held request.
    #[test]
    fn approving_a_dns_row_asks_with_https_preselected() {
        let mut a = app();
        a.ingest(request_pending(0, 7, "dns"));
        a.focus = Focus::Requests;
        a.request_sel = Some(7);

        press(&mut a, KeyCode::Char('a'));
        assert_eq!(a.allow_popup.as_ref().unwrap().choice, AllowChoice::Https);
        assert!(a.pending_resolve.is_none());
        press(&mut a, KeyCode::Enter);
        assert!(a.allow_popup.is_none());
        let (req, target) = a.pending_resolve.take().unwrap();
        assert_eq!(req.id, 7);
        assert_eq!(target, domain_target("maybe.test", &[(Some("443"), None)]));
    }

    #[test]
    fn each_choice_grants_what_it_says() {
        let popup = |choice| AllowPopup {
            choice,
            ..AllowPopup::new(
                None,
                "maybe.test".into(),
                AllowTarget::Resolve("maybe.test".into()),
            )
        };
        assert_eq!(
            popup(AllowChoice::Narrow).target(),
            Ok(AllowTarget::Resolve("maybe.test".into()))
        );
        assert_eq!(
            popup(AllowChoice::HttpHttps).target(),
            Ok(domain_target(
                "maybe.test",
                &[(Some("80"), Some("tcp")), (Some("443"), None)]
            ))
        );
        assert_eq!(
            popup(AllowChoice::AllPorts).target(),
            Ok(domain_target("maybe.test", &[(None, None)]))
        );
    }

    /// An empty field would read as any port, so it and malformed lists are
    /// refused in place. The popup stays open and nothing is queued.
    #[test]
    fn port_fields_take_only_a_valid_list() {
        let mut a = app();
        a.ingest(request_pending(0, 7, "dns"));
        a.focus = Focus::Requests;
        a.request_sel = Some(7);
        press(&mut a, KeyCode::Enter);
        // HTTPS → HTTP+HTTPS → all ports → TCP.
        for _ in 0..3 {
            press(&mut a, KeyCode::Right);
        }
        assert_eq!(a.allow_popup.as_ref().unwrap().choice, AllowChoice::Tcp);

        press(&mut a, KeyCode::Enter);
        assert!(a.allow_popup.as_ref().unwrap().error.is_some());
        assert!(a.pending_resolve.is_none());

        for c in ['8', ',', ',', 'x', 'q'] {
            press(&mut a, KeyCode::Char(c));
        }
        assert_eq!(a.allow_popup.as_ref().unwrap().tcp_ports, "8,,");
        press(&mut a, KeyCode::Enter);
        assert!(a.allow_popup.as_ref().unwrap().error.is_some());
        assert!(a.pending_resolve.is_none());

        press(&mut a, KeyCode::Backspace);
        press(&mut a, KeyCode::Backspace);
        for c in ",9-10".chars() {
            press(&mut a, KeyCode::Char(c));
        }
        press(&mut a, KeyCode::Enter);
        assert_eq!(
            a.pending_resolve.take().unwrap().1,
            domain_target("maybe.test", &[(Some("8,9-10"), Some("tcp"))])
        );
    }

    /// Keys stay in the popup: Esc closes it rather than the TUI, arrows don't
    /// switch tabs, and nothing is queued on the way out.
    #[test]
    fn the_popup_holds_the_keys_until_cancelled() {
        let mut a = app();
        a.ingest(request_pending(0, 7, "dns"));
        a.focus = Focus::Requests;
        a.request_sel = Some(7);
        press(&mut a, KeyCode::Enter);
        for code in [KeyCode::Right, KeyCode::Left, KeyCode::Char('q')] {
            press(&mut a, code);
        }
        assert!(a.allow_popup.is_some() && a.tab == Tab::Network && !a.should_quit);
        press(&mut a, KeyCode::Esc);
        assert!(a.allow_popup.is_none() && !a.should_quit);
        assert!(a.pending_resolve.is_none());
    }

    /// An address row's popup offers the row itself or its name, preselecting a
    /// choice that covers the row and is on the row's own port.
    #[test]
    fn an_address_row_preselects_a_choice_covering_it() {
        let opened = |port, proto| {
            let mut a = app_with_address_row("203.0.113.5", port, proto, Some("www.example.com"));
            press(&mut a, KeyCode::Char('a'));
            a.allow_popup.unwrap()
        };
        assert_eq!(opened(443, "tcp").choice, AllowChoice::Https);
        assert_eq!(opened(443, "udp").choice, AllowChoice::Https);
        assert_eq!(opened(80, "tcp").choice, AllowChoice::HttpHttps);
        assert_eq!(opened(80, "udp").choice, AllowChoice::Udp);
        let ssh = opened(22, "tcp");
        assert_eq!(
            (ssh.choice, ssh.tcp_ports.as_str()),
            (AllowChoice::Tcp, "22")
        );
        assert_eq!(
            ssh.target(),
            Ok(domain_target(
                "www.example.com",
                &[(Some("22"), Some("tcp"))]
            ))
        );

        let mut narrow = opened(22, "tcp");
        narrow.choice = AllowChoice::Narrow;
        assert_eq!(
            narrow.target(),
            Ok(AllowTarget::Flow {
                ip: "203.0.113.5".into(),
                port: 22,
                proto: "tcp".into(),
            })
        );
    }

    /// A rule on a name can't open a non-public address, so offering one would
    /// leave the row waiting. It approves directly, like a row with no name.
    #[test]
    fn a_non_public_address_row_approves_directly() {
        let mut a = app_with_address_row("192.168.1.1", 443, "tcp", Some("www.example.com"));
        press(&mut a, KeyCode::Char('a'));
        assert!(a.allow_popup.is_none());
        assert_eq!(
            a.pending_resolve.take().unwrap().1,
            AllowTarget::Flow {
                ip: "192.168.1.1".into(),
                port: 443,
                proto: "tcp".into(),
            }
        );
    }

    /// A refused row on the DNS panel has no held request: the choice goes
    /// straight to the policy.
    #[test]
    fn a_refused_dns_row_asks_too() {
        let mut a = app();
        a.ingest(Event::Dns {
            ts: 0,
            verdict: DnsVerdict::Refused,
            qname: "www.example.com.".into(),
            answers: Vec::new(),
            ttl: 0,
            reason: None,
        });
        a.focus = Focus::Dns;
        a.dns.sel = Some(0);
        press(&mut a, KeyCode::Char('a'));
        assert!(a.pending_allow.is_none());
        press(&mut a, KeyCode::Enter);
        assert_eq!(
            a.pending_allow.take(),
            Some(domain_target("www.example.com", &[(Some("443"), None)]))
        );
        assert!(a.pending_resolve.is_none());
    }

    /// The popup shows the labels and takes the logo down while open, since the
    /// logo is an image above the cells. Guest-chosen text in it gets scrubbed.
    #[test]
    fn the_popup_renders_over_the_panels_and_hides_the_logo() {
        let mut a = app();
        a.graphics = true;
        a.ingest(Event::RequestPending {
            ts: 0,
            id: 7,
            proto: "dns".into(),
            destination: "x\u{1b}]52;c;Zm9v\u{7}.evil.test".into(),
            port: None,
            via: None,
            expires_ts: 30,
        });
        a.focus = Focus::Requests;
        a.request_sel = Some(7);
        press(&mut a, KeyCode::Enter);

        let mut term = ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 24)).unwrap();
        term.draw(|f| draw(f, &mut a)).unwrap();
        assert_eq!(a.logo_place, None);
        let buf = term.backend().buffer();
        let text: String = buf.content.iter().map(|c| c.symbol()).collect();
        for label in [
            "Resolve only",
            "HTTPS",
            "HTTP+HTTPS",
            "all ports",
            "TCP [",
            "UDP [",
            "[confirm]",
        ] {
            assert!(text.contains(label), "{label} missing from {text:?}");
        }
        assert!(!text.contains(char::is_control));

        press(&mut a, KeyCode::Esc);
        term.draw(|f| draw(f, &mut a)).unwrap();
        assert!(a.logo_place.is_some());

        // A narrow terminal wraps the choices rather than losing them.
        press(&mut a, KeyCode::Enter);
        let mut narrow =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(40, 24)).unwrap();
        narrow.draw(|f| draw(f, &mut a)).unwrap();
        let text: String = narrow
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(
            text.contains("UDP [") && text.contains("[confirm]"),
            "{text:?}"
        );
    }

    #[test]
    fn approve_only_acts_on_the_highlighted_request() {
        let mut a = app();
        for id in 1..=3 {
            a.ingest(request_pending(0, id, "tcp"));
        }
        a.focus = Focus::Requests;
        a.request_sel = Some(2);

        // An older row expiring shifts the rows, not the selection.
        a.ingest(Event::RequestResolved {
            ts: 1,
            id: 1,
            verdict: "expired".into(),
        });
        press(&mut a, KeyCode::Char('a'));
        assert_eq!(a.pending_resolve.take().map(|(r, _)| r.id), Some(2));

        // Once the highlighted row is gone (a double Enter, or it expired),
        // approving does nothing rather than taking the next request.
        a.ingest(Event::RequestResolved {
            ts: 2,
            id: 2,
            verdict: "approved".into(),
        });
        press(&mut a, KeyCode::Enter);
        assert!(a.pending_resolve.is_none());
        assert_eq!(a.requests.len(), 1);
    }

    #[test]
    fn request_rows_say_where_their_address_came_from() {
        let pending =
            |id, destination: &str, port: Option<u16>, via: Option<&str>| Event::RequestPending {
                ts: 0,
                id,
                proto: if port.is_some() { "tcp" } else { "dns" }.into(),
                destination: destination.into(),
                port,
                via: via.map(str::to_string),
                expires_ts: u64::MAX,
            };
        let mut a = app();
        a.ingest(pending(1, "203.0.113.5", Some(443), Some("example.com")));
        a.ingest(pending(2, "198.51.100.7", Some(22), None));
        a.ingest(pending(3, "maybe.test", None, None));

        let text = screen(&mut a);
        let row = |needle: &str| {
            text.lines()
                .find(|l| l.contains(needle))
                .unwrap_or_else(|| panic!("no {needle} row in\n{text}"))
                .to_string()
        };
        assert!(row("203.0.113.5:443").contains("via example.com"), "{text}");
        assert!(
            row("198.51.100.7:22").contains("no recent lookup"),
            "{text}"
        );
        // A dns row is a name already.
        assert!(!row("dns maybe.test").contains("lookup"), "{text}");
    }

    #[test]
    fn long_names_keep_their_end_which_says_who_runs_them() {
        assert_eq!(name_tail("example.com"), "example.com");
        let spoof = format!("github.com.{}.evil.test", "a".repeat(60));
        let tail = name_tail(&spoof);
        assert_eq!(tail.chars().count(), MAX_VIA_CHARS);
        assert!(
            tail.starts_with('…') && tail.ends_with(".evil.test"),
            "{tail}"
        );
        assert!(!tail.contains("github.com"), "{tail}");
    }

    #[test]
    fn lost_events_flag_a_resync_that_reconciles_the_rows() {
        let mut a = app();
        a.ingest(request_pending(0, 1, "tcp"));
        a.ingest(request_pending(0, 2, "tcp"));
        a.request_sel = Some(2);
        a.notify_msg = None;
        assert!(!a.requests_dirty);

        a.ingest(Event::Dropped { ts: 1, count: 5 });
        assert!(a.requests_dirty);

        // Same rows but one: the phantom goes, the cursor stays, nothing notifies.
        let row = |id| PendingRequest {
            id,
            proto: "tcp".into(),
            destination: "203.0.113.5".into(),
            port: Some(443),
            via: None,
            expires_ts: 30,
        };
        a.sync_requests(vec![row(2)]);
        assert_eq!(a.requests.len(), 1);
        assert_eq!(a.request_sel, Some(2));
        assert!(a.notify_msg.is_none());

        // A request whose event was lost appears and notifies; the highlighted
        // one going away clears the cursor.
        a.sync_requests(vec![row(3)]);
        assert_eq!(a.requests, vec![row(3)]);
        assert_eq!(a.request_sel, None);
        assert_eq!(
            a.notify_msg.as_deref(),
            Some("demo has new egress requests")
        );
    }

    #[test]
    fn rows_past_their_expiry_are_removed() {
        let mut a = app();
        a.ingest(request_pending(0, 1, "tcp")); // expires at 30
        a.ingest(request_pending(10, 2, "tcp")); // expires at 40
        a.request_sel = Some(1);

        // At expiry the row stays: the supervisor's sweep gets to report it.
        a.prune_expired_requests(30);
        assert_eq!(a.requests.len(), 2);

        a.prune_expired_requests(31);
        assert_eq!(a.requests.len(), 1);
        assert_eq!(a.requests[0].id, 2);
        assert_eq!(a.request_sel, None);
    }

    #[test]
    fn approval_target_matches_the_request_row() {
        let tcp = PendingRequest {
            id: 1,
            proto: "tcp".into(),
            destination: "203.0.113.5".into(),
            port: Some(443),
            via: Some("example.com".into()),
            expires_ts: 30,
        };
        assert_eq!(
            request_allow_target(&tcp),
            AllowTarget::Flow {
                ip: "203.0.113.5".into(),
                port: 443,
                proto: "tcp".into(),
            }
        );
        let dns = PendingRequest {
            id: 2,
            proto: "dns".into(),
            destination: "maybe.test".into(),
            port: None,
            via: None,
            expires_ts: 30,
        };
        assert_eq!(
            request_allow_target(&dns),
            AllowTarget::Resolve("maybe.test".into())
        );
    }

    #[test]
    fn n_cycles_and_persists_the_notify_mode() {
        let dir = std::env::temp_dir().join(format!("sodabox-tui-notify-{}", std::process::id()));
        let mut a = app();
        a.notify_path = dir.join("tui.toml");
        assert_eq!(a.notify, NotifyMode::All);
        for m in [
            NotifyMode::Off,
            NotifyMode::Notification,
            NotifyMode::Bell,
            NotifyMode::All,
        ] {
            press(&mut a, KeyCode::Char('n'));
            assert_eq!(a.notify, m, "n must cycle the mode");
            assert_eq!(load_notify_from(&a.notify_path), m, "n must persist it");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ttl_countdown_follows_the_color_ramp() {
        assert_eq!(ttl_color(30), Color::White);
        assert_eq!(ttl_color(20), Color::White);
        assert_eq!(ttl_color(19), Color::Yellow);
        assert_eq!(ttl_color(15), Color::Yellow);
        assert_eq!(ttl_color(14), Color::Rgb(255, 140, 0));
        assert_eq!(ttl_color(10), Color::Rgb(255, 140, 0));
        assert_eq!(ttl_color(9), Color::Red);
        assert_eq!(ttl_color(6), Color::Red);
        assert_eq!(ttl_color(5), Color::Rgb(139, 0, 0));
        assert_eq!(ttl_color(3), Color::Rgb(139, 0, 0));
        assert_eq!(ttl_color(2), Color::Magenta);
        assert_eq!(ttl_color(0), Color::Magenta);
    }

    /// A notify file that doesn't exist, so a test `App` starts from the default
    /// mode and stays away from the real config dir.
    fn no_notify_file() -> PathBuf {
        std::env::temp_dir().join("sodabox-tui-test-absent/tui.toml")
    }

    fn app() -> App {
        App::new(
            "demo",
            None,
            None,
            PolicyView {
                version: 1,
                ..PolicyView::default()
            },
            "running".into(),
            no_notify_file(),
        )
    }

    #[test]
    fn bounded_evicts_oldest_and_signals_the_drop() {
        let mut b = Bounded::new(2);
        assert!(!b.push(egress(0)));
        assert!(!b.push(egress(1)));
        assert!(b.push(egress(2)), "3rd push at cap 2 must evict");
        assert_eq!(b.len(), 2);
        let kept: Vec<u64> = b
            .iter()
            .map(|e| match e {
                Event::Egress { ts, .. } => *ts,
                other => panic!("unexpected: {other:?}"),
            })
            .collect();
        assert_eq!(kept, vec![1, 2]);
    }

    #[test]
    fn ingest_routes_to_the_right_panel() {
        let mut a = app();
        a.ingest(egress(1));
        a.ingest(dns(2));
        a.ingest(egress(3));
        assert_eq!(a.egress.tail.len(), 2);
        assert_eq!(a.dns.tail.len(), 1);
    }

    #[test]
    fn ingest_sums_local_and_server_drops() {
        let mut a = app();
        a.egress.tail = Bounded::new(1);
        a.ingest(egress(0));
        a.ingest(egress(1)); // evicts one -> +1
        a.ingest(Event::Dropped { ts: 0, count: 9 }); // +9
        assert_eq!(a.dropped, 10);
    }

    #[test]
    fn ingest_tracks_policy_version_and_flags_refetch() {
        let mut a = app();
        assert!(!a.policy_dirty);
        a.ingest(Event::Policy { ts: 0, version: 5 });
        assert_eq!(a.policy.version, 5);
        assert!(a.policy_dirty, "a new version must flag a rules re-fetch");
        // A repeat of the same version is not a change.
        a.policy_dirty = false;
        a.ingest(Event::Policy { ts: 1, version: 5 });
        assert!(!a.policy_dirty);
    }

    #[test]
    fn ingest_tracks_lifecycle_state() {
        let mut a = app();
        a.ingest(Event::Lifecycle {
            ts: 0,
            state: "stopping".into(),
        });
        assert_eq!(a.state, "stopping");
    }

    #[test]
    fn fmt_rule_renders_ip_and_domain() {
        let ip = Rule::Ip {
            cidr: "10.0.0.0/8".into(),
            ports: Some("443".into()),
            proto: None,
        };
        assert_eq!(fmt_rule(&ip), "ip 10.0.0.0/8:443");
        let dom = Rule::Domain {
            name: "example.com".into(),
            scope: DomainScope::Wildcard,
            ports: None,
            proto: None,
        };
        assert_eq!(fmt_rule(&dom), "domain example.com (wildcard)");
    }

    #[test]
    fn fmt_uptime_crosses_day_boundary() {
        assert_eq!(fmt_uptime(Duration::from_secs(59)), "00:00:59");
        assert_eq!(fmt_uptime(Duration::from_secs(3661)), "01:01:01");
        assert_eq!(fmt_uptime(Duration::from_secs(90_061)), "1d 01:01:01");
    }

    #[test]
    fn event_line_tags_verdicts() {
        let text: String = event_line(&egress(0))
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect();
        assert!(text.contains("BLOCK"), "got {text:?}");

        let refused = event_line(&Event::Dns {
            ts: 0,
            verdict: DnsVerdict::Refused,
            qname: "evil.test".into(),
            answers: vec![],
            ttl: 0,
            reason: None,
        });
        let text: String = refused.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            text.contains("REFUSED") && text.contains("evil.test"),
            "got {text:?}"
        );
    }

    /// The reason sits before the name, which may get cut off at the panel's edge.
    #[test]
    fn a_refused_row_says_why_before_its_destination() {
        let line = |ev: &Event| -> String {
            event_line(ev)
                .spans
                .iter()
                .map(|s| s.content.as_ref())
                .collect()
        };
        let text = line(&Event::Dns {
            ts: 0,
            verdict: DnsVerdict::Refused,
            qname: "evil.test".into(),
            answers: vec![],
            ttl: 0,
            reason: Some(RefusalReason::Blocklist),
        });
        assert!(text.contains("REFUSED"), "{text}");
        assert!(text.contains("blocklist evil.test"), "{text}");

        let text = line(&Event::Egress {
            ts: 0,
            verdict: Verdict::Blocked,
            proto: "tcp".into(),
            daddr: "203.0.113.5".into(),
            dport: 443,
            rule: None,
            reason: Some(RefusalReason::TimedOut),
        });
        assert!(text.contains("timed out tcp 203.0.113.5:443"), "{text}");
    }

    fn allowed_egress(ts: u64) -> Event {
        Event::Egress {
            ts,
            verdict: Verdict::Allowed,
            proto: "tcp".into(),
            daddr: "10.0.0.5".into(),
            dport: 443,
            rule: Some("ip 10.0.0.0/8".into()),
            reason: None,
        }
    }

    fn refused_dns(ts: u64) -> Event {
        Event::Dns {
            ts,
            verdict: DnsVerdict::Refused,
            qname: "evil.test.".into(),
            answers: vec![],
            ttl: 0,
            reason: None,
        }
    }

    #[test]
    fn select_navigates_and_clamps_from_the_newest() {
        let mut a = app();
        for ts in 0..3 {
            a.ingest(egress(ts)); // buffer: [0,1,2], newest = 2
        }
        // No selection follows the tail.
        assert_eq!(a.sel(), None);
        // Up starts at the newest (offset 0) and walks toward older, clamping at 2.
        a.select_older();
        assert_eq!(a.sel(), Some(0));
        a.select_older();
        a.select_older();
        a.select_older(); // clamp at len-1
        assert_eq!(a.sel(), Some(2));
        // The selected event is the oldest retained (ts 0).
        assert!(matches!(
            a.selected_event(),
            Some(Event::Egress { ts: 0, .. })
        ));
        // Down walks back toward the newest, then releases to tail-follow.
        a.select_newer();
        assert_eq!(a.sel(), Some(1));
        a.select_newer();
        a.select_newer();
        assert_eq!(a.sel(), None);
    }

    #[test]
    fn focus_toggles_which_panels_selection_applies_to() {
        let mut a = app();
        a.ingest(egress(0));
        a.ingest(dns(1));
        a.select_older(); // selects in Egress
        assert_eq!(a.egress.sel, Some(0));
        assert_eq!(a.dns.sel, None);
        a.toggle_focus(); // now DNS
        a.select_older();
        assert_eq!(a.dns.sel, Some(0));
        assert_eq!(a.egress.sel, Some(0)); // egress selection preserved
    }

    #[test]
    fn allow_target_only_offered_for_blocked_rows() {
        let mut a = app();
        // Nothing selected yet.
        assert!(a.selected_allow_target().is_err());

        // A blocked egress row -> allow that proto and dst:port.
        a.ingest(egress(0)); // Blocked, daddr 203.0.113.1
        a.select_older();
        assert_eq!(a.selected_allow_target(), Ok(blocked_target()));

        // An already-allowed egress row is declined.
        let mut a = app();
        a.ingest(allowed_egress(0));
        a.select_older();
        assert!(a.selected_allow_target().is_err());

        // A refused DNS row -> allow the name, trailing dot stripped.
        let mut a = app();
        a.toggle_focus(); // focus DNS
        a.ingest(refused_dns(0));
        a.select_older();
        assert_eq!(
            a.selected_allow_target(),
            Ok(AllowTarget::Resolve("evil.test".into()))
        );

        // An allowed DNS row is declined.
        let mut a = app();
        a.toggle_focus();
        a.ingest(dns(0)); // Allowed
        a.select_older();
        assert!(a.selected_allow_target().is_err());
    }

    #[test]
    fn strip_trailing_dot_only_touches_the_suffix() {
        assert_eq!(strip_trailing_dot("example.com."), "example.com");
        assert_eq!(strip_trailing_dot("example.com"), "example.com");
        assert_eq!(strip_trailing_dot(""), "");
    }

    fn app_with_rules(rules: Vec<Rule>) -> App {
        App::new(
            "demo",
            None,
            None,
            PolicyView {
                version: 1,
                rules,
                ..PolicyView::default()
            },
            "running".into(),
            no_notify_file(),
        )
    }

    fn ip_rule(cidr: &str) -> Rule {
        Rule::Ip {
            cidr: cidr.into(),
            ports: None,
            proto: None,
        }
    }

    #[test]
    fn focus_cycles_through_policy_back_to_egress() {
        let mut a = app();
        assert!(a.focus == Focus::Egress);
        a.toggle_focus();
        assert!(a.focus == Focus::Dns);
        a.toggle_focus();
        assert!(a.focus == Focus::Policy);
        a.toggle_focus();
        assert!(a.focus == Focus::Requests);
        a.toggle_focus();
        assert!(a.focus == Focus::Egress);
    }

    #[test]
    fn policy_select_lands_on_first_then_clamps_both_ends() {
        let mut a = app_with_rules(vec![ip_rule("10.0.0.0/8"), ip_rule("192.168.0.0/16")]);
        a.focus = Focus::Policy;
        assert_eq!(a.policy_sel, None);
        // First move (either direction) lands on the first rule.
        a.policy_select(-1);
        assert_eq!(a.policy_sel, Some(0));
        // Down walks to the last rule and clamps there.
        a.policy_select(1);
        assert_eq!(a.policy_sel, Some(1));
        a.policy_select(1);
        assert_eq!(a.policy_sel, Some(1));
        // Up walks back and clamps at the first.
        a.policy_select(-1);
        a.policy_select(-1);
        assert_eq!(a.policy_sel, Some(0));
    }

    #[test]
    fn policy_select_is_a_noop_with_no_rules() {
        let mut a = app(); // no rules
        a.focus = Focus::Policy;
        a.policy_select(1);
        assert_eq!(a.policy_sel, None);
    }

    #[test]
    fn revoke_target_is_the_selected_rules_ip_or_domain() {
        let mut a = app_with_rules(vec![
            ip_rule("203.0.113.0/24"),
            Rule::Domain {
                name: "example.com".into(),
                scope: DomainScope::Subdomains,
                ports: None,
                proto: None,
            },
        ]);
        a.focus = Focus::Policy;
        // Nothing selected yet -> declined gracefully.
        request_policy_remove(&mut a);
        assert!(a.pending_revoke.is_none());

        a.policy_select(1); // first rule (ip)
        request_policy_remove(&mut a);
        assert_eq!(a.pending_revoke.take().as_deref(), Some("203.0.113.0/24"));

        a.policy_select(1); // second rule (domain) -> its name is the revoke spec
        request_policy_remove(&mut a);
        assert_eq!(a.pending_revoke.take().as_deref(), Some("example.com"));
    }

    fn egress_to(daddr: &str, dport: u16, verdict: Verdict, ts: u64) -> Event {
        Event::Egress {
            ts,
            verdict,
            proto: "tcp".into(),
            daddr: daddr.into(),
            dport,
            rule: None,
            reason: None,
        }
    }

    fn ts_of(ev: Option<&Event>) -> Option<u64> {
        match ev? {
            Event::Egress { ts, .. } | Event::Dns { ts, .. } => Some(*ts),
            _ => None,
        }
    }

    #[test]
    fn scroll_window_follows_the_cursor_past_the_edge() {
        // No selection follows the tail.
        assert_eq!(scroll_window(7, None, 5, 100), 0);
        // Cursor inside the window: the window stays put.
        assert_eq!(scroll_window(0, Some(3), 5, 100), 0);
        assert_eq!(scroll_window(10, Some(12), 5, 100), 10);
        // Cursor past the top edge: scroll just enough to keep it on the top row.
        assert_eq!(scroll_window(0, Some(5), 5, 100), 1);
        assert_eq!(scroll_window(0, Some(42), 5, 100), 38);
        // Cursor below the bottom edge (moving back toward newer): it lands on the bottom row.
        assert_eq!(scroll_window(38, Some(20), 5, 100), 20);
        // Never scroll past the oldest row (no blank space above it).
        assert_eq!(scroll_window(50, Some(9), 5, 10), 5);
        assert_eq!(scroll_window(0, Some(2), 5, 3), 0);
    }

    #[test]
    fn held_cursor_stays_on_its_row_as_events_arrive() {
        let mut a = app();
        for ts in 0..3 {
            a.ingest(egress(ts));
        }
        a.select_older();
        a.select_older(); // offset 1 = ts 1
        a.egress.scroll = 1;
        assert_eq!(ts_of(a.selected_event()), Some(1));
        a.ingest(egress(3));
        a.ingest(egress(4));
        assert_eq!(ts_of(a.selected_event()), Some(1), "cursor must not drift");
        assert_eq!(a.egress.sel, Some(3));
        assert_eq!(a.egress.scroll, 3, "window moves with the cursor");
        // Following the tail is unaffected.
        a.dns.release();
        a.ingest(dns(5));
        assert_eq!(a.dns.sel, None);
        assert_eq!(a.dns.scroll, 0);
    }

    #[test]
    fn held_cursor_clamps_when_its_row_is_evicted() {
        let mut a = app();
        a.egress.tail = Bounded::new(2);
        a.ingest(egress(0));
        a.ingest(egress(1));
        a.select_older();
        a.select_older(); // the oldest, ts 0
        a.ingest(egress(2)); // evicts ts 0
        assert_eq!(a.egress.sel, Some(1));
        assert_eq!(ts_of(a.selected_event()), Some(1));
    }

    #[test]
    fn unique_view_keeps_one_row_per_destination() {
        let mut a = app();
        a.ingest(egress_to("203.0.113.1", 443, Verdict::Blocked, 0));
        a.ingest(egress_to("203.0.113.2", 443, Verdict::Blocked, 1));
        a.ingest(egress_to("203.0.113.1", 443, Verdict::Blocked, 2));
        a.ingest(egress_to("203.0.113.1", 80, Verdict::Blocked, 3)); // other port: distinct
        a.ingest(egress_to("203.0.113.2", 443, Verdict::Allowed, 4));
        assert_eq!(a.egress.len(false), 5);
        assert_eq!(a.egress.len(true), 3);

        // Newest-first, in first-seen order, each with its latest event and hit count.
        let rows: Vec<(u64, Option<u64>)> = a
            .egress
            .rows(true)
            .map(|(ev, hits)| (ts_of(Some(ev)).unwrap(), hits))
            .collect();
        assert_eq!(rows, vec![(3, Some(1)), (4, Some(2)), (2, Some(2))]);

        // Acting on a unique row uses its latest verdict.
        a.toggle_unique();
        a.select_older();
        a.select_older(); // 203.0.113.2, latest verdict Allowed
        assert!(a.selected_allow_target().is_err());
        a.select_older(); // 203.0.113.1:443, latest verdict Blocked
        assert_eq!(a.selected_allow_target(), Ok(blocked_target()));
    }

    #[test]
    fn unique_dns_ignores_case_and_trailing_dot() {
        let mut a = app();
        a.ingest(refused_dns(0)); // "evil.test."
        a.ingest(Event::Dns {
            ts: 1,
            verdict: DnsVerdict::Refused,
            qname: "Evil.Test".into(),
            answers: vec![],
            ttl: 0,
            reason: None,
        });
        a.ingest(dns(2)); // example.com
        assert_eq!(a.dns.len(true), 2);
    }

    #[test]
    fn unique_cursor_only_moves_for_new_destinations() {
        let mut a = app();
        a.toggle_unique();
        a.ingest(egress_to("203.0.113.1", 443, Verdict::Blocked, 0));
        a.ingest(egress_to("203.0.113.2", 443, Verdict::Blocked, 1));
        a.select_older();
        a.select_older(); // 203.0.113.1
                          // A repeat refreshes a row in place: nothing shifts.
        a.ingest(egress_to("203.0.113.2", 443, Verdict::Blocked, 2));
        assert_eq!(a.egress.sel, Some(1));
        // A new destination lands below: the cursor follows its row.
        a.ingest(egress_to("203.0.113.3", 443, Verdict::Blocked, 3));
        assert_eq!(a.egress.sel, Some(2));
        assert_eq!(a.selected_allow_target(), Ok(blocked_target()));
    }

    #[test]
    fn toggling_the_view_releases_both_cursors() {
        let mut a = app();
        a.ingest(egress(0));
        a.ingest(dns(1));
        a.select_older();
        a.toggle_focus();
        a.select_older();
        a.toggle_unique();
        assert!(a.unique);
        assert_eq!((a.egress.sel, a.dns.sel), (None, None));
    }

    #[test]
    fn distinct_forgets_the_oldest_destination_at_capacity() {
        let mut d = Distinct::new(2);
        assert!(d.record(&egress_to("203.0.113.1", 443, Verdict::Blocked, 0)));
        assert!(d.record(&egress_to("203.0.113.2", 443, Verdict::Blocked, 1)));
        assert!(d.record(&egress_to("203.0.113.3", 443, Verdict::Blocked, 2)));
        assert_eq!(d.len(), 2);
        // .1 was forgotten, so it's new again; .3 is still indexed correctly.
        assert!(!d.record(&egress_to("203.0.113.3", 443, Verdict::Blocked, 3)));
        assert!(d.record(&egress_to("203.0.113.1", 443, Verdict::Blocked, 4)));
        assert!(
            !d.record(&Event::Policy { ts: 5, version: 1 }),
            "non-flow events are ignored"
        );
    }

    #[test]
    fn clamp_policy_sel_follows_a_shrinking_list() {
        let mut a = app_with_rules(vec![ip_rule("10.0.0.0/8"), ip_rule("192.168.0.0/16")]);
        a.focus = Focus::Policy;
        a.policy_select(1);
        a.policy_select(1);
        assert_eq!(a.policy_sel, Some(1));
        // Simulate a deny removing the last rule; the cursor clamps into range.
        a.policy = PolicyView {
            version: 2,
            rules: vec![ip_rule("10.0.0.0/8")],
            ..PolicyView::default()
        };
        a.clamp_policy_sel();
        assert_eq!(a.policy_sel, Some(0));
        // Emptying the list releases the selection entirely.
        a.policy = PolicyView {
            version: 3,
            ..PolicyView::default()
        };
        a.clamp_policy_sel();
        assert_eq!(a.policy_sel, None);
    }

    fn press(a: &mut App, code: KeyCode) {
        handle_key(
            a,
            KeyPress {
                code,
                mods: KeyModifiers::NONE,
            },
        );
    }

    /// An app whose policy has a gateway with two aliases.
    fn gateway_app() -> App {
        let policy: VmPolicy = toml::from_str(
            "version = 4\n[gateway]\nenabled = true\n\
             [[rules]]\nkind = \"service\"\nname = \"inference\"\n\
             [[models]]\nalias = \"big\"\nprovider = \"m\"\nmodel = \"large\"\ninitial_quota = 500\n\
             [[models]]\nalias = \"free\"\nprovider = \"m\"\nmodel = \"small\"\nquota = \"unlimited\"\n",
        )
        .unwrap();
        App::new(
            "demo",
            None,
            None,
            PolicyView::from(policy),
            "running".into(),
            no_notify_file(),
        )
    }

    fn inference(ts: u64) -> Event {
        Event::Inference {
            ts,
            verdict: Verdict::Allowed,
            api: "openai".into(),
            alias: "big".into(),
            provider: Some("m".into()),
            model: Some("large".into()),
            status: 200,
            tokens: Default::default(),
            complete: true,
            latency_ms: 5,
        }
    }

    #[test]
    fn inference_events_go_to_their_own_panel_and_flag_a_balance_refetch() {
        let mut a = app();
        a.quota_dirty = false;
        a.ingest(inference(1));
        a.ingest(Event::QuotaExhausted {
            ts: 2,
            alias: "big".into(),
        });
        assert_eq!((a.inference.tail.len(), a.egress.tail.len()), (2, 0));
        assert!(a.quota_dirty);
    }

    #[test]
    fn tabs_switch_and_tab_cycles_within_them() {
        let mut a = gateway_app();
        assert_eq!((a.tab, a.focus), (Tab::Network, Focus::Egress));
        press(&mut a, KeyCode::Tab);
        press(&mut a, KeyCode::Tab);
        assert_eq!(a.focus, Focus::Policy);
        press(&mut a, KeyCode::Tab);
        assert_eq!(a.focus, Focus::Requests);
        press(&mut a, KeyCode::Tab);
        assert_eq!(
            a.focus,
            Focus::Egress,
            "the network tab cycles its own panels"
        );
        press(&mut a, KeyCode::Char('2'));
        assert_eq!((a.tab, a.focus), (Tab::Inference, Focus::Inference));
        press(&mut a, KeyCode::Tab);
        assert_eq!(a.focus, Focus::Gateway);
        press(&mut a, KeyCode::Tab);
        assert_eq!(a.focus, Focus::Inference);
        press(&mut a, KeyCode::Left);
        assert_eq!((a.tab, a.focus), (Tab::Network, Focus::Egress));
    }

    #[test]
    fn grant_prompt_takes_keys_until_enter_or_esc() {
        let mut a = gateway_app();
        a.show_tab(Tab::Inference);
        a.focus = Focus::Gateway;
        press(&mut a, KeyCode::Char('g'));
        assert!(
            a.notice.as_ref().is_some_and(|n| n.error),
            "nothing selected yet"
        );
        press(&mut a, KeyCode::Down);
        press(&mut a, KeyCode::Char('g'));
        assert_eq!(a.prompt.as_ref().unwrap().alias, "big");
        // `q` isn't a token character, so it neither quits nor lands in the input.
        for c in ['2', 'q', 'M'] {
            press(&mut a, KeyCode::Char(c));
        }
        assert!(!a.should_quit);
        assert_eq!(a.prompt.as_ref().unwrap().input, "2M");
        press(&mut a, KeyCode::Enter);
        assert_eq!(a.pending_grant, Some(("big".into(), 2_000_000)));
        assert!(a.prompt.is_none());

        // Esc cancels the prompt, not the TUI.
        press(&mut a, KeyCode::Enter);
        press(&mut a, KeyCode::Esc);
        assert!(a.prompt.is_none() && !a.should_quit);
    }

    #[test]
    fn metering_switch_flips_the_selected_alias() {
        let mut a = gateway_app();
        a.show_tab(Tab::Inference);
        a.focus = Focus::Gateway;
        press(&mut a, KeyCode::Down);
        press(&mut a, KeyCode::Char('m'));
        assert_eq!(
            a.pending_metering,
            Some(("big".into(), QuotaMode::Unlimited))
        );
        press(&mut a, KeyCode::Down);
        press(&mut a, KeyCode::Char('m'));
        assert_eq!(
            a.pending_metering,
            Some(("free".into(), QuotaMode::Limited))
        );
    }

    #[test]
    fn balances_show_the_initial_quota_until_first_use() {
        let mut a = gateway_app();
        let big = a.policy.models[0].clone();
        let free = a.policy.models[1].clone();
        assert_eq!(a.balance_label(&big), "500");
        assert_eq!(a.balance_label(&free), "∞");
        a.quota.insert(
            "big".into(),
            sodabox_common::quota::Balance {
                balance: -20,
                initialized: true,
                granted: 500,
                used: 520,
                unmetered: 0,
            },
        );
        assert_eq!(a.balance_label(&big), "-20");
    }

    /// Draw `a` into an in-memory terminal and return the screen as text.
    fn screen(a: &mut App) -> String {
        let mut term = ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 24)).unwrap();
        term.draw(|f| draw(f, a)).unwrap();
        let buf = term.backend().buffer().clone();
        (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The probe's reply classification: a graphics answer wins (even an
    /// error — the protocol answered), a lone device-attributes answer means
    /// no support.
    #[test]
    fn probe_replies_are_classified() {
        // kitty-style: the graphics answer comes first, then the DA reply.
        let both = b"\x1b_Gi=31;OK\x1b\\\x1b[?62;22c";
        assert!(has_graphics_reply(both));
        assert!(has_graphics_reply(b"\x1b_Gi=31;EBADF: nope\x1b\\"));
        // A terminal without the protocol answers only the device attributes.
        let da = b"\x1b[?62;22c";
        assert!(!has_graphics_reply(da));
        assert!(has_da_reply(da));
        // The graphics check runs first, so a DA reply in the same stream
        // doesn't turn support into its absence.
        assert!(has_da_reply(both));
    }

    /// The probe consumes the reply through its final DA answer, even split
    /// across reads, and leaves no reader behind: the next key stays on the
    /// input for the event loop.
    #[test]
    fn the_probe_drains_its_reply_and_leaves_keys_alone() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;

        let (mut term, tui) = UnixStream::pair().unwrap();
        term.write_all(b"\x1b_Gi=31;OK\x1b\\").unwrap();
        let mut late = term.try_clone().unwrap();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            late.write_all(b"\x1b[?62;22c").unwrap();
        });
        assert!(read_probe_reply(&tui, Duration::from_secs(5)));
        writer.join().unwrap();

        term.write_all(b"j").unwrap();
        let mut key = [0u8; 8];
        let n = (&tui).read(&mut key).unwrap();
        assert_eq!(&key[..n], b"j");
    }

    /// A lone DA answer ends the probe at once with no support, as does
    /// silence once the timeout passes; a closed input doesn't hang it.
    #[test]
    fn the_probe_settles_without_a_graphics_reply() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let (mut term, tui) = UnixStream::pair().unwrap();
        term.write_all(b"\x1b[?62;22c").unwrap();
        let start = Instant::now();
        assert!(!read_probe_reply(&tui, Duration::from_secs(5)));
        assert!(start.elapsed() < Duration::from_secs(5));

        let (term, tui) = UnixStream::pair().unwrap();
        assert!(!read_probe_reply(&tui, Duration::from_millis(20)));

        drop(term);
        assert!(!read_probe_reply(&tui, Duration::from_secs(5)));
    }

    /// RFC 4648 test vectors — the graphics protocol's payload encoding.
    #[test]
    fn base64_matches_rfc4648() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    /// The logo's placement rectangle is the status lines' height, with the
    /// fields flowing to its right — and nothing at all when the terminal
    /// didn't answer the graphics-protocol probe.
    #[test]
    fn the_logo_is_constrained_to_the_status_lines() {
        let mut a = app();
        let mut term = ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 24)).unwrap();
        term.draw(|f| draw(f, &mut a)).unwrap();
        assert_eq!(a.logo_place, None);

        a.graphics = true;
        term.draw(|f| draw(f, &mut a)).unwrap();
        // The panel's four lines → a 4×4-cell rectangle (the 120×256 PNG's
        // aspect), flush against the panel's inner right edge.
        assert_eq!(
            a.logo_place,
            Some(Rect {
                x: 115,
                y: 2,
                width: 4,
                height: 4
            })
        );
        let buf = term.backend().buffer();
        // The fields start at the panel's inner left.
        assert_eq!(buf[(73, 2)].symbol(), "s");
        assert_eq!(buf[(73, 5)].symbol(), "u");
    }

    /// At a width where the logo fits on the Inference tab's wider right column
    /// but not on the Network tab's, switching tabs takes the placement down
    /// once and keeps the image data; switching back places it again.
    #[test]
    fn a_logo_that_stops_fitting_leaves_the_screen() {
        let mut a = app();
        a.graphics = true;
        let mut term = ratatui::Terminal::new(ratatui::backend::TestBackend::new(70, 24)).unwrap();
        let mut frame = |a: &mut App, tab| {
            a.show_tab(tab);
            term.draw(|f| draw(f, a)).unwrap();
            let mut out = Vec::new();
            place_logo(&mut out, a);
            String::from_utf8(out).unwrap()
        };

        assert!(frame(&mut a, Tab::Inference).contains("a=p,i=1,p=1"));
        assert_eq!(
            frame(&mut a, Tab::Network),
            "\x1b_Ga=d,d=i,i=1,p=1,q=2\x1b\\"
        );
        // Nothing left to take down on the frames after that.
        assert_eq!(frame(&mut a, Tab::Network), "");
        assert!(frame(&mut a, Tab::Inference).contains("a=p,i=1,p=1"));
    }

    #[test]
    fn guest_controlled_names_reach_the_screen_without_control_characters() {
        let hostile = "x\u{7}\u{1b}]52;c;Zm9v\u{7}\u{9b}2J.evil.test";
        let mut a = app();
        a.ingest(Event::RequestPending {
            ts: 0,
            id: 1,
            proto: "dns".into(),
            destination: hostile.into(),
            port: None,
            via: None,
            expires_ts: u64::MAX,
        });
        a.ingest(Event::RequestPending {
            ts: 0,
            id: 2,
            proto: "tcp".into(),
            destination: "203.0.113.5".into(),
            port: Some(443),
            via: Some(hostile.into()),
            expires_ts: u64::MAX,
        });
        a.ingest(Event::Dns {
            ts: 0,
            verdict: DnsVerdict::Refused,
            qname: hostile.into(),
            answers: Vec::new(),
            ttl: 0,
            reason: None,
        });
        // A highlighted row takes its own rendering path.
        a.request_sel = Some(1);

        let text = screen(&mut a);
        assert!(text.contains("evil.test"), "{text}");
        let stray: Vec<char> = text
            .chars()
            .filter(|c| c.is_control() && *c != '\n')
            .collect();
        assert!(stray.is_empty(), "{stray:?}\n{text}");
    }

    #[test]
    fn both_tabs_render() {
        let mut a = gateway_app();
        let net = screen(&mut a);
        assert!(
            net.contains("Egress") && net.contains("DNS") && net.contains("Policy"),
            "{net}"
        );
        assert!(!net.contains("Gateway"), "{net}");

        a.ingest(inference(1));
        a.show_tab(Tab::Inference);
        a.focus = Focus::Gateway;
        a.gateway_select(1);
        let inf = screen(&mut a);
        for want in [
            "Inference",
            "Gateway",
            "access granted",
            "500",
            "∞",
            "m/small",
            "g grant",
        ] {
            assert!(inf.contains(want), "missing {want:?} in:\n{inf}");
        }
        assert!(!inf.contains("Egress"), "{inf}");

        a.prompt = Some(GrantPrompt {
            alias: "big".into(),
            input: "2M".into(),
        });
        assert!(screen(&mut a).contains("grant tokens to 'big': 2M"));
    }
}
