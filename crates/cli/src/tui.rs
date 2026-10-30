//! `soda tui <vm>` — live terminal monitor (ADR-0009).
//!
//! Built on a control-socket `subscribe`, a ratatui render loop and bounded
//! buffers for backpressure, it shows four panels:
//!
//! - **Egress** — flow verdicts (proto, dst:port, matched rule).
//! - **DNS** — query verdicts (name, resolved IPs, TTL).
//! - **Policy** — the live policy version and its rules.
//! - **Status** — VM state, configured CPU/RAM, and uptime.
//!
//! Quick-actions: the focused flow panel has a selectable cursor
//! (`Tab` switches panels, `↑`/`↓` move it), and `a`/`Enter` allows the
//! highlighted **blocked** destination on the spot — an egress `BLOCK` becomes
//! an `ip` allow of its dst, a DNS `REFUSED` becomes a `domain` allow of its
//! name. Like `soda allow`, that edits `policy.toml` and pushes the whole new
//! policy via `PolicySet` (the supervisor rejects raw single-rule edits so the
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
use std::time::{Duration, SystemTime};

use ratatui::crossterm::event::{self, Event as TermEvent, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;
use tokio::sync::mpsc;

use sodabox_common::event::{DnsVerdict, Event, Verdict};
use sodabox_common::paths;
use sodabox_common::policy::{DomainScope, PolicyFile, Rule, VmPolicy};
use sodabox_common::protocol::{Request, Response};
use sodabox_common::vm::VmMeta;
use sodabox_supervisor::control::{ControlClient, EventStream};

/// Per-panel retention. A tail only shows a screenful; this bounds memory well
/// above any visible window while staying tiny.
const PANEL_CAPACITY: usize = 2048;

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
/// feed) and the rules (fetched separately via `policy.get`).
struct PolicyView {
    version: u32,
    rules: Vec<Rule>,
}

/// Which panel the selection cursor is on. Egress/DNS are the flow panels (allow
/// a just-blocked destination); Policy is the rule list (deny a selected
/// rule).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    Egress,
    Dns,
    Policy,
}

/// A destination the user chose to allow from a highlighted blocked row.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AllowTarget {
    /// Egress `BLOCK` → allow the dst IP (a bare host, added as a /32).
    Ip(String),
    /// DNS `REFUSED` → allow the queried name (subdomains scope).
    Domain(String),
}

/// A transient footer message (the outcome of the last quick-action).
struct Notice {
    text: String,
    error: bool,
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
    /// Cursor into `policy.rules` (top-down index; `None` = no selection). Unlike
    /// the flow panels' cursors this is a plain list index, not an offset-from-newest.
    policy_sel: Option<usize>,
    /// A quick-action requested this frame, applied (async) after the select.
    pending_allow: Option<AllowTarget>,
    /// A deny quick-action (the target `spec` for `remove_matching`) requested on
    /// the Policy panel this frame, applied (async) after the select.
    pending_deny: Option<String>,
    /// The last quick-action's outcome, shown in the footer.
    notice: Option<Notice>,
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
    ) -> Self {
        Self {
            vm: vm.to_string(),
            cpus: meta.as_ref().map(|m| m.cpus),
            mem: meta.map(|m| m.mem),
            boot,
            egress: FlowPanel::new(PANEL_CAPACITY),
            dns: FlowPanel::new(PANEL_CAPACITY),
            unique: false,
            policy,
            policy_dirty: false,
            state,
            dropped: 0,
            focus: Focus::Egress,
            policy_sel: None,
            pending_allow: None,
            pending_deny: None,
            notice: None,
            should_quit: false,
            disconnected: false,
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
            Event::Dns { .. } => {
                if self.dns.push(ev, self.unique) {
                    self.dropped = self.dropped.saturating_add(1);
                }
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
            }
        }
    }

    fn uptime(&self) -> Option<Duration> {
        self.boot
            .and_then(|b| SystemTime::now().duration_since(b).ok())
    }

    /// The focused flow panel, or `None` when the Policy panel is focused (it
    /// holds rules, not events).
    fn focused_flow(&self) -> Option<&FlowPanel> {
        match self.focus {
            Focus::Egress => Some(&self.egress),
            Focus::Dns => Some(&self.dns),
            Focus::Policy => None,
        }
    }

    fn focused_flow_mut(&mut self) -> Option<&mut FlowPanel> {
        match self.focus {
            Focus::Egress => Some(&mut self.egress),
            Focus::Dns => Some(&mut self.dns),
            Focus::Policy => None,
        }
    }

    #[cfg(test)]
    fn sel(&self) -> Option<usize> {
        match self.focus {
            Focus::Egress => self.egress.sel,
            Focus::Dns => self.dns.sel,
            Focus::Policy => self.policy_sel,
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
    }

    /// Move the Policy-panel cursor by `delta` rows, clamped to the rule list;
    /// the first move from no-selection lands on the first rule.
    fn policy_select(&mut self, delta: i32) {
        let len = self.policy.rules.len();
        if len == 0 {
            self.policy_sel = None;
            return;
        }
        self.policy_sel = Some(match self.policy_sel {
            None => 0,
            Some(cur) => (cur as i32 + delta).clamp(0, len as i32 - 1) as usize,
        });
    }

    /// Keep the Policy cursor valid after the rule list changes (e.g. a deny
    /// removed rows or a re-fetch shrank the list).
    fn clamp_policy_sel(&mut self) {
        let len = self.policy.rules.len();
        self.policy_sel = match self.policy_sel {
            _ if len == 0 => None,
            Some(i) => Some(i.min(len - 1)),
            None => None,
        };
    }

    fn toggle_focus(&mut self) {
        self.focus = match self.focus {
            Focus::Egress => Focus::Dns,
            Focus::Dns => Focus::Policy,
            Focus::Policy => Focus::Egress,
        };
    }

    /// The event under the cursor in the focused flow panel, if any.
    /// In the unique view that's the destination's latest event, so a row whose
    /// most recent verdict is a block is still actionable.
    fn selected_event(&self) -> Option<&Event> {
        let p = self.focused_flow()?;
        p.rows(self.unique).nth(p.sel?).map(|(ev, _)| ev)
    }

    /// The policy rule under the Policy-panel cursor, if any.
    fn selected_rule(&self) -> Option<&Rule> {
        self.policy_sel.and_then(|i| self.policy.rules.get(i))
    }

    /// The `remove_matching` target for the highlighted rule (its IP cidr or
    /// domain name), or why there is nothing to deny. Mirrors
    /// [`App::selected_allow_target`] for the deny direction.
    fn selected_deny_target(&self) -> Result<String, &'static str> {
        match self.selected_rule() {
            None => Err("select a rule first (↑/↓)"),
            Some(Rule::Ip { cidr, .. }) => Ok(cidr.clone()),
            Some(Rule::Domain { name, .. }) => Ok(name.clone()),
        }
    }

    /// What allowing the highlighted row would do — or why it can't. Only a
    /// *blocked* destination is actionable (allowing an already-allowed flow is a
    /// no-op the UI declines rather than issue a redundant policy bump).
    fn selected_allow_target(&self) -> Result<AllowTarget, &'static str> {
        match self.selected_event() {
            None => Err("select a row first (↑/↓)"),
            Some(Event::Egress {
                verdict: Verdict::Blocked,
                daddr,
                ..
            }) => Ok(AllowTarget::Ip(daddr.clone())),
            Some(Event::Egress { .. }) => Err("that flow is already allowed"),
            Some(Event::Dns {
                verdict: DnsVerdict::Refused,
                qname,
                ..
            }) => Ok(AllowTarget::Domain(strip_trailing_dot(qname))),
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
            .map(|p| PolicyView {
                version: p.version,
                rules: p.rules,
            })
            .unwrap_or(PolicyView {
                version: 0,
                rules: Vec::new(),
            });

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

        let mut app = App::new(vm, meta, boot, policy, state);
        let mut terminal = ratatui::init();
        let res = event_loop(&mut terminal, &mut app, stream).await;
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
/// existing rule short-circuits with no version bump.
async fn apply_allow(vm: &str, target: &AllowTarget) -> anyhow::Result<(VmPolicy, String)> {
    let mut file = PolicyFile::load(vm).map_err(|e| anyhow::anyhow!("reading policy: {e}"))?;
    let (added, summary) = match target {
        AllowTarget::Ip(cidr) => (
            file.add_ip(cidr, None).map_err(|e| anyhow::anyhow!(e))?,
            format!("allowed ip {cidr}"),
        ),
        AllowTarget::Domain(name) => (
            file.add_domain(name, DomainScope::Subdomains, None)
                .map_err(|e| anyhow::anyhow!(e))?,
            format!("allowed domain {name}"),
        ),
    };
    if !added {
        // Already present — nothing to persist or push.
        return Ok((
            file.policy().map_err(|e| anyhow::anyhow!(e))?,
            "already allowed".into(),
        ));
    }

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
    file.set_version(policy.version + 1);
    file.save(vm)
        .map_err(|e| anyhow::anyhow!("writing policy.toml: {e}"))?;
    file.policy().map_err(|e| anyhow::anyhow!(e))
}

/// Apply a deny quick-action: remove every rule matching `spec` from
/// `vm`'s persisted policy, validate, version-bump, save `policy.toml`, and push
/// the whole new policy live via `PolicySet` — the same edit-then-push path as
/// `soda deny`, so the file and the live allowlist never split-brain (the live
/// swap also purges a removed domain's ephemerals). Returns the new policy
/// (so the panel refreshes without a round trip) and a human summary. A `spec`
/// that matches nothing short-circuits with no version bump.
async fn apply_deny(vm: &str, spec: &str) -> anyhow::Result<(VmPolicy, String)> {
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
                format!("denied {spec} ({removed} {plural}) (v{})", policy.version),
            ))
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

    terminal.draw(|f| draw(f, app))?;
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
                terminal.draw(|f| draw(f, app))?;
            }
        }

        // A quick-action (`a`/Enter on a blocked row): edit + push live, then
        // reflect the result in the footer and the policy panel. Done here, off
        // the sync key handler, since it awaits a control-socket round trip.
        if let Some(target) = app.pending_allow.take() {
            match apply_allow(&app.vm, &target).await {
                Ok((policy, summary)) => {
                    app.policy = PolicyView {
                        version: policy.version,
                        rules: policy.rules,
                    };
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

        // A deny quick-action on the Policy panel (`d`/Enter): remove + push live,
        // then reflect the result in the footer and refresh the panel.
        if let Some(spec) = app.pending_deny.take() {
            match apply_deny(&app.vm, &spec).await {
                Ok((policy, summary)) => {
                    app.policy = PolicyView {
                        version: policy.version,
                        rules: policy.rules,
                    };
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

        // A policy version bump means the rules may have changed; re-fetch them
        // (a quick local IPC round trip) outside the panel render.
        if app.policy_dirty && !app.disconnected {
            if let Some(p) = fetch_policy(&app.vm).await {
                app.policy = PolicyView {
                    version: p.version,
                    rules: p.rules,
                };
                app.clamp_policy_sel();
            }
            app.policy_dirty = false;
        }

        if app.should_quit {
            break;
        }
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

/// Key bindings: quit (`q`/`Esc`/`Ctrl-C`), switch panel (`Tab`), move the cursor
/// (`↑`/`↓`, `k`/`j`), toggle the unique view of the flow panels (`u`). On a flow
/// panel `a`/Enter allows the highlighted blocked destination; on the Policy
/// panel `d`/Enter denies the highlighted rule. The action key is
/// context-sensitive to the focused panel.
fn handle_key(app: &mut App, k: KeyPress) {
    match k.code {
        KeyCode::Char('c') if k.mods.contains(KeyModifiers::CONTROL) => app.should_quit = true,
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
        KeyCode::Tab | KeyCode::BackTab => app.toggle_focus(),
        KeyCode::Char('u') => app.toggle_unique(),
        KeyCode::Up | KeyCode::Char('k') => match app.focus {
            Focus::Policy => app.policy_select(-1),
            _ => app.select_older(),
        },
        KeyCode::Down | KeyCode::Char('j') => match app.focus {
            Focus::Policy => app.policy_select(1),
            _ => app.select_newer(),
        },
        // `a` allows (flow panels only); `d` denies (Policy panel only). Enter is
        // "act on the selection" — allow or deny depending on the focused panel.
        KeyCode::Char('a') if app.focus != Focus::Policy => request_allow(app),
        KeyCode::Char('d') if app.focus == Focus::Policy => request_deny(app),
        KeyCode::Enter => match app.focus {
            Focus::Policy => request_deny(app),
            _ => request_allow(app),
        },
        _ => {}
    }
}

/// Queue an allow of the highlighted blocked flow, or surface why it can't.
fn request_allow(app: &mut App) {
    match app.selected_allow_target() {
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

/// Queue a deny of the highlighted policy rule, or surface why it can't.
fn request_deny(app: &mut App) {
    match app.selected_deny_target() {
        Ok(spec) => app.pending_deny = Some(spec),
        Err(msg) => {
            app.notice = Some(Notice {
                text: msg.to_string(),
                error: true,
            })
        }
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
fn draw(f: &mut Frame, app: &mut App) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(f.area());

    f.render_widget(header(app), outer[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(outer[1]);

    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(body[0]);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(6), Constraint::Min(1)])
        .split(body[1]);

    render_flow_panel(
        f,
        left[0],
        "Egress",
        &mut app.egress,
        app.focus == Focus::Egress,
        app.unique,
    );
    render_flow_panel(
        f,
        left[1],
        "DNS",
        &mut app.dns,
        app.focus == Focus::Dns,
        app.unique,
    );
    f.render_widget(status_panel(app), right[0]);
    render_policy_panel(f, right[1], app);

    f.render_widget(footer(app), outer[2]);
}

fn header(app: &App) -> Paragraph<'static> {
    let state_color = match app.state.as_str() {
        "running" => Color::Green,
        "stopped" => Color::Red,
        _ => Color::Yellow,
    };
    let mut spans = vec![
        Span::styled(
            format!(" sodabox {} ", app.vm),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw("["),
        Span::styled(app.state.clone(), Style::default().fg(state_color)),
        Span::raw(format!(
            "  egress {}  dns {}",
            app.egress.tail.len(),
            app.dns.tail.len()
        )),
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

fn status_panel(app: &App) -> Paragraph<'static> {
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
    let lines = vec![
        Line::from(vec![
            field("state"),
            Span::styled(app.state.clone(), Style::default().fg(state_color)),
        ]),
        Line::from(vec![field("cpu"), Span::raw(cpu)]),
        Line::from(vec![field("mem"), Span::raw(mem)]),
        Line::from(vec![field("uptime"), Span::raw(uptime)]),
    ];
    Paragraph::new(lines).block(Block::bordered().title(" Status "))
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

    let rules = &app.policy.rules;
    if rules.is_empty() {
        lines.push(Line::from(Span::styled(
            "(deny-all)",
            Style::default().fg(Color::DarkGray),
        )));
        f.render_widget(Paragraph::new(lines).block(block), area);
        return;
    }

    // Rows left below the version header; reserve one for the "…" indicator when
    // the list doesn't fully fit, and keep the selected row inside the window.
    let room = inner_h.saturating_sub(1).max(1);
    let truncated = rules.len() > room;
    let cap = if truncated {
        room.saturating_sub(1).max(1)
    } else {
        room
    };
    let start = match app.policy_sel {
        Some(i) if i >= cap => (i + 1 - cap).min(rules.len() - cap),
        _ => 0,
    };
    for (idx, r) in rules.iter().enumerate().skip(start).take(cap) {
        let mut line = Line::from(fmt_rule(r));
        if focused && app.policy_sel == Some(idx) {
            line = line.style(Style::default().add_modifier(Modifier::REVERSED));
        }
        lines.push(line);
    }
    if truncated {
        let end = (start + cap).min(rules.len());
        lines.push(Line::from(Span::styled(
            format!("… {}–{} of {}", start + 1, end, rules.len()),
            Style::default().fg(Color::DarkGray),
        )));
    }
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn footer(app: &App) -> Paragraph<'static> {
    let mut spans = Vec::new();
    if let Some(n) = &app.notice {
        let color = if n.error { Color::Red } else { Color::Green };
        spans.push(Span::styled(
            format!(" {} ", n.text),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ));
    }
    // The action key is context-sensitive: `a` allows on the flow panels, `d`
    // denies on the Policy panel (Enter acts on whichever is focused).
    let action = if app.focus == Focus::Policy {
        "d deny"
    } else {
        "a allow"
    };
    let view = if app.unique { "u all" } else { "u unique" };
    spans.push(Span::styled(
        format!(" Tab panel  ↑/↓ select  {action}  {view}  q quit "),
        Style::default().fg(Color::DarkGray),
    ));
    Paragraph::new(Line::from(spans))
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
        } => {
            let (tag, color) = match verdict {
                Verdict::Allowed => ("ALLOW", Color::Green),
                Verdict::Blocked => ("BLOCK", Color::Red),
            };
            let mut spans = vec![
                ts_span(*ts),
                tag_span(tag, color),
                Span::raw(format!("{proto} {daddr}:{dport}")),
            ];
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
            Line::from(vec![ts_span(*ts), tag_span(tag, color), Span::raw(detail)])
        }
        // Not routed to a flow panel, but render defensively.
        Event::Policy { ts, version } => Line::from(vec![
            ts_span(*ts),
            tag_span("POLICY", Color::Cyan),
            Span::raw(format!("v{version}")),
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
        }
    }

    fn dns(ts: u64) -> Event {
        Event::Dns {
            ts,
            verdict: DnsVerdict::Allowed,
            qname: "example.com".into(),
            answers: vec!["93.184.216.34".into()],
            ttl: 300,
        }
    }

    fn app() -> App {
        App::new(
            "demo",
            None,
            None,
            PolicyView {
                version: 1,
                rules: vec![],
            },
            "running".into(),
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
        });
        let text: String = refused.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(
            text.contains("REFUSED") && text.contains("evil.test"),
            "got {text:?}"
        );
    }

    fn allowed_egress(ts: u64) -> Event {
        Event::Egress {
            ts,
            verdict: Verdict::Allowed,
            proto: "tcp".into(),
            daddr: "10.0.0.5".into(),
            dport: 443,
            rule: Some("ip 10.0.0.0/8".into()),
        }
    }

    fn refused_dns(ts: u64) -> Event {
        Event::Dns {
            ts,
            verdict: DnsVerdict::Refused,
            qname: "evil.test.".into(),
            answers: vec![],
            ttl: 0,
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

        // A blocked egress row -> allow its dst IP.
        a.ingest(egress(0)); // Blocked, daddr 203.0.113.1
        a.select_older();
        assert_eq!(
            a.selected_allow_target(),
            Ok(AllowTarget::Ip("203.0.113.1".into()))
        );

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
            Ok(AllowTarget::Domain("evil.test".into()))
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
            PolicyView { version: 1, rules },
            "running".into(),
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
    fn deny_target_is_the_selected_rules_ip_or_domain() {
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
        assert!(a.selected_deny_target().is_err());

        a.policy_select(1); // first rule (ip)
        assert_eq!(a.selected_deny_target(), Ok("203.0.113.0/24".to_string()));

        a.policy_select(1); // second rule (domain) -> its name is the deny spec
        assert_eq!(a.selected_deny_target(), Ok("example.com".to_string()));
    }

    fn egress_to(daddr: &str, dport: u16, verdict: Verdict, ts: u64) -> Event {
        Event::Egress {
            ts,
            verdict,
            proto: "tcp".into(),
            daddr: daddr.into(),
            dport,
            rule: None,
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
        assert_eq!(
            a.selected_allow_target(),
            Ok(AllowTarget::Ip("203.0.113.1".into()))
        );
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
        assert_eq!(
            a.selected_allow_target(),
            Ok(AllowTarget::Ip("203.0.113.1".into()))
        );
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
        };
        a.clamp_policy_sel();
        assert_eq!(a.policy_sel, Some(0));
        // Emptying the list releases the selection entirely.
        a.policy = PolicyView {
            version: 3,
            rules: vec![],
        };
        a.clamp_policy_sel();
        assert_eq!(a.policy_sel, None);
    }
}
