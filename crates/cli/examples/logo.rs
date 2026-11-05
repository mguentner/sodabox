//! Debug the Status panel's logo in isolation: probe the kitty graphics
//! protocol, then bisect the transmit with acked experiments — each hermetic
//! (every image wiped first, storage verified immediately by a 1×1 placement
//! far off-screen) so the experiments can't contaminate each other. e1 is the
//! TUI's exact bytes; the others change one suspect at a time. The demo then
//! re-transmits the TUI's bytes fresh and places them at the Status panel's
//! size and big, framed so the covered cells are visible even where the
//! image isn't.
//!
//! ```text
//! cargo run -p sodabox-cli --example logo
//! ```

use std::io::{IsTerminal, Read, Write};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use ratatui::crossterm::terminal::{disable_raw_mode, enable_raw_mode};

/// The logo, as the TUI embeds it.
const LOGO_PNG: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../assets/logo_120x256.png"
));
/// The logo PNG's pixel size — the aspect reference for cell sizing.
const LOGO_W: u32 = 120;
const LOGO_H: u32 = 256;

/// The TUI's `logo_cols`: cell columns the logo spans at `rows` cell rows
/// (terminal cells are about twice as tall as wide).
fn logo_cols(rows: u16) -> u16 {
    ((u32::from(rows) * 2 * LOGO_W + LOGO_H / 2) / LOGO_H) as u16
}

fn main() {
    if !std::io::stdin().is_terminal() {
        eprintln!("run me in a terminal: cargo run -p sodabox-cli --example logo");
        return;
    }
    if enable_raw_mode().is_err() {
        eprintln!("cannot put the terminal in raw mode");
        return;
    }

    // One reader thread owns stdin for the whole run, so the probe, the ack
    // reads and the key wait can't race each other for bytes.
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 64];
        while let Ok(n) = stdin.read(&mut buf) {
            if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });

    // 1. Probe, as `detect_graphics` does.
    let reply = probe(&rx);
    if find(&reply, b"\x1b_G").is_none() {
        let _ = disable_raw_mode();
        eprintln!("graphics protocol: NOT detected");
        eprintln!("  reply ({} bytes): {}", reply.len(), show(&reply));
        if reply.is_empty() {
            eprintln!(
                "  nothing answered at all — the terminal doesn't implement the kitty\n  \
                 graphics protocol (xterm, gnome-terminal, alacritty, iTerm2, …), or\n  \
                 something between you and it ate the query"
            );
        } else {
            eprintln!(
                "  only the device attributes came back — the terminal ignored the\n  \
                 graphics query"
            );
        }
        if std::env::var_os("TMUX").is_some() {
            eprintln!(
                "  tmux is running: it swallows graphics escapes unless\n  \
                 `set -g allow-passthrough on` and DCS wrapping are configured"
            );
        }
        eprintln!("  env: TERM={} TMUX={}", env("TERM"), env("TMUX"));
        return;
    }

    // 2. Bisect the transmit, each experiment hermetic: wipe every image id
    //    first (a delete also aborts any half-finished chunked load), then
    //    transmit, then verify storage immediately with a 1×1 placement far
    //    off-screen — its ack is the verdict. q≥1 suppresses transmit acks,
    //    so a missing one there is expected. e1 is the TUI's exact bytes;
    //    the others change one suspect at a time.
    let b64 = base64(LOGO_PNG);
    let plan = [
        ("the TUI's exact bytes: id 1, q=2", 1u32, "f=100,q=2"),
        ("the same, without q: id 2", 2, "f=100"),
        ("the same, id 999 instead of 1", 999, "f=100,q=2"),
        ("control: id 777, no q", 777, "f=100"),
    ];
    let ids = plan.map(|p| p.1);
    let mut results = Vec::new();
    for (name, id, keys) in plan {
        wipe(ids);
        transmit(id, keys, b64.as_bytes(), 4096);
        let tx = read_ack(&rx, Duration::from_millis(400));
        place(id, 1, 200, 1, 1, 1); // off-screen: only its ack matters
        let stored = read_ack(&rx, Duration::from_millis(400));
        results.push((name, id, keys, tx, stored));
    }

    // 3. Report the bisect.
    let mut out = std::io::stdout();
    let _ = write!(out, "\x1b[2J"); // clear
    label(1, "sodabox logo debug — graphics protocol detected");
    label(2, &format!("probe reply: {}", show(&reply)));
    label(
        3,
        &format!(
            "env: TERM={} TMUX={} TERM_PROGRAM={}",
            env("TERM"),
            env("TMUX"),
            env("TERM_PROGRAM")
        ),
    );
    label(
        4,
        "experiments, each wiped first — transmit ack · stored-probe ack:",
    );
    for (i, (name, _, _, tx, stored)) in results.iter().enumerate() {
        label(
            5 + i as u16,
            &format!("  e{} {} → {} · {}", i + 1, name, ack(tx), ack(stored)),
        );
    }
    let stored = |i: usize| results[i].4.clone();
    label(
        10,
        &if ok(&stored(0)) {
            "the TUI's exact transmit stores on this terminal — an earlier \
             ENOENT was cross-talk between experiments, not the TUI"
                .to_string()
        } else if ok(&stored(1)) {
            "q on the transmit breaks it — the TUI should drop q=2 from \
             transmit_logo"
                .to_string()
        } else if ok(&stored(2)) {
            "image id 1 breaks it — the TUI should pick another LOGO_ID".to_string()
        } else {
            "NOTHING stored — the transmit itself is broken on this terminal".to_string()
        },
    );

    // 4. Demo: re-transmit the TUI's exact bytes — fresh, after a wipe — and
    //    place: a probe first, then the Status panel's size and a big one.
    let (_, id, keys, _, _) = results[0];
    wipe(ids);
    transmit(id, keys, b64.as_bytes(), 4096);
    let _ = read_ack(&rx, Duration::from_millis(400)); // expected: none (q=2)
    place(id, 1, 200, 1, 1, 1);
    let probe = read_ack(&rx, Duration::from_millis(400));
    label(
        12,
        &format!(
            "demo — the TUI's bytes re-transmitted (id {id}, {keys}): probe → {}",
            ack(&probe)
        ),
    );

    let (w, h) = (logo_cols(4), 4);
    label(
        13,
        &format!("the Status panel's placement — {h} rows × {w} cols, letterboxed, at the right:"),
    );
    label(
        14,
        &format!("  escape: \\x1b[16;40H\\x1b_Ga=p,i={id},p=1,q=2,c={w},r={h}\\x1b\\\\"),
    );
    frame(16, 40, w, h);
    place(id, 1, 16, 40, w, h);
    let ack1 = read_ack(&rx, Duration::from_millis(300));
    label(21, &format!("  placement ack: {}", ack(&ack1)));

    let (w, h) = (logo_cols(16), 16);
    label(23, &format!("a big one — {h} rows × {w} cols:"));
    frame(25, 40, w, h);
    // p=2: the same image, but a distinct placement — the same (id, p) pair
    // would replace the small placement above.
    place(id, 2, 25, 40, w, h);
    let ack2 = read_ack(&rx, Duration::from_millis(300));
    label(42, &format!("  placement ack: {}", ack(&ack2)));
    label(
        43,
        "the PNG should show inside each frame; enter or q deletes and exits",
    );
    let _ = out.flush();

    // 5. Wait for a key, then free every image we transmitted.
    wait_key(&rx);
    wipe(ids);
    let _ = write!(out, "\x1b[45;1H");
    let _ = out.flush();
    let _ = disable_raw_mode();
    println!("deleted the transmitted images — the frames should have stayed");
}

/// Delete every image id we use (also aborts half-finished chunked loads).
fn wipe(ids: [u32; 4]) {
    let mut out = std::io::stdout();
    for id in ids {
        let _ = write!(out, "\x1b_Ga=d,d=I,i={id}\x1b\\");
    }
    let _ = out.flush();
}

/// The TUI's `detect_graphics`, but the raw reply is handed back for display:
/// write the graphics query + primary DA, then drain stdin until a graphics
/// reply, a DA reply, or the deadline.
fn probe(rx: &Receiver<Vec<u8>>) -> Vec<u8> {
    let mut out = std::io::stdout();
    let _ = out.write_all(b"\x1b_Gi=31,s=1,v=1,a=q,t=d,f=24;AAAA\x1b\\\x1b[c");
    let _ = out.flush();

    let deadline = Instant::now() + Duration::from_millis(500);
    let mut seen = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match rx.recv_timeout(left) {
            Ok(bytes) => seen.extend_from_slice(&bytes),
            Err(_) => break,
        }
        // A complete graphics reply (ESC _ G … ESC \ ) or a complete DA reply
        // (ESC [ ? … c) settles it.
        if let Some(p) = find(&seen, b"\x1b_G") {
            if find(&seen[p + 3..], b"\x1b\\").is_some() {
                break;
            }
        }
        if let Some(p) = find(&seen, b"\x1b[?") {
            if seen[p + 3..].contains(&b'c') {
                break;
            }
        }
    }
    seen
}

/// The next graphics acknowledgement (`ESC _ G … ESC \`), or `None` on
/// timeout. Non-graphics bytes (a late DA reply, stray keys) are skipped.
fn read_ack(rx: &Receiver<Vec<u8>>, timeout: Duration) -> Option<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    let mut seen = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        match rx.recv_timeout(left) {
            Ok(bytes) => seen.extend_from_slice(&bytes),
            Err(_) => return None,
        }
        if let Some(p) = find(&seen, b"\x1b_G") {
            if let Some(q) = find(&seen[p + 3..], b"\x1b\\") {
                return Some(seen[p..p + 3 + q + 2].to_vec());
            }
        }
    }
}

/// Human form of an ack: `OK`, the error text, or `NO ACK`.
fn ack(ack: &Option<Vec<u8>>) -> String {
    match ack {
        None => "NO ACK".into(),
        Some(bytes) => show(bytes)
            .trim_start_matches("ESC_G")
            .trim_end_matches("ESC\\")
            .to_string(),
    }
}

/// Was the ack an `OK`?
fn ok(ack: &Option<Vec<u8>>) -> bool {
    ack.as_deref().is_some_and(|a| find(a, b";OK").is_some())
}

/// The TUI's `transmit_logo`, generalized: transmit `payload` (already
/// base64) as image `id` with `keys` (e.g. `f=100`), in `chunk`-byte chunks —
/// `0` means one single escape.
fn transmit(id: u32, keys: &str, payload: &[u8], chunk: usize) {
    let mut out = std::io::stdout();
    let mut pos = 0;
    let mut first = true;
    loop {
        let end = if chunk == 0 {
            payload.len()
        } else {
            (pos + chunk).min(payload.len())
        };
        let last = end == payload.len();
        let m = if last { 0 } else { 1 };
        let head = if first {
            format!("a=t,i={id},{keys},")
        } else {
            String::new()
        };
        let _ = write!(
            out,
            "\x1b_G{head}m={m};{}\x1b\\",
            String::from_utf8_lossy(&payload[pos..end])
        );
        pos = end;
        first = false;
        if last {
            break;
        }
    }
    let _ = out.flush();
}

/// The TUI's `place_logo`, generalized with a placement id: cursor to the
/// top-left cell (1-based), then the placement command with the cell
/// rectangle. Distinct placement ids keep multiple placements of the same
/// image from replacing each other.
fn place(id: u32, pid: u32, row: u16, col: u16, w: u16, h: u16) {
    let mut out = std::io::stdout();
    let _ = write!(
        out,
        "\x1b[{row};{col}H\x1b_Ga=p,i={id},p={pid},c={w},r={h}\x1b\\"
    );
    let _ = out.flush();
}

/// Draw a box one cell around the placement rect, so the covered cells stay
/// visible where the terminal can't show the image.
fn frame(row: u16, col: u16, w: u16, h: u16) {
    let mut out = std::io::stdout();
    let horiz = "─".repeat(w as usize);
    let (top, left, right, bottom) = (row - 1, col - 1, col + w, row + h);
    let _ = write!(out, "\x1b[{top};{left}H┌{horiz}┐");
    for r in row..row + h {
        let _ = write!(out, "\x1b[{r};{left}H│\x1b[{r};{right}H│");
    }
    let _ = write!(out, "\x1b[{bottom};{left}H└{horiz}┘");
    let _ = out.flush();
}

/// Write `text` at a 1-based row, column 1.
fn label(row: u16, text: &str) {
    let mut out = std::io::stdout();
    let _ = write!(out, "\x1b[{row};1H{text}");
    let _ = out.flush();
}

/// Block until Enter, `q` or Ctrl-C (raw mode's 0x03).
fn wait_key(rx: &Receiver<Vec<u8>>) {
    while let Ok(bytes) = rx.recv() {
        if bytes
            .iter()
            .any(|&b| matches!(b, b'\r' | b'\n' | b'q' | 0x03))
        {
            return;
        }
    }
}

/// The TUI's `base64` (RFC 4648), verbatim.
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

/// Printable form of raw bytes: `ESC` for the escape byte, other controls as
/// hex, the rest as-is.
fn show(bytes: &[u8]) -> String {
    let mut s = String::new();
    for &b in bytes {
        match b {
            0x1b => s.push_str("ESC"),
            b'\r' => s.push_str("\\r"),
            b'\n' => s.push_str("\\n"),
            0x20..=0x7e => s.push(b as char),
            _ => s.push_str(&format!("\\x{b:02x}")),
        }
    }
    s
}

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| "<unset>".into())
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
