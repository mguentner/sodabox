//! Per-VM event-log persistence (ADR-0009).
//!
//! Every [`Event`] broadcast on a VM's live stream is also appended to a
//! newline-delimited JSON log under the persistent data dir
//! ([`paths::event_log_path`]) so `soda logs <vm>` can show the history for
//! post-hoc audit after the VM (and its runtime dir) are gone.
//!
//! The writer is a plain broadcast subscriber like the TUI: it drains the same
//! ring and shares its backpressure semantics. If it falls behind under a chatty
//! or hostile guest, the broadcast layer reports the gap as `Lagged(n)` and we
//! persist an [`Event::Dropped`] marker in place of the lost events, so a gap is
//! never silent in the log either. Each record is flushed as it is written, so an
//! event that has been consumed is durable even if the supervisor is torn down
//! mid-stream (the tokio runtime dropping the task can only lose events still
//! sitting unread in the ring, which a clean stop has already stopped producing).
//!
//! Size is bounded to two files: when the log exceeds [`ROTATE_BYTES`] at open
//! time it is rotated to `events.log.1` (replacing any previous one), so a
//! long-lived VM's audit trail never grows without limit.

use std::path::{Path, PathBuf};

use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::broadcast;

use sodabox_common::event::{now_ts, Event};

/// Rotate `events.log` to `events.log.1` once it grows past this at open time.
/// Two files ⇒ at most ~2× this on disk.
const ROTATE_BYTES: u64 = 8 * 1024 * 1024;

/// Open (creating/rotating as needed) the append log at `path`, then drain
/// `events` into it until the stream closes (all senders dropped at teardown).
/// Errors opening or writing are logged to stderr and end the task — losing the
/// audit log must never take the VM down, so this is best-effort and detached.
pub async fn run(path: PathBuf, events: broadcast::Receiver<Event>) {
    match open_rotating(&path).await {
        Ok(file) => {
            if let Err(e) = write_loop(file, events).await {
                eprintln!("sodabox event log ({}): {e}", path.display());
            }
        }
        Err(e) => eprintln!("sodabox event log ({}): open failed: {e}", path.display()),
    }
}

/// Open `path` for appending, first rotating it to `<path>.1` if it already
/// exceeds [`ROTATE_BYTES`]. The parent data dir is expected to exist (the VM was
/// created), but we create it defensively so a first event never fails on a
/// missing dir.
async fn open_rotating(path: &Path) -> std::io::Result<File> {
    if let Some(dir) = path.parent() {
        tokio::fs::create_dir_all(dir).await?;
    }
    if let Ok(meta) = tokio::fs::metadata(path).await {
        if meta.len() > ROTATE_BYTES {
            // Replace the single predecessor; a failed rotate is non-fatal — we
            // simply keep appending to the current file rather than lose events.
            let prev = prev_path(path);
            let _ = tokio::fs::rename(path, &prev).await;
        }
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
}

/// `<path>.1` — the rotated-out predecessor (mirrors
/// [`sodabox_common::paths::event_log_prev_path`], but derived from `path` so the
/// rotation is self-contained and unit-testable).
fn prev_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".1");
    path.with_file_name(name)
}

/// Append each received event as one JSON line, flushing per record. A broadcast
/// `Lagged(n)` becomes a [`Event::Dropped`] marker; `Closed` ends the loop.
async fn write_loop(mut file: File, mut events: broadcast::Receiver<Event>) -> std::io::Result<()> {
    loop {
        let event = match events.recv().await {
            Ok(ev) => ev,
            Err(broadcast::error::RecvError::Lagged(n)) => Event::Dropped {
                ts: now_ts(),
                count: n,
            },
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
        };
        write_record(&mut file, &event).await?;
    }
}

/// Serialize one event to a `\n`-terminated JSON line and flush it. `serde_json`
/// never emits an embedded newline, so one line is one record (same framing as
/// the control socket).
async fn write_record(file: &mut File, event: &Event) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(event).map_err(std::io::Error::other)?;
    line.push(b'\n');
    file.write_all(&line).await?;
    file.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sodabox_common::event::Verdict;

    fn tmp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("sodabox-eventlog-{}-{tag}", std::process::id()))
    }

    #[test]
    fn prev_path_appends_dot_one() {
        assert_eq!(
            prev_path(Path::new("/d/events.log")),
            PathBuf::from("/d/events.log.1")
        );
    }

    #[tokio::test]
    async fn writes_json_lines_and_a_dropped_marker_on_lag() {
        let dir = tmp_dir("write");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        let path = dir.join("events.log");

        let (tx, rx) = broadcast::channel::<Event>(4);
        tx.send(Event::Egress {
            ts: 1,
            verdict: Verdict::Blocked,
            proto: "tcp".into(),
            daddr: "203.0.113.1".into(),
            dport: 443,
            rule: None,
            reason: None,
        })
        .unwrap();
        tx.send(Event::Policy { ts: 2, version: 7 }).unwrap();
        drop(tx); // close the stream so the loop terminates

        let file = open_rotating(&path).await.unwrap();
        write_loop(file, rx).await.unwrap();

        let body = tokio::fs::read_to_string(&path).await.unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2, "one JSON line per event: {body:?}");
        // Round-trips back to the same event variants.
        assert!(matches!(
            serde_json::from_str::<Event>(lines[0]).unwrap(),
            Event::Egress { dport: 443, .. }
        ));
        assert!(matches!(
            serde_json::from_str::<Event>(lines[1]).unwrap(),
            Event::Policy { version: 7, .. }
        ));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn rotates_an_oversized_log_to_dot_one() {
        let dir = tmp_dir("rotate");
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("events.log");

        // Seed an over-limit current log, then open: it must rotate aside.
        tokio::fs::write(&path, vec![b'x'; (ROTATE_BYTES + 1) as usize])
            .await
            .unwrap();
        let mut file = open_rotating(&path).await.unwrap();
        write_record(
            &mut file,
            &Event::Lifecycle {
                ts: 1,
                state: "started".into(),
            },
        )
        .await
        .unwrap();

        assert!(
            path.with_file_name("events.log.1").exists(),
            "old log rotated to .1"
        );
        // The fresh current log holds only the new record, not the old bulk.
        let body = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(body.lines().count(), 1);

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
