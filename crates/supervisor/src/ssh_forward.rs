//! Host-loopback → guest:22 SSH forward (ADR-0011).
//!
//! # Why a relay
//!
//! passt runs **inside the per-VM network namespace** so its outbound sockets are
//! subject to the nft egress interception ([`crate::netns`], [`crate::passt`]).
//! Its inbound forward (`-t 127.0.0.1/<port>:22`) therefore listens on the
//! *netns* loopback — which the host cannot reach: the netns has only `lo` and a
//! black-hole dummy interface, no veth to the host (that isolation is the
//! enforcement boundary). So we do **not** ask passt to bind a host address.
//! Instead the fork-split supervisor bridges the two loopbacks without adding any
//! host↔netns IP path:
//!
//! ```text
//! ssh client ─▶ 127.0.0.1:<host_port>        (parent, host netns)
//!                     │ accept
//!                     ▼  SCM_RIGHTS(fd)       (existing fork socketpair idiom)
//!               netns child ─▶ 127.0.0.1:<passt_port> ─▶ passt ─▶ guest:22
//! ```
//!
//! An accepted TCP connection's fd works regardless of namespace once
//! established (netns only governs bind/connect/listen), so the parent accepts in
//! the host netns and hands the raw fd to the child, which splices it to passt's
//! in-netns forward. The whole datapath is a single guest NIC (no second,
//! egress-bypassing interface) and needs no privilege.
//!
//! # Which host port
//!
//! `<host_port>` is **not** chosen here. It is allocated once at `soda create`
//! and stored in the VM's `meta.toml` ([`VmMeta::ssh_port`]), so it is stable for
//! the VM's lifetime and unique across VMs — see [`bind_vm_forward`] and
//! ADR-0011's *Port assignment*.

use std::io;
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::thread;

use sodabox_common::vm::VmMeta;

/// The in-netns loopback port passt listens on for the SSH forward
/// (`-t 127.0.0.1/<PASST_SSH_PORT>:22`). The netns is fresh per VM, so this fixed
/// port never collides; it is unrelated to the VM's host-side port.
pub const PASST_SSH_PORT: u16 = 2222;

/// Bind VM `vm`'s host-loopback listener on `assigned` — the port recorded in its
/// `meta.toml` ([`VmMeta::ssh_port`]), which no other VM can be assigned, so a
/// restart always lands on the same port and `ssh.endpoint` never names another
/// VM's forward.
///
/// The one way that port can be unavailable is a process outside sodabox holding
/// it. Then the VM is reassigned the lowest port no other VM owns and **that is
/// persisted** (printed, since the port is user-visible): the alternative — a
/// per-boot slide that is not written down — is what let a stale `ssh.endpoint`
/// point at a live, unrelated VM. `bind()` itself is the only arbiter, so two
/// VMs reallocating at once cannot agree on the same port.
pub fn bind_vm_forward(vm: &str, assigned: u16) -> io::Result<(TcpListener, u16)> {
    let mut want = assigned;
    let mut occupied: Vec<u16> = Vec::new();
    loop {
        match TcpListener::bind((Ipv4Addr::LOCALHOST, want)) {
            Ok(listener) => {
                if want != assigned {
                    let mut meta = VmMeta::load(vm)?;
                    meta.ssh_port = want;
                    meta.save()?;
                    println!(
                        "soda: ssh port {assigned} is held by another process; \
                         '{vm}' reassigned to {want} (saved)"
                    );
                }
                return Ok((listener, want));
            }
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                occupied.push(want);
                // Avoid both the ports other VMs own and the ones just found
                // occupied; the range is finite, so this terminates. The metadata
                // is only read once the assigned port actually fails, so the
                // common path touches no state at all.
                let mut avoid = VmMeta::ssh_ports_taken(vm)?;
                avoid.extend_from_slice(&occupied);
                want = VmMeta::allocate_ssh_port(vm, &avoid)?;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Parent side (host netns): accept SSH clients on `listener` and hand each
/// accepted connection's fd to the netns child over `fd_sock`, which splices it
/// to passt's in-netns forward. Blocking; runs on its own thread for the VM's
/// lifetime and returns when the listener or the child channel goes away.
pub fn serve_host_listener(listener: TcpListener, fd_sock: UnixStream) {
    for conn in listener.incoming() {
        let conn = match conn {
            Ok(c) => c,
            Err(_) => break, // listener closed / fatal accept error
        };
        // Hand the live fd to the netns child; it dups it and owns the relay.
        if crate::fdpass::send_fds(&fd_sock, &[conn.as_fd()]).is_err() {
            break; // child gone — nothing can service further connections
        }
        // The parent keeps no copy; the child's dup carries the connection.
        drop(conn);
    }
}

/// Child side (VM netns): receive accepted SSH fds from the parent over `fd_sock`
/// and splice each to passt's in-netns forward at `127.0.0.1:<passt_port>`
/// (→ guest:22). Blocking; runs on its own thread and returns when the parent
/// closes the channel (which also happens when the supervisor dies).
pub fn serve_netns_relay(fd_sock: UnixStream, passt_port: u16) {
    loop {
        let mut fds = match crate::fdpass::recv_fds(&fd_sock, 1) {
            Ok(f) => f,
            Err(_) => break, // parent gone
        };
        let Some(fd) = fds.pop() else { continue };
        thread::spawn(move || {
            if let Err(e) = splice_to_passt(fd, passt_port) {
                eprintln!("soda ssh relay: {e}");
            }
        });
    }
}

/// Splice one accepted client connection to passt's in-netns SSH forward.
fn splice_to_passt(client_fd: OwnedFd, passt_port: u16) -> io::Result<()> {
    let client = TcpStream::from(client_fd);
    let upstream = TcpStream::connect((Ipv4Addr::LOCALHOST, passt_port))?;
    splice_bidir(client, upstream)
}

/// Copy bytes both ways between two streams until each direction hits EOF, then
/// half-close the peer so the other end sees the close (graceful teardown).
fn splice_bidir(a: TcpStream, b: TcpStream) -> io::Result<()> {
    let mut a_read = a.try_clone()?;
    let mut b_write = b.try_clone()?;
    let up = thread::spawn(move || {
        let _ = io::copy(&mut a_read, &mut b_write);
        let _ = b_write.shutdown(Shutdown::Write);
    });

    let mut b_read = b;
    let mut a_write = a;
    let _ = io::copy(&mut b_read, &mut a_write);
    let _ = a_write.shutdown(Shutdown::Write);
    let _ = up.join();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn bind_vm_forward_uses_the_assigned_port() {
        // The common path: the assigned port is free, so it is taken verbatim and
        // no metadata is touched (this VM has none on disk — proof we didn't).
        let free = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = free.local_addr().unwrap().port();
        drop(free);

        let vm = format!("sodabox-test-{}", std::process::id());
        let (listener, got) = bind_vm_forward(&vm, port).expect("bind the assigned port");
        assert_eq!(got, port, "must use the assignment, not pick its own port");
        assert_eq!(listener.local_addr().unwrap().port(), port);
    }

    #[test]
    fn bind_vm_forward_fails_rather_than_silently_moving_without_state() {
        // The assigned port is held by someone else and the VM has no meta.toml,
        // so the reassignment cannot be persisted — bind must surface that rather
        // than quietly serve on a port nothing recorded.
        let held = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = held.local_addr().unwrap().port();

        let vm = format!("sodabox-missing-{}", std::process::id());
        let err = bind_vm_forward(&vm, port).expect_err("no state to record a move in");
        assert_eq!(err.kind(), io::ErrorKind::NotFound, "{err}");
        drop(held);
    }

    /// End-to-end relay without KVM/passt: a fake in-"netns" server stands in for
    /// passt's forward target, and we push a real accepted host-loopback fd across
    /// the SCM_RIGHTS channel exactly as the supervisor does, then check bytes flow
    /// both ways.
    #[test]
    fn relay_splices_host_connection_to_the_passt_target() {
        // Fake passt forward target: echoes a suffix so we can prove both directions.
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let passt_port = target.local_addr().unwrap().port();
        let target_thread = thread::spawn(move || {
            let (mut sock, _) = target.accept().unwrap();
            let mut buf = [0u8; 5];
            sock.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"hello");
            sock.write_all(b"world").unwrap();
        });

        // The netns-child relay reads fds from `child` and connects to the target.
        let (parent_sock, child_sock) = UnixStream::pair().unwrap();
        let relay = thread::spawn(move || serve_netns_relay(child_sock, passt_port));

        // Host-loopback listener the "ssh client" connects to.
        let host = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let host_port = host.local_addr().unwrap().port();
        let host_thread = thread::spawn(move || {
            let (conn, _) = host.accept().unwrap();
            crate::fdpass::send_fds(&parent_sock, &[conn.as_fd()]).unwrap();
            // Drop the parent socketpair end so the relay loop ends after this fd.
            drop(conn);
            drop(parent_sock);
        });

        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, host_port)).unwrap();
        client.write_all(b"hello").unwrap();
        let mut got = [0u8; 5];
        client.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"world");

        drop(client);
        target_thread.join().unwrap();
        host_thread.join().unwrap();
        relay.join().unwrap();
    }
}
