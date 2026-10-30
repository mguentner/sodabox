//! `SCM_RIGHTS` file-descriptor passing over a unix socket.
//!
//! The fork-split supervisor (ADR-0004/0007) runs the filter
//! proxy and DNS resolver in the **host** network namespace so their dials reach
//! the internet, but their *listening* sockets must be created inside the VM
//! netns (the TPROXY TCP listener needs `IP_TRANSPARENT`/CAP_NET_ADMIN there; the
//! resolver's UDP listener must receive passt's forwarded queries in-netns). A
//! socket stays bound to the netns it was created in even after its fd moves, so
//! the netns child creates those listeners and hands their fds to the host parent
//! over a `socketpair` via `SCM_RIGHTS`.
//!
//! This module is that primitive: [`send_fds`] / [`recv_fds`] over a blocking
//! `std` [`UnixStream`] (the handoff happens during the synchronous pre-tokio
//! bootstrap, so blocking I/O is correct here). Received fds arrive
//! close-on-exec. A fixed, ordered set is wrapped by [`Listeners`] so the two
//! sides agree on which fd is which without a framing protocol.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags};

/// Send one or more file descriptors over `sock` as a single `SCM_RIGHTS`
/// message. A one-byte payload accompanies the ancillary data (a message with no
/// data bytes can be dropped by the kernel, taking the fds with it).
pub fn send_fds(sock: &UnixStream, fds: &[BorrowedFd<'_>]) -> io::Result<()> {
    if fds.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "send_fds: no fds to send",
        ));
    }
    let raw: Vec<RawFd> = fds.iter().map(AsRawFd::as_raw_fd).collect();
    let cmsgs = [ControlMessage::ScmRights(&raw)];
    let payload = [0u8; 1];
    let iov = [io::IoSlice::new(&payload)];
    sendmsg::<()>(sock.as_raw_fd(), &iov, &cmsgs, MsgFlags::empty(), None).map_err(errno)?;
    Ok(())
}

/// Receive up to `max_fds` descriptors from a single `SCM_RIGHTS` message on
/// `sock`. Returned fds are owned (closed on drop) and `CLOEXEC`. Errors if the
/// message carried no descriptors.
pub fn recv_fds(sock: &UnixStream, max_fds: usize) -> io::Result<Vec<OwnedFd>> {
    let mut payload = [0u8; 1];
    let mut iov = [io::IoSliceMut::new(&mut payload)];
    // Space for up to `max_fds` RawFds of ancillary data.
    let space = unsafe {
        nix::libc::CMSG_SPACE((max_fds * std::mem::size_of::<RawFd>()) as nix::libc::c_uint)
    } as usize;
    let mut cmsg_space = vec![0u8; space];

    // MSG_CMSG_CLOEXEC so a racing exec in another thread can't leak these fds.
    let msg = recvmsg::<()>(
        sock.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_space),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )
    .map_err(errno)?;

    let mut out = Vec::new();
    for cmsg in msg.cmsgs().map_err(errno)? {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            // SAFETY: the kernel just installed these as fresh, owned fds in this
            // process; nobody else holds them.
            out.extend(
                fds.into_iter()
                    .map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }),
            );
        }
    }
    if out.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "recv_fds: peer sent no SCM_RIGHTS descriptors",
        ));
    }
    Ok(out)
}

/// The fixed set of listener fds the netns child hands to the host parent, in a
/// stable order so no framing is needed.
pub struct Listeners {
    /// TPROXY transparent-TCP listener (the filter proxy's accept socket).
    pub tproxy_tcp: OwnedFd,
    /// The DNS resolver's UDP listener (passt forwards guest queries here).
    pub resolver_udp: OwnedFd,
    /// TPROXY transparent-UDP listener (the filter proxy's UDP datagram socket).
    /// Diverted guest UDP arrives here for original-dst recovery.
    pub tproxy_udp: OwnedFd,
}

impl Listeners {
    /// Order the fds travel in.
    const COUNT: usize = 3;

    /// Send all listeners (child side).
    pub fn send(
        sock: &UnixStream,
        tproxy_tcp: BorrowedFd<'_>,
        resolver_udp: BorrowedFd<'_>,
        tproxy_udp: BorrowedFd<'_>,
    ) -> io::Result<()> {
        send_fds(sock, &[tproxy_tcp, resolver_udp, tproxy_udp])
    }

    /// Receive all listeners (parent side), in the order [`Listeners::send`] used.
    pub fn recv(sock: &UnixStream) -> io::Result<Self> {
        let mut fds = recv_fds(sock, Self::COUNT)?;
        if fds.len() != Self::COUNT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected {} listener fds, got {}", Self::COUNT, fds.len()),
            ));
        }
        // Reverse-pop preserves send order.
        let tproxy_udp = fds.pop().unwrap();
        let resolver_udp = fds.pop().unwrap();
        let tproxy_tcp = fds.pop().unwrap();
        Ok(Self {
            tproxy_tcp,
            resolver_udp,
            tproxy_udp,
        })
    }
}

fn errno(e: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::AsFd;

    /// Passing a socket's fd and then exchanging bytes proves the *same* kernel
    /// object crossed the boundary (SCM_RIGHTS is valid in-process too).
    #[test]
    fn round_trips_a_live_socket_fd() {
        let (a, b) = UnixStream::pair().unwrap();

        // Payload socket to hand across: write on `far`, expect to read it out of
        // whatever fd the receiver gets for `near`.
        let (near, mut far) = UnixStream::pair().unwrap();

        send_fds(&a, &[near.as_fd()]).unwrap();
        let mut got = recv_fds(&b, 1).unwrap();
        assert_eq!(got.len(), 1);

        // Turn the received fd back into a socket and prove identity with `near`.
        let mut received: UnixStream = got.pop().unwrap().into();
        far.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        received.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");

        // Keep `near` alive until after the exchange.
        drop(near);
    }

    #[test]
    fn passes_multiple_fds_in_order() {
        let (a, b) = UnixStream::pair().unwrap();

        let (one, mut one_far) = UnixStream::pair().unwrap();
        let (two, mut two_far) = UnixStream::pair().unwrap();
        let (three, mut three_far) = UnixStream::pair().unwrap();

        Listeners::send(&a, one.as_fd(), two.as_fd(), three.as_fd()).unwrap();
        let listeners = Listeners::recv(&b).unwrap();

        // First fd == `one`.
        let mut got_one: UnixStream = listeners.tproxy_tcp.into();
        one_far.write_all(b"1").unwrap();
        let mut buf = [0u8; 1];
        got_one.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"1");

        // Second fd == `two`.
        let mut got_two: UnixStream = listeners.resolver_udp.into();
        two_far.write_all(b"2").unwrap();
        got_two.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"2");

        // Third fd == `three`.
        let mut got_three: UnixStream = listeners.tproxy_udp.into();
        three_far.write_all(b"3").unwrap();
        got_three.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"3");

        drop((one, two, three));
    }

    #[test]
    fn sending_no_fds_is_rejected() {
        let (a, _b) = UnixStream::pair().unwrap();
        let err = send_fds(&a, &[]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
