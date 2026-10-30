//! UDP reply injection across the fork split (ADR-0004).
//!
//! The filter proxy runs in the **host** netns, but a UDP reply must re-enter the
//! guest with its source forged to the original destination (`dst:port`) — passt's
//! connected outbound socket accepts nothing else. Forging that source needs an
//! `IP_TRANSPARENT` socket bound to `dst` **inside the VM netns**, which the
//! rootless host-netns proxy cannot create (it holds no privilege in the child's
//! user namespace).
//!
//! So the split: the host-netns proxy ([`sodabox_proxy::udp`]) decides + dials +
//! relays, and hands each reply to a [`ChannelReplySink`] which frames it onto a
//! `SOCK_DGRAM` unix socketpair. The netns child runs [`run_injector`] on that
//! socketpair, owns the transparent send, and injects the datagram so passt (and
//! thus the guest) sees it arrive from `dst`.
//!
//! Frame = `guest(6) | src(6) | payload`, where each address is 4 IPv4 octets +
//! big-endian port; one datagram per reply (SOCK_DGRAM preserves boundaries).

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::net::UnixDatagram;

use socket2::{Domain, Protocol, Socket, Type};

use sodabox_proxy::udp::ReplySink;

/// Fixed frame header: two IPv4 socket addresses (6 bytes each).
const HEADER: usize = 12;
/// Max reply payload we relay (matches the proxy's `MAX_UDP`).
const MAX_PAYLOAD: usize = 65_535;
/// Bound on distinct forged-source sockets the injector caches (fail-safe against
/// a guest that scatters replies across many destinations).
const MAX_INJECT_SOCKETS: usize = 1024;

fn encode(buf: &mut Vec<u8>, guest: SocketAddrV4, src: SocketAddrV4, payload: &[u8]) {
    buf.clear();
    buf.extend_from_slice(&guest.ip().octets());
    buf.extend_from_slice(&guest.port().to_be_bytes());
    buf.extend_from_slice(&src.ip().octets());
    buf.extend_from_slice(&src.port().to_be_bytes());
    buf.extend_from_slice(payload);
}

fn decode(frame: &[u8]) -> Option<(SocketAddrV4, SocketAddrV4, &[u8])> {
    if frame.len() < HEADER {
        return None;
    }
    let addr = |o: usize| {
        let ip = Ipv4Addr::new(frame[o], frame[o + 1], frame[o + 2], frame[o + 3]);
        let port = u16::from_be_bytes([frame[o + 4], frame[o + 5]]);
        SocketAddrV4::new(ip, port)
    };
    Some((addr(0), addr(6), &frame[HEADER..]))
}

/// Parent-side [`ReplySink`]: frames each reply and sends it to the netns child
/// over the connected socketpair. Best-effort — a full/broken channel drops the
/// datagram (UDP semantics), never blocks the async relay.
pub struct ChannelReplySink {
    chan: UnixDatagram,
}

impl ChannelReplySink {
    /// `chan` must be the parent end of the injector socketpair, set nonblocking.
    pub fn new(chan: UnixDatagram) -> Self {
        Self { chan }
    }
}

impl ReplySink for ChannelReplySink {
    fn inject(&self, guest: SocketAddrV4, src: SocketAddrV4, payload: &[u8]) {
        // Oversized payloads cannot be a legitimate single UDP datagram anyway.
        if payload.len() > MAX_PAYLOAD {
            return;
        }
        // A small per-call buffer; the framing is tiny relative to the payload.
        let mut buf = Vec::with_capacity(HEADER + payload.len());
        encode(&mut buf, guest, src, payload);
        let _ = self.chan.send(&buf); // nonblocking; drop on WouldBlock/closed
    }
}

/// Child-side loop (runs in the VM netns, holds CAP_NET_ADMIN): read framed
/// replies from `chan` and inject each so it appears to originate from `src`.
/// Returns only when the channel closes (the parent is gone) or on a fatal error.
pub fn run_injector(chan: UnixDatagram) -> io::Result<()> {
    let mut buf = vec![0u8; HEADER + MAX_PAYLOAD];
    // One forged-source socket per distinct `src` (dst:port), reused across replies.
    let mut sockets: HashMap<SocketAddrV4, UnixSock> = HashMap::new();

    loop {
        let n = match chan.recv(&mut buf) {
            Ok(0) => return Ok(()), // peer closed
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let Some((guest, src, payload)) = decode(&buf[..n]) else {
            continue; // truncated/garbage frame
        };

        let sock = match sockets.get(&src) {
            Some(s) => s,
            None => {
                if sockets.len() >= MAX_INJECT_SOCKETS {
                    // Simplest bound: clear the cache rather than track LRU in the
                    // child. Rebinding on the next reply is cheap and rare.
                    sockets.clear();
                }
                match transparent_bound(src) {
                    Ok(s) => sockets.entry(src).or_insert(s),
                    Err(e) => {
                        eprintln!("udp inject: bind {src} failed: {e}");
                        continue;
                    }
                }
            }
        };
        if let Err(e) = sock.send_to(payload, guest) {
            eprintln!("udp inject: send to {guest} from {src} failed: {e}");
        }
    }
}

/// A blocking `std` UDP socket bound `IP_TRANSPARENT` to a (possibly nonlocal)
/// address so datagrams it sends carry that address as their source.
type UnixSock = std::net::UdpSocket;

fn transparent_bound(src: SocketAddrV4) -> io::Result<UnixSock> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    // IP_TRANSPARENT permits binding to `src` even though it is not a local
    // address, and stamps outgoing datagrams with it as the source.
    sock.set_ip_transparent(true)?;
    sock.bind(&std::net::SocketAddr::V4(src).into())?;
    Ok(sock.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrips() {
        let guest = SocketAddrV4::new(Ipv4Addr::new(10, 255, 255, 53), 40001);
        let src = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 443);
        let mut buf = Vec::new();
        encode(&mut buf, guest, src, b"hello-quic");
        let (g, s, p) = decode(&buf).expect("decode");
        assert_eq!(g, guest);
        assert_eq!(s, src);
        assert_eq!(p, b"hello-quic");
    }

    #[test]
    fn decode_rejects_short_frame() {
        assert!(decode(&[0u8; HEADER - 1]).is_none());
    }

    #[test]
    fn sink_frames_onto_channel() {
        // The parent sink writes a frame the child decodes identically.
        let (parent, child) = UnixDatagram::pair().unwrap();
        parent.set_nonblocking(true).unwrap();
        let sink = ChannelReplySink::new(parent);
        let guest = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5555);
        let src = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53);
        sink.inject(guest, src, b"reply");

        let mut buf = vec![0u8; 128];
        let n = child.recv(&mut buf).unwrap();
        let (g, s, p) = decode(&buf[..n]).unwrap();
        assert_eq!((g, s, p), (guest, src, b"reply".as_slice()));
    }
}
