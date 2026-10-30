//! DNS front-end: the per-VM UDP listener that receives guest queries passt
//! forwards into the netns (ADR-0005, spike 0002).
//!
//! passt is configured with `--dns-forward <addr>` (the resolver address the
//! guest is handed) and `-D <this listener>` so guest DNS lands here. This module
//! owns only the transport + parse + dispatch: it reads a datagram, parses the
//! question ([`crate::wire`]), asks a [`QueryHandler`] for a verdict, and writes
//! the response back to the guest. The verdict logic — allowlist REFUSED,
//! upstream resolution, ephemeral admission — lives
//! behind the handler.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::wire::{self, Query};

/// Max UDP DNS payload we accept/parse. Guest queries are tiny; anything larger
/// is not a legitimate question and is dropped.
const MAX_UDP: usize = 1232;

/// What a handler decides to send back. Returning `Drop` sends nothing (the
/// guest resolver will time out) — used for unparseable/hostile input.
pub enum Response {
    /// A fully-built DNS response payload.
    Packet(Vec<u8>),
    /// Send no reply.
    Drop,
}

pub type HandleFuture = Pin<Box<dyn Future<Output = Response> + Send>>;

/// Produces a response for a parsed query. Implemented by the filtering resolver;
/// tests use small stand-ins.
pub trait QueryHandler: Send + Sync + 'static {
    fn handle(&self, query: Query, client: SocketAddr) -> HandleFuture;
}

/// The UDP DNS front-end.
pub struct DnsFrontend {
    socket: Arc<UdpSocket>,
}

impl DnsFrontend {
    /// Bind the listener. In production this is the in-netns resolver address
    /// passt forwards to (e.g. `10.0.2.3:53` / a private loopback addr).
    pub async fn bind(addr: SocketAddr) -> io::Result<DnsFrontend> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(DnsFrontend {
            socket: Arc::new(socket),
        })
    }

    /// Adopt an already-bound `std` UDP socket. The supervisor's netns child
    /// creates the resolver's listener inside the VM netns and passes its
    /// fd to the host-netns parent, which builds it back into a socket and hands
    /// it here — so the listener keeps receiving passt's in-netns forwarded
    /// queries while the resolver's own upstream lookups go out the host netns.
    /// Must be called on a tokio runtime.
    pub fn from_std(socket: std::net::UdpSocket) -> io::Result<DnsFrontend> {
        socket.set_nonblocking(true)?;
        Ok(DnsFrontend {
            socket: Arc::new(UdpSocket::from_std(socket)?),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Receive-and-respond loop. Each query is handled on its own task so a slow
    /// upstream does not stall other guests' lookups. Returns only on a
    /// fatal socket error.
    pub async fn serve<H: QueryHandler>(self, handler: Arc<H>) -> io::Result<()> {
        let mut buf = vec![0u8; MAX_UDP];
        loop {
            let (n, peer) = self.socket.recv_from(&mut buf).await?;
            let datagram = &buf[..n];

            let query = match wire::parse_query(datagram) {
                Ok(q) => q,
                Err(_) => continue, // malformed / not-a-query: ignore
            };

            let socket = self.socket.clone();
            let handler = handler.clone();
            tokio::spawn(async move {
                match handler.handle(query, peer).await {
                    Response::Packet(bytes) => {
                        let _ = socket.send_to(&bytes, peer).await;
                    }
                    Response::Drop => {}
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{build_response, Answer, RecordData, RCODE_REFUSED, TYPE_A};
    use std::net::Ipv4Addr;

    /// A handler that REFUSES anything except a single allowed name, which it
    /// answers with a fixed A record — enough to exercise the transport both ways.
    struct StubHandler {
        allow: &'static str,
        ip: Ipv4Addr,
    }
    impl QueryHandler for StubHandler {
        fn handle(&self, query: Query, _client: SocketAddr) -> HandleFuture {
            let allow = self.allow;
            let ip = self.ip;
            Box::pin(async move {
                if query.question.name == allow {
                    let ans = vec![Answer {
                        name: allow.into(),
                        ttl: 60,
                        data: RecordData::A(ip),
                    }];
                    Response::Packet(build_response(&query, 0, &ans))
                } else {
                    Response::Packet(build_response(&query, RCODE_REFUSED, &[]))
                }
            })
        }
    }

    fn raw_query(id: u16, name: &str) -> Vec<u8> {
        // Mirror wire::tests::raw_query for an A/IN question with RD.
        let mut b = Vec::new();
        b.extend_from_slice(&id.to_be_bytes());
        b.extend_from_slice(&(1u16 << 8).to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        for label in name.split('.') {
            b.push(label.len() as u8);
            b.extend_from_slice(label.as_bytes());
        }
        b.push(0);
        b.extend_from_slice(&TYPE_A.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b
    }

    #[tokio::test]
    async fn serves_allow_and_refuse_over_udp() {
        let front = DnsFrontend::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = front.local_addr().unwrap();
        let handler = Arc::new(StubHandler {
            allow: "ok.test",
            ip: Ipv4Addr::new(1, 2, 3, 4),
        });
        tokio::spawn(front.serve(handler));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(addr).await.unwrap();

        // Allowed name -> NOERROR with the A record.
        client.send(&raw_query(0x01, "ok.test")).await.unwrap();
        let mut buf = [0u8; 512];
        let n = client.recv(&mut buf).await.unwrap();
        let resp = &buf[..n];
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0x01);
        assert_eq!(resp[3] & 0x0f, 0); // NOERROR
        assert!(resp.windows(4).any(|w| w == [1, 2, 3, 4]));

        // Blocked name -> REFUSED, no answers.
        client.send(&raw_query(0x02, "evil.test")).await.unwrap();
        let n = client.recv(&mut buf).await.unwrap();
        let resp = &buf[..n];
        assert_eq!(resp[3] & 0x0f, RCODE_REFUSED);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0);
    }

    #[tokio::test]
    async fn malformed_datagram_is_ignored() {
        let front = DnsFrontend::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = front.local_addr().unwrap();
        let handler = Arc::new(StubHandler {
            allow: "ok.test",
            ip: Ipv4Addr::LOCALHOST,
        });
        tokio::spawn(front.serve(handler));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(addr).await.unwrap();
        client.send(b"\x00\x01\x02").await.unwrap(); // junk, < header

        // A valid query afterwards still gets served (the loop survived).
        client.send(&raw_query(0x09, "ok.test")).await.unwrap();
        let mut buf = [0u8; 512];
        client.recv(&mut buf).await.unwrap();
        assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 0x09);
    }
}
