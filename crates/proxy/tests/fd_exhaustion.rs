//! Running out of file descriptors must not end the proxy's accept loop, since
//! the supervisor powers the guest off when it ends. Its own test binary because
//! it lowers the fd limit of the whole process.

use std::fs::File;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use sodabox_proxy::tcp::{DialFuture, Dialer, TransparentProxy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Dials a fixed echo server, whatever the destination.
struct EchoDialer(SocketAddr);

impl Dialer for EchoDialer {
    fn dial(&self, _dst: SocketAddr) -> DialFuture {
        let target = self.0;
        Box::pin(async move { TcpStream::connect(target).await })
    }
}

async fn spawn_echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

fn lower_fd_limit(soft: u64) {
    use nix::libc;
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: both calls only read or write the local `limit`.
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
        limit.rlim_cur = soft;
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limit), 0);
    }
}

#[tokio::test]
async fn accept_loop_survives_running_out_of_fds() {
    let dialer = Arc::new(EchoDialer(spawn_echo().await));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = TransparentProxy::new(listener, dialer);
    let paddr = proxy.local_addr().unwrap();
    let serving = tokio::spawn(proxy.serve());

    // Use up every fd but one, which the client takes: the proxy's accept of it
    // then fails with EMFILE.
    lower_fd_limit(128);
    let mut hogs = Vec::new();
    let exhausted = loop {
        match File::open("/dev/null") {
            Ok(f) => hogs.push(f),
            Err(e) => break e,
        }
    };
    assert_eq!(exhausted.raw_os_error(), Some(nix::libc::EMFILE));
    assert!(hogs.pop().is_some());
    let mut client = TcpStream::connect(paddr).await.unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!serving.is_finished(), "EMFILE ended the accept loop");

    // Fds free up and the waiting connection is served after all.
    hogs.clear();
    client.write_all(b"still here").await.unwrap();
    let mut reply = [0u8; 10];
    tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut reply))
        .await
        .expect("the waiting connection was never served")
        .unwrap();
    assert_eq!(&reply, b"still here");
    assert!(!serving.is_finished());
}
