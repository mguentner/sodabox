//! nftables egress interception, scoped to the per-VM network namespace
//! (mechanism from spike 0003, ADR-0004).
//!
//! Note: the ticket title said "REDIRECT"; the spike superseded that with
//! **TPROXY** — one mechanism for TCP, UDP and QUIC that recovers the original
//! destination directly (no NAT, no conntrack race). passt's egress is
//! *locally generated* in the netns, so it hits OUTPUT and would skip PREROUTING
//! (where TPROXY is legal). The kernel-documented fix is to **mark in OUTPUT and
//! policy-route the marked packets onto `lo`**, re-entering PREROUTING where the
//! TPROXY verdict diverts them to the in-netns filter proxy.
//!
//! Deny-by-default: unlike the spike's per-dport probe, this intercepts *all*
//! TCP and UDP — the filter proxy is what allows or blocks each
//! connection. `direct_daddrs` (e.g. the in-netns DNS resolver passt forwards
//! to) bypass interception so they are reachable without looping. ICMP has no
//! L4 port to divert, so it is dropped by default (fail-closed).
//!
//! Everything here is confined to the current netns (owned via [`crate::netns`],
//! CAP_NET_ADMIN held there) and touches no host state.

use std::ffi::OsString;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};

/// The fwmark and routing table used to bounce marked egress back onto `lo`.
pub const DEFAULT_MARK: u32 = 0x111;
pub const DEFAULT_TABLE_ID: u32 = 100;
/// Our nft table name in the netns.
pub const NFT_TABLE: &str = "sodabox";

fn nft_bin() -> OsString {
    std::env::var_os("SODABOX_NFT").unwrap_or_else(|| OsString::from("nft"))
}

/// Egress interception parameters for one VM's netns.
#[derive(Debug, Clone)]
pub struct EgressRules {
    pub mark: u32,
    pub table_id: u32,
    /// TPROXY target port for TCP (the filter proxy's transparent TCP listener).
    pub tcp_port: u16,
    /// TPROXY target port for UDP.
    pub udp_port: u16,
    /// Destinations that bypass interception (reached directly), e.g. the
    /// in-netns resolver passt forwards DNS to.
    pub direct_daddrs: Vec<Ipv4Addr>,
    /// Bypass loopback↔loopback traffic (both source and destination in
    /// 127.0.0.0/8) before marking. Needed by the SSH forward relay,
    /// whose in-netns hop connects to passt's inbound listener on `127.0.0.1`.
    /// Safe: guest egress is never loopback→loopback — passt rewrites it to a
    /// real destination before it hits this hook — so this can only ever match
    /// sodabox's own intra-netns plumbing, never a guest connection.
    pub allow_loopback: bool,
    /// Drop ICMP egress by default (fail-closed; passt guest ping stays blocked).
    pub drop_icmp: bool,
}

impl EgressRules {
    pub fn new(tcp_port: u16, udp_port: u16) -> Self {
        Self {
            mark: DEFAULT_MARK,
            table_id: DEFAULT_TABLE_ID,
            tcp_port,
            udp_port,
            direct_daddrs: Vec::new(),
            allow_loopback: false,
            drop_icmp: true,
        }
    }

    /// Render the nft script (pure; unit-tested). Idempotent: it (re)creates the
    /// table from scratch via the add/delete/define trick so re-applying is safe.
    pub fn nft_ruleset(&self) -> String {
        let mark = self.mark;
        let mut bypass = String::new();
        if self.allow_loopback {
            // Intra-netns loopback (e.g. the SSH relay → passt inbound listener);
            // never guest egress, which always carries a real destination here.
            bypass.push_str("    ip saddr 127.0.0.0/8 ip daddr 127.0.0.0/8 accept\n");
        }
        for d in &self.direct_daddrs {
            bypass.push_str(&format!("    ip daddr {d} accept\n"));
        }
        let icmp = if self.drop_icmp {
            "\n  chain icmp_out {\n    type filter hook output priority filter; policy accept;\n    ip protocol icmp drop\n  }\n"
        } else {
            ""
        };
        format!(
            "add table ip {t}\n\
             delete table ip {t}\n\
             table ip {t} {{\n\
             \x20 chain out {{\n\
             \x20   type route hook output priority mangle; policy accept;\n\
             {bypass}\
             \x20   meta l4proto tcp meta mark set {mark:#x}\n\
             \x20   meta l4proto udp meta mark set {mark:#x}\n\
             \x20 }}\n\
             \x20 chain pre {{\n\
             \x20   type filter hook prerouting priority mangle; policy accept;\n\
             \x20   meta l4proto tcp meta mark {mark:#x} tproxy to :{tcp} accept\n\
             \x20   meta l4proto udp meta mark {mark:#x} tproxy to :{udp} accept\n\
             \x20 }}\n\
             {icmp}\
             }}\n",
            t = NFT_TABLE,
            tcp = self.tcp_port,
            udp = self.udp_port,
        )
    }

    /// Apply the full interception setup in the current netns: namespaced
    /// sysctls, the policy route that bounces marked packets onto `lo`, and the
    /// nft ruleset. Idempotent.
    pub fn apply(&self) -> io::Result<()> {
        self.set_sysctls()?;
        self.set_policy_route()?;
        self.load_nft()?;
        Ok(())
    }

    /// rp_filter=0 (so packets rerouted onto `lo` aren't dropped as martians) and
    /// route_localnet=1 (so `local default dev lo` accepts non-127/8 dsts). These
    /// are per-netns sysctls; writing them does not affect the host.
    fn set_sysctls(&self) -> io::Result<()> {
        for (path, val) in [
            ("/proc/sys/net/ipv4/conf/all/rp_filter", "0"),
            ("/proc/sys/net/ipv4/conf/default/rp_filter", "0"),
            ("/proc/sys/net/ipv4/conf/lo/rp_filter", "0"),
            ("/proc/sys/net/ipv4/conf/all/route_localnet", "1"),
            ("/proc/sys/net/ipv4/conf/lo/route_localnet", "1"),
        ] {
            std::fs::write(path, val)
                .map_err(|e| io::Error::new(e.kind(), format!("sysctl {path}: {e}")))?;
        }
        Ok(())
    }

    fn set_policy_route(&self) -> io::Result<()> {
        let mark = format!("{:#x}", self.mark);
        let table = self.table_id.to_string();
        // `ip rule add` / `ip route add` are not idempotent (EEXIST), so delete
        // first and ignore failure.
        run_ip(&["rule", "del", "fwmark", &mark, "lookup", &table], true)?;
        run_ip(&["rule", "add", "fwmark", &mark, "lookup", &table], false)?;
        run_ip(&["route", "flush", "table", &table], true)?;
        run_ip(
            &[
                "route", "add", "local", "default", "dev", "lo", "table", &table,
            ],
            false,
        )?;
        Ok(())
    }

    fn load_nft(&self) -> io::Result<()> {
        let mut child = Command::new(nft_bin())
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|e| io::Error::new(e.kind(), format!("spawn nft: {e}")))?;
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(self.nft_ruleset().as_bytes())?;
        let status = child.wait()?;
        if !status.success() {
            return Err(io::Error::other(format!("nft -f - failed: {status}")));
        }
        Ok(())
    }
}

fn run_ip(args: &[&str], ignore_failure: bool) -> io::Result<()> {
    let ip = std::env::var_os(crate::netns::IP_BIN_ENV).unwrap_or_else(|| "ip".into());
    let status = Command::new(&ip)
        .args(args)
        .stderr(Stdio::null())
        .status()?;
    if !status.success() && !ignore_failure {
        return Err(io::Error::other(format!(
            "`{} {}` failed: {status}",
            ip.to_string_lossy(),
            args.join(" ")
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset_has_mark_and_tproxy() {
        let r = EgressRules::new(18443, 18053);
        let s = r.nft_ruleset();
        // Recreate-from-scratch preamble.
        assert!(s.contains("add table ip sodabox"));
        assert!(s.contains("delete table ip sodabox"));
        // OUTPUT marks both protocols; PREROUTING TPROXYs them.
        assert!(s.contains("meta l4proto tcp meta mark set 0x111"));
        assert!(s.contains("meta l4proto udp meta mark set 0x111"));
        assert!(s.contains("meta l4proto tcp meta mark 0x111 tproxy to :18443 accept"));
        assert!(s.contains("meta l4proto udp meta mark 0x111 tproxy to :18053 accept"));
        // ICMP dropped by default.
        assert!(s.contains("ip protocol icmp drop"));
    }

    #[test]
    fn direct_daddrs_bypass_before_marking() {
        let mut r = EgressRules::new(1, 2);
        r.direct_daddrs = vec![Ipv4Addr::new(10, 0, 2, 3)];
        let s = r.nft_ruleset();
        let bypass = s.find("ip daddr 10.0.2.3 accept").expect("bypass rule");
        let mark = s.find("meta mark set").expect("mark rule");
        assert!(bypass < mark, "bypass must precede marking");
    }

    #[test]
    fn loopback_bypass_precedes_marking_when_enabled() {
        let mut r = EgressRules::new(1, 2);
        assert!(!r.nft_ruleset().contains("127.0.0.0/8"), "off by default");
        r.allow_loopback = true;
        let s = r.nft_ruleset();
        let bypass = s
            .find("ip saddr 127.0.0.0/8 ip daddr 127.0.0.0/8 accept")
            .expect("loopback bypass");
        let mark = s.find("meta mark set").expect("mark rule");
        assert!(bypass < mark, "loopback bypass must precede marking");
    }

    #[test]
    fn icmp_drop_can_be_disabled() {
        let mut r = EgressRules::new(1, 2);
        r.drop_icmp = false;
        assert!(!r.nft_ruleset().contains("icmp"));
    }
}
