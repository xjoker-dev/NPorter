//! Target reachability / latency probes.
//!
//! Measures the latency of the *downstream* hop — from this host to a mapping's
//! target — which is the part of the forward path NPorter controls (the
//! client→host hop depends on the client's network and can't be measured here).
//!
//! TCP mappings: TCP handshake RTT to `target_ip:target_port` (also a real
//! reachability check — confirms something is listening). UDP mappings: ICMP
//! ping to the target host (no handshake for UDP), via the system `ping`.

use std::net::{IpAddr, SocketAddr, TcpStream};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::model::{Mapping, Protocol};

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub mapping_id: String,
    /// Round-trip latency, or `None` if unreachable / timed out.
    pub latency: Option<Duration>,
    /// "tcp" (handshake) or "icmp" (ping).
    pub method: &'static str,
    pub error: Option<String>,
}

impl ProbeResult {
    /// Short display string: "12ms", "0.4ms", "✗", or the failure reason.
    pub fn display(&self) -> String {
        match self.latency {
            Some(d) => format_latency(d),
            None => "✗".to_string(),
        }
    }
}

pub fn format_latency(d: Duration) -> String {
    let ms = d.as_secs_f64() * 1000.0;
    if ms < 1.0 {
        format!("{ms:.1}ms")
    } else {
        format!("{:.0}ms", ms)
    }
}

/// Probe a single mapping's target. Blocks up to `timeout`.
pub fn probe(m: &Mapping, timeout: Duration) -> ProbeResult {
    let id = m.mapping_id_owned();
    let ip: IpAddr = match m.target_ip.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return ProbeResult {
                mapping_id: id,
                latency: None,
                method: "tcp",
                error: Some(format!("invalid target_ip {}", m.target_ip)),
            };
        }
    };

    match m.protocol {
        Protocol::Tcp => tcp_probe(id, ip, m.target_port, timeout),
        Protocol::Udp => icmp_probe(id, ip, timeout),
    }
}

fn tcp_probe(id: String, ip: IpAddr, port: u16, timeout: Duration) -> ProbeResult {
    let addr = SocketAddr::new(ip, port);
    let start = Instant::now();
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => ProbeResult {
            mapping_id: id,
            latency: Some(start.elapsed()),
            method: "tcp",
            error: None,
        },
        Err(e) => ProbeResult {
            mapping_id: id,
            latency: None,
            method: "tcp",
            error: Some(e.to_string()),
        },
    }
}

fn icmp_probe(id: String, ip: IpAddr, timeout: Duration) -> ProbeResult {
    match system_ping(ip, timeout) {
        Some(d) => ProbeResult {
            mapping_id: id,
            latency: Some(d),
            method: "icmp",
            error: None,
        },
        None => ProbeResult {
            mapping_id: id,
            latency: None,
            method: "icmp",
            error: Some("no reply".into()),
        },
    }
}

/// One ICMP echo via the system `ping`, returning the measured RTT. Flags differ
/// per platform; IPv6 is handled by modern `ping` directly.
fn system_ping(ip: IpAddr, timeout: Duration) -> Option<Duration> {
    let secs = timeout.as_secs().max(1).to_string();
    let mut cmd = Command::new("ping");
    cmd.arg("-c").arg("1");
    if cfg!(target_os = "macos") {
        cmd.arg("-t").arg(&secs);
    } else {
        // Linux: -W is the per-reply timeout in seconds.
        cmd.arg("-W").arg(&secs);
        if ip.is_ipv6() {
            cmd.arg("-6");
        }
    }
    cmd.arg(ip.to_string());

    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    parse_ping_time(&String::from_utf8_lossy(&out.stdout))
}

/// Pull the RTT out of `ping` output ("... time=12.3 ms ...").
fn parse_ping_time(s: &str) -> Option<Duration> {
    let idx = s.find("time=")?;
    let after = &s[idx + 5..];
    let num: f64 = after
        .trim_start()
        .split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .next()?
        .parse()
        .ok()?;
    Some(Duration::from_secs_f64(num / 1000.0))
}

impl Mapping {
    fn mapping_id_owned(&self) -> String {
        self.id.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ping_time() {
        let s = "64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms";
        let d = parse_ping_time(s).unwrap();
        assert!((d.as_secs_f64() * 1000.0 - 12.3).abs() < 0.01);
        assert!(parse_ping_time("no time here").is_none());
    }

    #[test]
    fn latency_formatting() {
        assert_eq!(format_latency(Duration::from_micros(400)), "0.4ms");
        assert_eq!(format_latency(Duration::from_millis(12)), "12ms");
        assert_eq!(format_latency(Duration::from_millis(250)), "250ms");
    }
}
