//! Desired-rule generation.
//!
//! Produces an abstract intermediate representation (IR) of the nftables rules
//! that a config implies. The IR is used for `plan`/`check` display and for
//! diffing against observed rules; the netlink backend materializes it.
//!
//! Each rule carries an identity comment `nporter:v1 id=<id> kind=<kind> h=<hash>`
//! so we can identify and reconcile our own rules without touching foreign ones.
//!
//! Forward-chain design: the counter rules carry **no verdict** and the chain
//! policy is `accept`. That way a packet is counted and then falls through to
//! the policy — no `accept` verdict can short-circuit evaluation before the
//! counters run, so accounting is correct regardless of rule order (which
//! matters because incremental apply appends new rules).

use std::fmt;

use anyhow::{Result, bail};

use crate::config::Family;
use crate::model::{COMMENT_PREFIX, Config, Mapping};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuleKind {
    /// Destination NAT in the prerouting chain (counts new connections → "nat").
    Dnat,
    /// Source NAT (masquerade) in the postrouting chain.
    Masquerade,
    /// Counter on forwarded traffic toward the target (→ "in"). No verdict.
    ForwardIn,
    /// Counter on return traffic from the target (→ "out"). No verdict.
    ForwardReturn,
}

impl RuleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RuleKind::Dnat => "dnat",
            RuleKind::Masquerade => "masquerade",
            RuleKind::ForwardIn => "forward-in",
            RuleKind::ForwardReturn => "forward-return",
        }
    }

    pub fn parse(s: &str) -> Option<RuleKind> {
        Some(match s {
            "dnat" => RuleKind::Dnat,
            "masquerade" => RuleKind::Masquerade,
            "forward-in" => RuleKind::ForwardIn,
            "forward-return" => RuleKind::ForwardReturn,
            _ => return None,
        })
    }
}

impl fmt::Display for RuleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The rule kinds a given mapping produces (masquerade only when enabled).
/// Single source of truth shared by display generation and the netlink backend.
pub fn mapping_kinds(m: &Mapping) -> Vec<RuleKind> {
    let mut kinds = vec![RuleKind::Dnat, RuleKind::ForwardIn, RuleKind::ForwardReturn];
    if m.masquerade {
        kinds.push(RuleKind::Masquerade);
    }
    kinds
}

/// Stable content hash of the fields that define a mapping's rules. Embedded in
/// the rule comment so the backend can tell when a rule's meaning changed
/// (replace it) versus stayed the same (keep it, preserving its counter).
pub fn content_hash(m: &Mapping) -> String {
    let key = format!(
        "{}|{}|{}|{}|{}",
        m.protocol, m.listen_ip, m.listen_port, m.target_ip, m.target_port
    );
    format!("{:016x}", crate::nft::fnv1a(&key))
}

/// Identity comment stamped onto a rule's userdata.
pub fn identity_comment(id: &str, kind: RuleKind, hash: &str) -> String {
    format!("{COMMENT_PREFIX} id={id} kind={kind} h={hash}")
}

/// Parse an identity comment back into `(id, kind, hash)`. `None` if not ours.
pub fn parse_identity(comment: &str) -> Option<(String, RuleKind, String)> {
    if !comment.starts_with(COMMENT_PREFIX) {
        return None;
    }
    let mut id = None;
    let mut kind = None;
    let mut hash = String::new();
    for field in comment.split_whitespace() {
        if let Some(v) = field.strip_prefix("id=") {
            id = Some(v.to_string());
        } else if let Some(v) = field.strip_prefix("kind=") {
            kind = RuleKind::parse(v);
        } else if let Some(v) = field.strip_prefix("h=") {
            hash = v.to_string();
        }
    }
    Some((id?, kind?, hash))
}

/// One desired nftables rule, in abstract form (for `plan` display).
#[derive(Debug, Clone)]
pub struct DesiredRule {
    pub mapping_id: String,
    pub kind: RuleKind,
    pub expr: String,
}

fn comment(id: &str, kind: RuleKind) -> String {
    format!("{COMMENT_PREFIX} id={id} kind={kind}")
}

fn ip_kw(fam: Family) -> &'static str {
    match fam {
        Family::V4 => "ip",
        Family::V6 => "ip6",
    }
}

fn is_wildcard(ip: &str) -> bool {
    ip == "0.0.0.0" || ip == "::"
}

/// nft `id` strings may only contain a conservative character set, since they
/// end up in rule comments parsed by whitespace.
pub fn is_safe_id(id: &str) -> bool {
    let mut chars = id.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    id.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

fn dnat_target(fam: Family, ip: &str, port: u16) -> String {
    match fam {
        Family::V4 => format!("{ip}:{port}"),
        Family::V6 => format!("[{ip}]:{port}"),
    }
}

fn rule(id: &str, kind: RuleKind, expr: String) -> DesiredRule {
    DesiredRule {
        mapping_id: id.to_string(),
        kind,
        expr,
    }
}

fn mapping_rules(m: &Mapping) -> Result<Vec<DesiredRule>> {
    let fam = m.family()?;
    let kw = ip_kw(fam);
    let proto = m.protocol.as_str();

    let mut listen_match = format!("{proto} dport {}", m.listen_port);
    if !is_wildcard(&m.listen_ip) {
        listen_match = format!("{kw} daddr {} {listen_match}", m.listen_ip);
    } else {
        listen_match = format!("meta nfproto {} {listen_match}", nfproto(fam));
    }

    let id = &m.id;
    let mut rules = vec![
        rule(
            id,
            RuleKind::Dnat,
            format!(
                "{listen_match} counter dnat {kw} to {} comment \"{}\"",
                dnat_target(fam, &m.target_ip, m.target_port),
                comment(id, RuleKind::Dnat)
            ),
        ),
        rule(
            id,
            RuleKind::ForwardIn,
            format!(
                "{kw} daddr {} {proto} dport {} counter comment \"{}\"",
                m.target_ip,
                m.target_port,
                comment(id, RuleKind::ForwardIn)
            ),
        ),
        rule(
            id,
            RuleKind::ForwardReturn,
            format!(
                "{kw} saddr {} {proto} sport {} counter comment \"{}\"",
                m.target_ip,
                m.target_port,
                comment(id, RuleKind::ForwardReturn)
            ),
        ),
    ];

    // Per-mapping masquerade is authoritative; `default_masquerade` only seeds
    // the default at `add` time, so the TUI/CLI toggle is always meaningful.
    if m.masquerade {
        rules.push(rule(
            id,
            RuleKind::Masquerade,
            format!(
                "{kw} daddr {} masquerade comment \"{}\"",
                m.target_ip,
                comment(id, RuleKind::Masquerade)
            ),
        ));
    }
    Ok(rules)
}

fn nfproto(fam: Family) -> &'static str {
    match fam {
        Family::V4 => "ipv4",
        Family::V6 => "ipv6",
    }
}

/// Build the full desired rule set for a config (enabled mappings only).
pub fn desired_rules(cfg: &Config) -> Result<Vec<DesiredRule>> {
    let mut out = Vec::new();
    for m in &cfg.mappings {
        if !m.enabled {
            continue;
        }
        if !is_safe_id(&m.id) {
            bail!("mapping {} contains unsupported characters in its id", m.id);
        }
        out.extend(mapping_rules(m)?);
    }
    out.sort_by(|a, b| a.mapping_id.cmp(&b.mapping_id).then(a.kind.cmp(&b.kind)));
    Ok(out)
}

/// Render the rule set as an nft-style script, grouped by chain — for `plan`.
/// Human-readable only; rules are applied via netlink.
pub fn render_ruleset(cfg: &Config) -> Result<String> {
    let rules = desired_rules(cfg)?;
    let mut b = String::new();
    let (fam, table) = (&cfg.nftables.family, &cfg.nftables.table_name);
    b.push_str(&format!("table {fam} {table} {{\n"));

    b.push_str("  chain prerouting {\n");
    b.push_str("    type nat hook prerouting priority dstnat; policy accept;\n");
    for r in rules.iter().filter(|r| r.kind == RuleKind::Dnat) {
        b.push_str(&format!("    {}\n", r.expr));
    }
    b.push_str("  }\n\n");

    b.push_str("  chain postrouting {\n");
    b.push_str("    type nat hook postrouting priority srcnat; policy accept;\n");
    for r in rules.iter().filter(|r| r.kind == RuleKind::Masquerade) {
        b.push_str(&format!("    {}\n", r.expr));
    }
    b.push_str("  }\n\n");

    b.push_str("  chain forward {\n");
    b.push_str("    type filter hook forward priority filter; policy accept;\n");
    // Counter-only rules (no verdict); the policy accepts. Order-independent.
    for r in rules
        .iter()
        .filter(|r| matches!(r.kind, RuleKind::ForwardIn | RuleKind::ForwardReturn))
    {
        b.push_str(&format!("    {}\n", r.expr));
    }
    b.push_str("  }\n}\n");
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Mapping, Protocol};

    fn cfg_with(m: Mapping) -> Config {
        let mut c = Config::default();
        c.mappings.push(m);
        c
    }

    fn base(id: &str) -> Mapping {
        Mapping {
            id: id.into(),
            name: String::new(),
            protocol: Protocol::Tcp,
            listen_ip: "0.0.0.0".into(),
            listen_port: 10022,
            target_ip: "192.0.2.11".into(),
            target_port: 22,
            enabled: true,
            masquerade: true,
            description: String::new(),
        }
    }

    #[test]
    fn v4_rule_shapes() {
        let rules = desired_rules(&cfg_with(base("ssh"))).unwrap();
        // dnat + forward-in + forward-return + masquerade
        assert_eq!(rules.len(), 4);
        let dnat = rules.iter().find(|r| r.kind == RuleKind::Dnat).unwrap();
        assert!(dnat.expr.contains("dnat ip to 192.0.2.11:22"));
        assert!(dnat.expr.contains("tcp dport 10022"));
        assert!(dnat.expr.contains("meta nfproto ipv4")); // wildcard listen pins family
        // forward counters carry no accept verdict
        let fin = rules
            .iter()
            .find(|r| r.kind == RuleKind::ForwardIn)
            .unwrap();
        assert!(fin.expr.contains("counter"));
        assert!(!fin.expr.contains("accept"));
        let fret = rules
            .iter()
            .find(|r| r.kind == RuleKind::ForwardReturn)
            .unwrap();
        assert!(fret.expr.contains("saddr 192.0.2.11"));
        assert!(fret.expr.contains("sport 22 counter"));
        assert!(!fret.expr.contains("accept"));
    }

    #[test]
    fn v6_uses_ip6_and_brackets() {
        let mut m = base("web");
        m.listen_ip = "::".into();
        m.target_ip = "fd00::1".into();
        m.target_port = 80;
        let rules = desired_rules(&cfg_with(m)).unwrap();
        let dnat = rules.iter().find(|r| r.kind == RuleKind::Dnat).unwrap();
        assert!(
            dnat.expr.contains("dnat ip6 to [fd00::1]:80"),
            "{}",
            dnat.expr
        );
    }

    #[test]
    fn masquerade_off_and_explicit_listen() {
        let mut m = base("svc");
        m.masquerade = false;
        m.listen_ip = "198.51.100.5".into();
        let rules = desired_rules(&cfg_with(m)).unwrap();
        assert_eq!(rules.len(), 3); // no masquerade
        let dnat = rules.iter().find(|r| r.kind == RuleKind::Dnat).unwrap();
        assert!(dnat.expr.contains("ip daddr 198.51.100.5"));
        assert!(!dnat.expr.contains("nfproto")); // explicit listen, no wildcard pin
    }

    #[test]
    fn rejects_unsafe_id() {
        let mut m = base("bad");
        m.id = "bad id!".into();
        assert!(desired_rules(&cfg_with(m)).is_err());
    }
}
