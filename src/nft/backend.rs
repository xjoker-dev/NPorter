//! Linux netlink backend (rustables).
//!
//! Applies rules incrementally: rules whose defining fields are unchanged are
//! left in place so their traffic counters survive config edits. Only new rules
//! are added and stale/removed rules are deleted — unlike a flush-and-recreate,
//! which resets every counter on every change.

use std::collections::HashSet;
use std::net::IpAddr;

use anyhow::{Context, Result};
use rustables::expr::{Cmp, CmpOp, Counter, Immediate, Meta, MetaType, Nat, NatType, Register};
use rustables::{
    Batch, Chain, ChainPolicy, ChainType, Hook, HookClass, MsgType, NfNetlinkObject, Protocol,
    ProtocolFamily, Rule, Table, list_chains_for_table, list_rules_for_chain, list_tables,
};

use crate::model::{Config, Mapping, Protocol as MProto};
use crate::nft::ruleset::{
    RuleKind, content_hash, identity_comment, mapping_kinds, parse_identity,
};
use crate::nft::{ApplyReport, ObservedRule};

const PREROUTING: &str = "prerouting";
const POSTROUTING: &str = "postrouting";
const FORWARD: &str = "forward";

// NF_INET priorities for the relevant hooks.
const PRI_DSTNAT: i32 = -100;
const PRI_SRCNAT: i32 = 100;
const PRI_FILTER: i32 = 0;

// NFPROTO_* family bytes for an nfproto meta match.
const NFPROTO_IPV4: u8 = 2;
const NFPROTO_IPV6: u8 = 10;

fn table_family(cfg: &Config) -> ProtocolFamily {
    match cfg.nftables.family.as_str() {
        "ip" => ProtocolFamily::Ipv4,
        "ip6" => ProtocolFamily::Ipv6,
        _ => ProtocolFamily::Inet,
    }
}

fn rproto(p: MProto) -> Protocol {
    match p {
        MProto::Tcp => Protocol::TCP,
        MProto::Udp => Protocol::UDP,
    }
}

fn make_table(cfg: &Config) -> Table {
    Table::new(table_family(cfg)).with_name(cfg.nftables.table_name.clone())
}

fn make_chain(table: &Table, name: &str, ty: ChainType, hook: HookClass, prio: i32) -> Chain {
    Chain::new(table)
        .with_name(name)
        .with_type(ty)
        .with_hook(Hook::new(hook, prio))
        .with_policy(ChainPolicy::Accept)
}

struct Chains {
    pre: Chain,
    post: Chain,
    fwd: Chain,
}

impl Chains {
    fn build(table: &Table) -> Self {
        Chains {
            pre: make_chain(
                table,
                PREROUTING,
                ChainType::Nat,
                HookClass::PreRouting,
                PRI_DSTNAT,
            ),
            post: make_chain(
                table,
                POSTROUTING,
                ChainType::Nat,
                HookClass::PostRouting,
                PRI_SRCNAT,
            ),
            fwd: make_chain(
                table,
                FORWARD,
                ChainType::Filter,
                HookClass::Forward,
                PRI_FILTER,
            ),
        }
    }

    fn for_kind(&self, kind: RuleKind) -> &Chain {
        match kind {
            RuleKind::Dnat => &self.pre,
            RuleKind::Masquerade => &self.post,
            _ => &self.fwd,
        }
    }
}

/// Match the L3 family without pinning a specific address (used for a wildcard
/// listen address, so a v4 mapping never matches v6 traffic and vice versa).
fn match_nfproto(rule: Rule, fam: ProtocolFamily) -> Rule {
    let byte = if fam == ProtocolFamily::Ipv6 {
        NFPROTO_IPV6
    } else {
        NFPROTO_IPV4
    };
    rule.with_expr(Meta::new(MetaType::NfProto))
        .with_expr(Cmp::new(CmpOp::Eq, [byte]))
}

fn add_dnat(rule: Rule, target: IpAddr, port: u16) -> Rule {
    let (ip_bytes, fam) = match target {
        IpAddr::V4(a) => (a.octets().to_vec(), ProtocolFamily::Ipv4),
        IpAddr::V6(a) => (a.octets().to_vec(), ProtocolFamily::Ipv6),
    };
    rule.with_expr(Immediate::new_data(ip_bytes, Register::Reg1))
        .with_expr(Immediate::new_data(
            port.to_be_bytes().to_vec(),
            Register::Reg2,
        ))
        .with_expr(
            Nat::default()
                .with_nat_type(NatType::DNat)
                .with_family(fam)
                .with_ip_register(Register::Reg1)
                .with_port_register(Register::Reg2),
        )
}

/// Build the rustables rule for a (mapping, kind) pair.
///
/// Forward-chain rules (ForwardIn/ForwardReturn) carry only a counter and no
/// verdict; the forward chain's policy is `accept`, so a packet is counted and
/// then accepted by policy. This keeps counting correct regardless of rule
/// order (incremental apply appends rules).
fn build_rule(chains: &Chains, m: &Mapping, kind: RuleKind, userdata: String) -> Result<Rule> {
    let listen: IpAddr = m.listen_ip.parse().context("listen_ip")?;
    let target: IpAddr = m.target_ip.parse().context("target_ip")?;
    let pfam = if target.is_ipv4() {
        ProtocolFamily::Ipv4
    } else {
        ProtocolFamily::Ipv6
    };
    let proto = rproto(m.protocol);
    let rule = Rule::new(chains.for_kind(kind))?;
    let rule = match kind {
        RuleKind::Dnat => {
            let r = if listen.is_unspecified() {
                match_nfproto(rule, pfam)
            } else {
                rule.daddr(listen)
            };
            let r = r.dport(m.listen_port, proto).with_expr(Counter::default());
            add_dnat(r, target, m.target_port)
        }
        RuleKind::Masquerade => rule.daddr(target).masquerade(),
        RuleKind::ForwardIn => rule
            .daddr(target)
            .dport(m.target_port, proto)
            .with_expr(Counter::default()),
        RuleKind::ForwardReturn => {
            // Return traffic is identified by (saddr=target, sport=target_port);
            // no ct-state match — we want to count every return packet, and a
            // bare SYN-ACK is not reliably "established" yet at forward time.
            rule.saddr(target)
                .sport(m.target_port, proto)
                .with_expr(Counter::default())
        }
    };
    Ok(rule.with_userdata(userdata.into_bytes()))
}

type Key = (String, RuleKind, String);

struct Raw {
    key: Key,
    kind: RuleKind,
    handle: u64,
}

/// List the rules in our table that carry our identity comment.
///
/// If our table does not exist yet, returns empty (a legitimate fresh state).
/// If the table exists but listing fails, the error is propagated rather than
/// swallowed — a blind "no rules" view would make `apply` skip cleanup and
/// re-add duplicates, and make `status` silently lie.
fn list_our_rules(table: &Table) -> Result<Vec<Raw>> {
    let mut out = Vec::new();

    let tables = list_tables().context("listing nftables tables")?;
    let exists = tables
        .iter()
        .any(|t| t.get_name() == table.get_name() && t.get_family() == table.get_family());
    if !exists {
        return Ok(out);
    }

    let chains = list_chains_for_table(table).context("listing chains for our table")?;
    for chain in &chains {
        let rules = list_rules_for_chain(chain).context("listing rules in chain")?;
        for rule in &rules {
            let Some(userdata) = rule.get_userdata() else {
                continue;
            };
            let Ok(comment) = std::str::from_utf8(userdata) else {
                continue;
            };
            let Some((id, kind, hash)) = parse_identity(comment) else {
                continue;
            };
            let handle = rule.get_handle().copied().unwrap_or(0);
            out.push(Raw {
                key: (id, kind, hash),
                kind,
                handle,
            });
        }
    }
    Ok(out)
}

/// Desired rules as (key, kind, mapping index).
fn desired_items(cfg: &Config) -> Vec<(Key, RuleKind, usize)> {
    let mut out = Vec::new();
    for (idx, m) in cfg.mappings.iter().enumerate() {
        if !m.enabled {
            continue;
        }
        let hash = content_hash(m);
        for kind in mapping_kinds(m) {
            out.push(((m.id.clone(), kind, hash.clone()), kind, idx));
        }
    }
    out
}

pub fn apply(cfg: &Config) -> Result<ApplyReport> {
    if cfg.nftables.enable_ip_forward {
        enable_forwarding(cfg)?;
    }

    let table = make_table(cfg);
    let chains = Chains::build(&table);

    let observed = list_our_rules(&table)?;
    let observed_keys: HashSet<Key> = observed.iter().map(|r| r.key.clone()).collect();

    let desired = desired_items(cfg);
    let desired_keys: HashSet<Key> = desired.iter().map(|(k, _, _)| k.clone()).collect();

    let mut batch = Batch::new();
    // Idempotent: creating an existing table/chain is a no-op on the kernel.
    batch.add(&table, MsgType::Add);
    batch.add(&chains.pre, MsgType::Add);
    batch.add(&chains.post, MsgType::Add);
    batch.add(&chains.fwd, MsgType::Add);

    let mut report = ApplyReport::default();

    // Build the rules we need to add (must outlive the batch references).
    let mut to_add: Vec<Rule> = Vec::new();
    for (key, kind, m_idx) in &desired {
        if observed_keys.contains(key) {
            report.kept += 1;
            continue;
        }
        let userdata = identity_comment(&key.0, *kind, &key.2);
        to_add.push(build_rule(&chains, &cfg.mappings[*m_idx], *kind, userdata)?);
    }

    // Delete rules that are not desired (orphans/stale) and any duplicate of a
    // desired key beyond the first (dedup — keep one, drop the rest).
    let mut kept_keys: HashSet<Key> = HashSet::new();
    let mut to_del: Vec<Rule> = Vec::new();
    for raw in &observed {
        let keep = desired_keys.contains(&raw.key) && kept_keys.insert(raw.key.clone());
        if !keep {
            // A rule we cannot identify by handle must not be deleted blindly
            // (handle 0 is undefined for a delete); skip and warn instead.
            if raw.handle == 0 {
                eprintln!(
                    "warning: skipping delete of {} {} — no rule handle",
                    raw.key.0, raw.kind
                );
                continue;
            }
            to_del.push(Rule::new(chains.for_kind(raw.kind))?.with_handle(raw.handle));
        }
    }

    report.added = to_add.len();
    report.deleted = to_del.len();
    for r in &to_add {
        batch.add(r, MsgType::Add);
    }
    for r in &to_del {
        batch.add(r, MsgType::Del);
    }

    batch
        .send()
        .context("sending nftables batch over netlink")?;
    Ok(report)
}

pub fn observe(cfg: &Config) -> Result<Vec<ObservedRule>> {
    let table = make_table(cfg);
    let raws = list_our_rules(&table)?;
    Ok(raws
        .into_iter()
        .map(|r| ObservedRule {
            mapping_id: r.key.0,
            kind: r.kind,
        })
        .collect())
}

fn enable_forwarding(cfg: &Config) -> Result<()> {
    let fam = cfg.nftables.family.as_str();
    if fam == "ip" || fam == "inet" {
        write_proc("/proc/sys/net/ipv4/ip_forward")?;
    }
    if fam == "ip6" || fam == "inet" {
        write_proc("/proc/sys/net/ipv6/conf/all/forwarding")?;
    }
    Ok(())
}

fn write_proc(path: &str) -> Result<()> {
    std::fs::write(path, "1\n").with_context(|| format!("enabling forwarding via {path}"))
}
