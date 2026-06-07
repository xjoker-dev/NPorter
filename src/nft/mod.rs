//! nftables integration: desired-rule generation, netlink apply, counter
//! observation.
//!
//! The netlink backend (rustables) is Linux-only. On other platforms the
//! `apply`/`observe` entry points compile to stubs that return an error, so the
//! rest of the program still builds and runs for local development.

pub mod ruleset;

pub use ruleset::{RuleKind, desired_rules, render_ruleset};

use crate::model::Config;

/// A rule observed on the kernel that carries our identity comment.
#[derive(Debug, Clone)]
pub struct ObservedRule {
    pub mapping_id: String,
    pub kind: RuleKind,
}

/// Outcome of an `apply`: how many rules were added, deleted, or left untouched
/// (untouched rules keep their traffic counters).
#[derive(Debug, Default, Clone, Copy)]
pub struct ApplyReport {
    pub added: usize,
    pub deleted: usize,
    pub kept: usize,
}

#[cfg(target_os = "linux")]
mod backend;

#[cfg(target_os = "linux")]
pub fn apply(cfg: &Config) -> anyhow::Result<ApplyReport> {
    backend::apply(cfg)
}

#[cfg(target_os = "linux")]
pub fn observe(cfg: &Config) -> anyhow::Result<Vec<ObservedRule>> {
    backend::observe(cfg)
}

#[cfg(not(target_os = "linux"))]
pub fn apply(_cfg: &Config) -> anyhow::Result<ApplyReport> {
    anyhow::bail!("apply requires Linux (nftables netlink)")
}

#[cfg(not(target_os = "linux"))]
pub fn observe(_cfg: &Config) -> anyhow::Result<Vec<ObservedRule>> {
    anyhow::bail!("observe requires Linux (nftables netlink)")
}

/// FNV-1a (64-bit), used for the content hash embedded in rule comments.
/// Hand-rolled to guarantee the same value across processes and Rust versions
/// (unlike `DefaultHasher`). 64-bit keeps collision probability negligible even
/// for adversarially-chosen config content.
pub(crate) fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}
