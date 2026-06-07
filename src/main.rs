// The netlink backend (and its helpers) only compile on Linux; on other
// platforms those symbols look dead. Keep dead-code enforcement on Linux (the
// real target) and silence it for local dev builds elsewhere.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod cli;
mod config;
mod daemon;
mod metrics;
mod model;
mod nft;
mod probe;
mod tui;

fn main() {
    if let Err(e) = cli::run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
