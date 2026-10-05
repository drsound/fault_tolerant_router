//! PolyWAN 2.0: a multi-uplink policy routing daemon for Linux
//! routers. The behaviour is specified in SPEC.md; requirement identifiers
//! (for example FR-ROUTE-3) in comments refer to it.

#![forbid(unsafe_code)]

pub mod api;
pub mod checks;
pub mod cleanup;
pub mod cli;
pub mod config;
pub mod daemon;
pub mod discover;
pub mod duration;
pub mod events;
pub mod health;
pub mod identity;
pub mod model;
pub mod netlink;
pub mod nft;
pub mod nftctl;
pub mod observer;
pub mod plan;
pub mod probe;
pub mod quality;
pub mod ra;
pub mod reconcile;
pub mod select;
pub mod state;
pub mod status;
pub mod subprocess;
pub mod sysctl;
pub mod system;
pub mod test_hooks;
pub mod worker;
