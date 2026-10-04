//! Fault Tolerant Router 2.0: a multi-uplink policy routing daemon for Linux
//! routers. The behaviour is specified in SPEC.md; requirement identifiers
//! (for example FR-ROUTE-3) in comments refer to it.

#![forbid(unsafe_code)]

pub mod checks;
pub mod cleanup;
pub mod config;
pub mod daemon;
pub mod discover;
pub mod duration;
pub mod health;
pub mod model;
pub mod netlink;
pub mod nft;
pub mod nftctl;
pub mod observer;
pub mod plan;
pub mod probe;
pub mod ra;
pub mod reconcile;
pub mod select;
pub mod state;
pub mod sysctl;
pub mod system;
pub mod test_hooks;
