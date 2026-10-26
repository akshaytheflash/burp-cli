//! `burpcli` is a Burp Suite-style HTTP security testing toolkit for the terminal.
//!
//! The crate is deliberately modular so that every feature (proxy, scanner,
//! intruder, repeater, sequencer, ...) can be used both from the command line
//! and from Rust code / tests.

pub mod cli;
pub mod comparer;
pub mod config;
pub mod decoder;
pub mod http;
pub mod intruder;
pub mod oob;
pub mod plugins;
pub mod proxy;
pub mod report;
pub mod scanner;
pub mod scope;
pub mod sequencer;
pub mod session;
pub mod sitemap;
pub mod storage;
pub mod util;

/// Version reported by the CLI and by generated reports.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Name used in the `Server` header of the OOB listener and in reports.
pub const PRODUCT: &str = "burpcli";
