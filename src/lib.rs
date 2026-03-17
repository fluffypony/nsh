//! nsh (Natural Shell) — AI-powered shell assistant library.
//!
//! Provides the core modules for the nsh shell assistant, including LLM query
//! processing, tool execution, memory management, and shell integration.

pub(crate) mod ansi;
pub(crate) mod app;
pub(crate) mod audit;
pub(crate) mod autoconfigure;
pub(crate) mod cli;
pub mod config;
pub(crate) mod context;
pub(crate) mod db;
pub(crate) mod debug_io;
pub(crate) mod fast_cwd;
pub(crate) mod history_import;
pub(crate) mod json_extract;
pub(crate) mod mcp;
pub(crate) mod memory;
pub(crate) mod model_defaults;
pub mod provider;
pub(crate) mod query;
pub(crate) mod redact;
pub(crate) mod runtime;
pub(crate) mod security;
pub mod shim;
pub(crate) mod skills;
pub(crate) mod summary;
#[cfg(test)]
pub(crate) mod test_support;
pub(crate) mod tools;
pub(crate) mod ui;
pub(crate) mod util;

pub use app::main_inner;
pub use runtime::cliproxyapi;
pub(crate) use runtime::connectivity;
pub(crate) use runtime::daemon;
pub(crate) use runtime::daemon_client;
pub(crate) use runtime::daemon_db;
#[cfg(unix)]
pub(crate) use runtime::global_daemon;
pub(crate) use runtime::live_update;
pub use runtime::update_checker;
pub(crate) use shim::pty;
pub(crate) use shim::pump;
pub(crate) use ui as tui;
pub(crate) use ui::json_display;
pub(crate) use ui::stream_consumer;
pub(crate) use ui::streaming;
