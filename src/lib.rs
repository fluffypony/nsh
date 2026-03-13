// Library root for nsh: exposes modules and shared main entry for binaries.

pub mod ansi;
pub mod app;
pub mod audit;
pub mod autoconfigure;
pub mod cli;
pub mod coding_agent;
pub mod config;
pub mod context;
pub mod db;
pub mod debug_io;
pub mod fast_cwd;
pub mod history_import;
pub mod init;
pub mod json_extract;
#[allow(dead_code)]
pub mod mcp;
pub mod memory;
pub mod model_defaults;
pub mod provider;
pub mod provider_bootstrap;
pub mod query;
pub mod redact;
pub mod runtime;
pub mod security;
pub mod shell_hooks;
pub mod shim;
pub mod skills;
pub mod summary;
#[cfg(test)]
pub(crate) mod test_support;
pub mod tool_health;
pub mod tools;
pub mod ui;
pub mod util;

pub use app::main_inner;
pub use runtime::cliproxyapi;
pub use runtime::connectivity;
pub use runtime::daemon;
pub use runtime::daemon_client;
pub use runtime::daemon_db;
#[cfg(unix)]
pub use runtime::global_daemon;
pub use runtime::live_update;
pub use runtime::update_checker;
pub use shim::pty;
pub use shim::pump;
pub use ui as tui;
pub use ui::display;
pub use ui::json_display;
pub use ui::stream_consumer;
pub use ui::streaming;
