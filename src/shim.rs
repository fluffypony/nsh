//! Stable shim boundary — PTY wrapper, pump loop, and capture engine.
//!
//! Code in this module is part of the "frozen" shim binary (`nsh`).
//! It persists for the lifetime of a terminal session and should
//! change extremely rarely. Any change here requires users to
//! restart their terminal.
//!
//! Dependencies: pty.rs, pump.rs — these are also part of the stable boundary.

pub use crate::pty;
pub use crate::pump;

/// Commands that the shim handles directly (not delegated to nsh-core).
pub fn is_shim_command(arg: &str) -> bool {
    matches!(arg, "wrap")
}

/// Shim-level wrap handler — called directly from shim_main.
/// Re-implements the `wrap` command to keep the shim self-contained.
pub fn run_wrap(args: Vec<String>) {
    // Determine shell from args or $SHELL
    let shell = args
        .iter()
        .position(|a| a == "wrap")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .or_else(|| std::env::var("SHELL").ok())
        .unwrap_or_else(|| "/bin/sh".to_string());

    if let Err(e) = crate::pty::run_wrapped_shell(&shell) {
        eprintln!("nsh wrap error: {e}");
        std::process::exit(1);
    }
}
