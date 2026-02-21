//! nsh-core — full implementation binary, updated independently.
//! Invoked either directly or via the nsh shim.

fn main() -> anyhow::Result<()> {
    nsh::main_inner()
}
