pub fn run_wrapped_shell(_shell: &str) -> anyhow::Result<()> {
    anyhow::bail!(
        "PTY wrapping is not supported on native Windows.\n\
         nsh query, history, and tools work without wrapping.\n\
         For full functionality, use WSL: wsl --install"
    );
}

pub fn exec_execvp(cmd: &str, args: &[&str]) -> std::io::Error {
    exec::execvp(cmd, args)
}

pub mod exec {
    pub fn execvp(_cmd: &str, _args: &[&str]) -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "exec-replacement is not available on Windows",
        )
    }
}
