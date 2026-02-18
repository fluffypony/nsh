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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_wrapped_shell_returns_actionable_error_message() {
        let err = run_wrapped_shell("pwsh").expect_err("run_wrapped_shell should fail on windows shim");
        let text = err.to_string();
        assert!(text.contains("not supported on native Windows"));
        assert!(text.contains("use WSL"));
    }

    #[test]
    fn exec_execvp_reports_unsupported_kind() {
        let err = exec_execvp("cmd", &["/c", "echo hello"]);
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert!(err.to_string().contains("not available on Windows"));
    }
}
