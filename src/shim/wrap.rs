use super::config::ShimWrapConfig;

fn parse_wrap_shell(args: &[String]) -> Option<String> {
    if let Some(index) = args.iter().position(|arg| arg == "--shell") {
        return args
            .get(index + 1)
            .cloned()
            .filter(|value| !value.is_empty());
    }

    args.iter()
        .position(|arg| arg == "wrap")
        .and_then(|index| args.get(index + 1))
        .filter(|value| value.as_str() != "--shell" && !value.is_empty())
        .cloned()
}

pub fn run_wrap(args: Vec<String>) {
    let shell = parse_wrap_shell(&args)
        .or_else(|| std::env::var("SHELL").ok())
        .unwrap_or_else(|| "/bin/sh".to_string());

    let wrap_config = ShimWrapConfig::from_env();

    if let Err(error) = crate::pty::run_wrapped_shell(&shell, &wrap_config) {
        eprintln!("nsh wrap error: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::parse_wrap_shell;

    #[test]
    fn parse_wrap_shell_prefers_flag_value() {
        let args = vec![
            "nsh".to_string(),
            "wrap".to_string(),
            "--shell".to_string(),
            "zsh".to_string(),
        ];
        assert_eq!(parse_wrap_shell(&args).as_deref(), Some("zsh"));
    }

    #[test]
    fn parse_wrap_shell_falls_back_to_positional_value() {
        let args = vec!["nsh".to_string(), "wrap".to_string(), "fish".to_string()];
        assert_eq!(parse_wrap_shell(&args).as_deref(), Some("fish"));
    }
}
