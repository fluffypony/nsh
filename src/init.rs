pub fn generate_init_script(shell: &str) -> String {
    let session_id = uuid::Uuid::new_v4().to_string();
    let template = match shell {
        "zsh" => include_str!("../shell/nsh.zsh"),
        "bash" => include_str!("../shell/nsh.bash"),
        other => {
            eprintln!(
                "nsh: unsupported shell '{other}'. \
                 Supported: zsh, bash"
            );
            std::process::exit(1);
        }
    };
    template.replace("__SESSION_ID__", &session_id)
}
