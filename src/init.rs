pub fn generate_init_script(shell: &str) -> String {
    let session_id = uuid::Uuid::new_v4().to_string();
    let template = match shell {
        "zsh" => include_str!("../shell/nsh.zsh"),
        "bash" => include_str!("../shell/nsh.bash"),
        other => {
            return format!(
                "# nsh: unsupported shell '{}'. Supported: zsh, bash\n\
                 echo 'nsh: unsupported shell' >&2",
                other
            );
        }
    };
    template.replace("__SESSION_ID__", &session_id)
}
