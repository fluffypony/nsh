pub fn default_timeout_for_tool(name: &str) -> u64 {
    match name {
        "read_file" | "grep_file" | "list_directory" | "glob" => 15,
        "man_page" => 10,
        "list_tools" | "find_tools" => 10,
        "search_history"
        | "search_memory"
        | "core_memory_append"
        | "core_memory_rewrite"
        | "store_memory"
        | "retrieve_secret" => 15,
        "run_command" => 60,
        "web_search" | "github" => 45,
        "manage_config" | "install_skill" | "install_mcp_server" | "skill_exists"
        | "uninstall_skill" => 30,
        "code" => 900,
        _ if name.starts_with("mcp_") => 60,
        _ if name.starts_with("skill_") => 60,
        _ => 60,
    }
}

#[cfg(test)]
mod tests {
    use super::default_timeout_for_tool;

    #[test]
    fn default_timeout_for_tool_uses_specific_overrides() {
        assert_eq!(default_timeout_for_tool("read_file"), 15);
        assert_eq!(default_timeout_for_tool("web_search"), 45);
        assert_eq!(default_timeout_for_tool("code"), 900);
    }

    #[test]
    fn default_timeout_for_tool_handles_prefixes_and_unknowns() {
        assert_eq!(default_timeout_for_tool("mcp_server.list"), 60);
        assert_eq!(default_timeout_for_tool("skill_demo"), 60);
        assert_eq!(default_timeout_for_tool("unknown"), 60);
    }
}
