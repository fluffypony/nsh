use super::*;
use serde_json::json;
use std::collections::HashSet;

#[test]
fn test_all_tool_definitions_returns_all_tools() {
    let tools = all_tool_definitions();
    assert!(tools.len() >= 22);
    for tool in &tools {
        assert!(!tool.name.is_empty());
        assert!(!tool.description.is_empty());
    }
}

#[test]
fn test_tool_definitions_have_valid_schemas() {
    let tools = all_tool_definitions();
    for tool in &tools {
        let obj = tool
            .parameters
            .as_object()
            .expect("parameters should be an object");
        assert_eq!(obj.get("type").and_then(|v| v.as_str()), Some("object"));
    }
}

#[test]
fn test_tool_names_unique() {
    let tools = all_tool_definitions();
    let mut names = HashSet::new();
    for tool in &tools {
        assert!(
            names.insert(tool.name.clone()),
            "duplicate tool name: {}",
            tool.name
        );
    }
}

#[test]
fn test_specific_tools_exist() {
    let tools = all_tool_definitions();
    let names: HashSet<String> = tools.iter().map(|tool| tool.name.clone()).collect();
    let expected = [
        "command",
        "chat",
        "search_history",
        "grep_file",
        "read_file",
        "list_directory",
        "glob",
        "web_search",
        "github",
        "run_command",
        "ask_user",
        "code",
        "write_file",
        "patch_file",
        "man_page",
        "manage_config",
        "install_skill",
        "install_mcp_server",
    ];
    for name in &expected {
        assert!(names.contains(*name), "missing tool: {name}");
    }
}

#[test]
fn test_tool_required_fields() {
    let tools = all_tool_definitions();
    for tool in &tools {
        let obj = tool.parameters.as_object().unwrap();
        assert!(
            obj.contains_key("required"),
            "tool '{}' missing 'required' field",
            tool.name
        );
    }
}

#[test]
fn test_validate_read_path_tilde_expansion() {
    let _home = dirs::home_dir().unwrap();
    let result = validate_read_path("~/Desktop");
    match result {
        Ok(path) => assert!(path.is_absolute()),
        Err(err) => assert!(
            err.contains("sensitive") || err.contains("Access denied"),
            "unexpected error: {err}"
        ),
    }
}

#[test]
fn test_validate_read_path_tilde_alone() {
    let result = validate_read_path("~");
    match result {
        Ok(path) => assert!(path.is_absolute()),
        Err(err) => assert!(
            err.contains("sensitive") || err.contains("Access denied"),
            "unexpected error: {err}"
        ),
    }
}

#[test]
fn test_validate_read_path_rejects_parent_dir() {
    let result = validate_read_path("/tmp/../etc/passwd");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains(".."));
}

#[test]
fn test_validate_read_path_relative_path() {
    let result = validate_read_path("Cargo.toml");
    if let Ok(path) = result {
        assert!(path.is_absolute());
    }
}

#[test]
fn test_validate_read_path_nonexistent_file() {
    let result = validate_read_path("/tmp/nsh_test_nonexistent_file_xyz_99999.txt");
    match result {
        Ok(path) => assert!(path.is_absolute()),
        Err(err) => assert!(err.contains("Access denied"), "unexpected error: {err}"),
    }
}

#[test]
fn test_validate_read_path_sensitive_ssh() {
    let result = validate_read_path("~/.ssh/id_rsa");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("sensitive"));
}

#[test]
fn test_validate_read_path_sensitive_nsh() {
    let result = validate_read_path("~/.nsh/config.toml");
    match result {
        Ok(path) => assert!(path.is_absolute()),
        Err(err) => assert!(err.contains("sensitive")),
    }
}

#[test]
fn test_validate_read_path_sensitive_aws() {
    let result = validate_read_path("~/.aws/credentials");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("sensitive"));
}

#[test]
fn test_validate_read_path_sensitive_gnupg() {
    let result = validate_read_path("~/.gnupg/pubring.kbx");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("sensitive"));
}

#[test]
fn test_validate_read_path_absolute_valid() {
    let result = validate_read_path("/tmp");
    assert!(result.is_ok());
    assert!(result.unwrap().is_absolute());
}

#[test]
fn test_validate_read_path_existing_but_cannot_resolve() {
    let tmp = tempfile::TempDir::new().unwrap();
    let file_path = tmp.path().join("test.txt");
    std::fs::write(&file_path, "hello").unwrap();
    let result = validate_read_path(file_path.to_str().unwrap());
    assert!(result.is_ok());
}

#[test]
fn test_validate_read_path_with_access_allow_bypasses_sensitive() {
    let result = validate_read_path_with_access("~/.ssh/id_rsa", "allow");
    match result {
        Ok(path) => assert!(path.is_absolute()),
        Err(err) => {
            assert!(
                !err.contains("sensitive"),
                "allow mode should not block sensitive dirs, got: {err}"
            );
        }
    }
}

#[test]
fn test_validate_read_path_with_access_block_rejects_sensitive() {
    let result = validate_read_path_with_access("~/.ssh/id_rsa", "block");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("sensitive"));
}

#[test]
fn test_validate_read_path_sensitive_gpg() {
    let result = validate_read_path("~/.gpg/keys");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("sensitive"));
}

#[test]
fn test_validate_read_path_sensitive_kube() {
    let result = validate_read_path("~/.kube/config");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("sensitive"));
}

#[test]
fn test_validate_read_path_sensitive_docker() {
    let result = validate_read_path("~/.docker/config.json");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("sensitive"));
}

#[test]
fn test_validate_read_path_sensitive_azure() {
    let result = validate_read_path("~/.azure/credentials");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("sensitive"));
}

#[test]
fn test_validate_read_path_sensitive_gcloud() {
    let result = validate_read_path("~/.config/gcloud/credentials.json");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("sensitive"));
}

#[test]
fn test_validate_read_path_parent_dir_in_middle() {
    let result = validate_read_path("/usr/local/../bin/ls");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains(".."));
}

#[test]
fn test_validate_read_path_parent_dir_at_end() {
    let result = validate_read_path("/tmp/foo/..");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains(".."));
}

#[test]
fn test_tool_definition_serializes_to_json() {
    let tool = ToolDefinition {
        name: "test_tool".into(),
        description: "A test tool".into(),
        parameters: json!({"type": "object", "properties": {}, "required": []}),
    };
    let serialized = serde_json::to_value(&tool).unwrap();
    assert_eq!(serialized["name"], "test_tool");
    assert_eq!(serialized["description"], "A test tool");
    assert!(serialized["parameters"].is_object());
}

#[test]
fn test_tool_definition_clone() {
    let tool = ToolDefinition {
        name: "clone_test".into(),
        description: "desc".into(),
        parameters: json!({"type": "object"}),
    };
    let cloned = tool.clone();
    assert_eq!(cloned.name, tool.name);
    assert_eq!(cloned.description, tool.description);
    assert_eq!(cloned.parameters, tool.parameters);
}

#[test]
fn test_tool_definition_debug() {
    let tool = ToolDefinition {
        name: "debug_test".into(),
        description: "desc".into(),
        parameters: json!({}),
    };
    let debug_str = format!("{tool:?}");
    assert!(debug_str.contains("debug_test"));
}

#[test]
fn test_command_tool_schema_properties() {
    let tools = all_tool_definitions();
    let command = tools.iter().find(|tool| tool.name == "command").unwrap();
    let props = command.parameters["properties"].as_object().unwrap();
    assert!(props.contains_key("command"));
    assert!(props.contains_key("explanation"));
    assert!(props.contains_key("pending"));
    assert_eq!(props["pending"]["type"], "boolean");
    assert_eq!(props["pending"]["default"], false);
    let required = command.parameters["required"].as_array().unwrap();
    let req_strs: Vec<&str> = required
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert!(req_strs.contains(&"command"));
    assert!(req_strs.contains(&"explanation"));
    assert!(!req_strs.contains(&"pending"));
}

#[test]
fn test_chat_tool_schema() {
    let tools = all_tool_definitions();
    let chat = tools.iter().find(|tool| tool.name == "chat").unwrap();
    let props = chat.parameters["properties"].as_object().unwrap();
    assert!(props.contains_key("response"));
    assert_eq!(props["response"]["type"], "string");
    let required = chat.parameters["required"].as_array().unwrap();
    assert_eq!(required.len(), 1);
    assert_eq!(required[0], "response");
}

#[test]
fn test_search_history_tool_schema() {
    let tools = all_tool_definitions();
    let search_history = tools
        .iter()
        .find(|tool| tool.name == "search_history")
        .unwrap();
    let props = search_history.parameters["properties"].as_object().unwrap();
    let expected_props = [
        "query",
        "command",
        "entity",
        "entity_type",
        "latest_only",
        "regex",
        "since",
        "until",
        "exit_code",
        "failed_only",
        "session",
        "limit",
    ];
    for property in &expected_props {
        assert!(
            props.contains_key(*property),
            "search_history missing property: {property}"
        );
    }
    assert_eq!(props["exit_code"]["type"], "integer");
    assert_eq!(props["failed_only"]["type"], "boolean");
    assert_eq!(props["latest_only"]["type"], "boolean");
    assert_eq!(props["limit"]["default"], 20);
}

#[test]
fn test_write_file_tool_requires_path_content_reason() {
    let tools = all_tool_definitions();
    let write_file = tools.iter().find(|tool| tool.name == "write_file").unwrap();
    let required = write_file.parameters["required"].as_array().unwrap();
    let req_strs: Vec<&str> = required
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert!(req_strs.contains(&"path"));
    assert!(req_strs.contains(&"content"));
    assert!(req_strs.contains(&"reason"));
}

#[test]
fn test_patch_file_tool_requires_all_fields() {
    let tools = all_tool_definitions();
    let patch_file = tools.iter().find(|tool| tool.name == "patch_file").unwrap();
    let required = patch_file.parameters["required"].as_array().unwrap();
    let req_strs: Vec<&str> = required
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(req_strs.len(), 4);
    assert!(req_strs.contains(&"path"));
    assert!(req_strs.contains(&"search"));
    assert!(req_strs.contains(&"replace"));
    assert!(req_strs.contains(&"reason"));
}

#[test]
fn test_manage_config_tool_action_enum() {
    let tools = all_tool_definitions();
    let manage_config = tools
        .iter()
        .find(|tool| tool.name == "manage_config")
        .unwrap();
    let action = &manage_config.parameters["properties"]["action"];
    let enum_vals = action["enum"].as_array().unwrap();
    let vals: Vec<&str> = enum_vals
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert!(vals.contains(&"set"));
    assert!(vals.contains(&"remove"));
    assert_eq!(vals.len(), 2);
}

#[test]
fn test_install_mcp_server_transport_enum() {
    let tools = all_tool_definitions();
    let mcp = tools
        .iter()
        .find(|tool| tool.name == "install_mcp_server")
        .unwrap();
    let transport = &mcp.parameters["properties"]["transport"];
    let enum_vals = transport["enum"].as_array().unwrap();
    let vals: Vec<&str> = enum_vals
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert!(vals.contains(&"stdio"));
    assert!(vals.contains(&"http"));
}

#[test]
fn test_all_tools_have_properties_object() {
    let tools = all_tool_definitions();
    for tool in &tools {
        let props = tool.parameters.get("properties");
        assert!(
            props.is_some() && props.unwrap().is_object(),
            "tool '{}' missing properties object",
            tool.name
        );
    }
}

#[test]
fn test_all_required_fields_exist_in_properties() {
    let tools = all_tool_definitions();
    for tool in &tools {
        let props = tool.parameters["properties"].as_object().unwrap();
        let required = tool.parameters["required"].as_array().unwrap();
        for req in required {
            let key = req.as_str().unwrap();
            assert!(
                props.contains_key(key),
                "tool '{}' requires '{}' but it's not in properties",
                tool.name,
                key
            );
        }
    }
}

#[test]
fn test_all_property_types_are_valid_json_schema_types() {
    let valid_types = ["string", "integer", "boolean", "array", "object", "number"];
    let tools = all_tool_definitions();
    for tool in &tools {
        let props = tool.parameters["properties"].as_object().unwrap();
        for (key, prop) in props {
            if let Some(ty) = prop.get("type").and_then(|value| value.as_str()) {
                assert!(
                    valid_types.contains(&ty),
                    "tool '{}' property '{}' has invalid type '{}'",
                    tool.name,
                    key,
                    ty
                );
            }
        }
    }
}

#[test]
fn test_grep_file_tool_properties() {
    let tools = all_tool_definitions();
    let grep_file = tools.iter().find(|tool| tool.name == "grep_file").unwrap();
    let props = grep_file.parameters["properties"].as_object().unwrap();
    let required = grep_file.parameters["required"].as_array().unwrap();
    assert!(props.contains_key("path"));
    assert!(props.contains_key("pattern"));
    assert!(props.contains_key("context_lines"));
    assert!(props.contains_key("max_lines"));
    assert_eq!(required.len(), 2);
    assert!(required.contains(&serde_json::json!("path")));
    assert!(required.contains(&serde_json::json!("pattern")));
    assert_eq!(props["context_lines"]["default"], 3);
    assert_eq!(props["max_lines"]["default"], 100);
}

#[test]
fn test_read_file_tool_properties() {
    let tools = all_tool_definitions();
    let read_file = tools.iter().find(|tool| tool.name == "read_file").unwrap();
    let props = read_file.parameters["properties"].as_object().unwrap();
    assert!(props.contains_key("path"));
    assert!(props.contains_key("full"));
    assert!(props.contains_key("start_line"));
    assert!(props.contains_key("end_line"));
    assert_eq!(props["full"]["default"], false);
}

#[test]
fn test_list_directory_tool_defaults() {
    let tools = all_tool_definitions();
    let list_directory = tools
        .iter()
        .find(|tool| tool.name == "list_directory")
        .unwrap();
    let props = list_directory.parameters["properties"].as_object().unwrap();
    assert_eq!(props["path"]["default"], ".");
    assert_eq!(props["show_hidden"]["default"], false);
    assert_eq!(props["recursive"]["default"], false);
    assert_eq!(props["max_entries"]["default"], 100);
    let required = list_directory.parameters["required"].as_array().unwrap();
    assert!(required.is_empty());
}

#[test]
fn test_run_command_tool_requires_command_and_reason() {
    let tools = all_tool_definitions();
    let run_command = tools
        .iter()
        .find(|tool| tool.name == "run_command")
        .unwrap();
    let required = run_command.parameters["required"].as_array().unwrap();
    let req_strs: Vec<&str> = required
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert!(req_strs.contains(&"command"));
    assert!(req_strs.contains(&"reason"));
}

#[test]
fn test_ask_user_tool_options_is_array() {
    let tools = all_tool_definitions();
    let ask_user = tools.iter().find(|tool| tool.name == "ask_user").unwrap();
    let props = ask_user.parameters["properties"].as_object().unwrap();
    assert_eq!(props["options"]["type"], "array");
    assert_eq!(props["options"]["items"]["type"], "string");
}

#[test]
fn test_install_skill_tool_parameters_additionalproperties() {
    let tools = all_tool_definitions();
    let install_skill = tools
        .iter()
        .find(|tool| tool.name == "install_skill")
        .unwrap();
    let params_prop = &install_skill.parameters["properties"]["parameters"];
    assert_eq!(params_prop["type"], "object");
    assert!(params_prop.get("additionalProperties").is_some());
}

#[test]
fn test_install_mcp_server_args_is_string_array() {
    let tools = all_tool_definitions();
    let mcp = tools
        .iter()
        .find(|tool| tool.name == "install_mcp_server")
        .unwrap();
    let args = &mcp.parameters["properties"]["args"];
    assert_eq!(args["type"], "array");
    assert_eq!(args["items"]["type"], "string");
}

#[test]
fn test_tool_count_matches_expected_names() {
    let tools = all_tool_definitions();
    let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_str()).collect();
    for must in [
        "command",
        "chat",
        "run_command",
        "web_search",
        "github",
        "ask_user",
        "write_file",
        "patch_file",
        "manage_config",
    ] {
        assert!(names.contains(&must), "tool list missing {must}");
    }
}

#[test]
fn test_no_tool_has_empty_parameters() {
    let tools = all_tool_definitions();
    for tool in &tools {
        assert!(
            !tool.parameters.is_null(),
            "tool '{}' has null parameters",
            tool.name
        );
    }
}

#[test]
fn test_man_page_section_is_integer() {
    let tools = all_tool_definitions();
    let man_page = tools.iter().find(|tool| tool.name == "man_page").unwrap();
    let section = &man_page.parameters["properties"]["section"];
    assert_eq!(section["type"], "integer");
}

#[test]
fn test_install_mcp_server_timeout_default() {
    let tools = all_tool_definitions();
    let mcp = tools
        .iter()
        .find(|tool| tool.name == "install_mcp_server")
        .unwrap();
    let timeout = &mcp.parameters["properties"]["timeout_seconds"];
    assert_eq!(timeout["type"], "integer");
    assert_eq!(timeout["default"], 30);
}

#[test]
fn test_install_skill_timeout_default() {
    let tools = all_tool_definitions();
    let install_skill = tools
        .iter()
        .find(|tool| tool.name == "install_skill")
        .unwrap();
    let timeout = &install_skill.parameters["properties"]["timeout_seconds"];
    assert_eq!(timeout["default"], 30);
}

#[test]
fn test_install_skill_terminal_default() {
    let tools = all_tool_definitions();
    let install_skill = tools
        .iter()
        .find(|tool| tool.name == "install_skill")
        .unwrap();
    let terminal = &install_skill.parameters["properties"]["terminal"];
    assert_eq!(terminal["type"], "boolean");
    assert_eq!(terminal["default"], false);
}

#[test]
fn test_validate_read_path_nonexistent_under_tmp() {
    let result = validate_read_path("/tmp/nsh_nonexistent_subdir/foo/bar.txt");
    if let Ok(path) = result {
        assert!(path.is_absolute());
    }
}

#[test]
fn test_validate_read_path_empty_string() {
    let result = validate_read_path("");
    if let Ok(path) = result {
        assert!(path.is_absolute());
    }
}

#[test]
fn test_validate_read_path_dot() {
    let result = validate_read_path(".");
    assert!(result.is_ok());
    assert!(result.unwrap().is_absolute());
}

#[test]
fn test_web_search_tool_requires_query() {
    let tools = all_tool_definitions();
    let web_search = tools.iter().find(|tool| tool.name == "web_search").unwrap();
    let required = web_search.parameters["required"].as_array().unwrap();
    assert_eq!(required.len(), 1);
    assert_eq!(required[0], "query");
}

#[test]
fn test_validate_read_path_allow_mode_normal_path() {
    let result = validate_read_path_with_access("/tmp", "allow");
    assert!(result.is_ok());
    assert!(result.unwrap().is_absolute());
}

#[test]
fn test_validate_read_path_allow_mode_rejects_dotdot() {
    let result = validate_read_path_with_access("/tmp/../etc/passwd", "allow");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains(".."));
}

#[test]
fn test_validate_read_path_tilde_subpath_nonexistent() {
    let result = validate_read_path("~/nonexistent_nsh_test_dir_999/file.txt");
    match result {
        Ok(path) => assert!(path.is_absolute()),
        Err(err) => assert!(
            err.contains("Access denied") || err.contains("sensitive"),
            "unexpected error: {err}"
        ),
    }
}

#[test]
fn test_validate_read_path_relative_nonexistent() {
    let result = validate_read_path("nsh_nonexistent_relative_test_file_xyz.txt");
    match result {
        Ok(path) => assert!(path.is_absolute()),
        Err(err) => assert!(err.contains("Access denied"), "unexpected error: {err}"),
    }
}

#[test]
fn test_validate_read_path_block_mode_non_sensitive_path() {
    let result = validate_read_path_with_access("/tmp", "block");
    assert!(result.is_ok());
    assert!(result.unwrap().is_absolute());
}

#[test]
fn test_normalize_sensitive_file_access_mode_accepts_known_values() {
    assert_eq!(normalize_sensitive_file_access_mode("allow"), "allow");
    assert_eq!(normalize_sensitive_file_access_mode("ask"), "ask");
    assert_eq!(normalize_sensitive_file_access_mode("block"), "block");
}

#[test]
fn test_normalize_sensitive_file_access_mode_falls_back_to_ask() {
    assert_eq!(normalize_sensitive_file_access_mode(""), "ask");
    assert_eq!(normalize_sensitive_file_access_mode("invalid"), "ask");
    assert_eq!(normalize_sensitive_file_access_mode("ALLOW"), "ask");
}
