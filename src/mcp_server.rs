//! MCP (Model Context Protocol) server over stdio.
//!
//! Allows external MCP-compatible clients (Claude Desktop, Cursor, VS Code Copilot,
//! Windsurf, etc.) to access nsh's history search, memory, and file tools.
//!
//! Protocol: JSON-RPC 2.0 over line-delimited stdin/stdout (MCP stdio transport).

use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Write};

use crate::config::{Config, SensitiveFileAccess};
use crate::tools::ToolDefinition;

// ── JSON-RPC Types ─────────────────────────────────────────────────

#[derive(Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    id: Option<serde_json::Value>,
    method: String,
    #[serde(default)]
    params: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Serialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

impl JsonRpcResponse {
    fn success(id: Option<serde_json::Value>, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    fn error(id: Option<serde_json::Value>, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
            }),
        }
    }
}

// ── MCP Tool Schema Conversion ─────────────────────────────────────

fn tool_def_to_mcp(def: &ToolDefinition) -> serde_json::Value {
    serde_json::json!({
        "name": def.name,
        "description": def.description,
        "inputSchema": def.parameters,
    })
}

/// Tools exposed via the MCP server (safe read-only subset + scoped tools).
const EXPOSED_TOOLS: &[&str] = &[
    "search_history",
    "search_memory",
    "read_file",
    "grep_file",
    "list_directory",
    "glob",
    "man_page",
    "skill_exists",
    "run_command",
];

fn get_exposed_tool_defs() -> Vec<ToolDefinition> {
    crate::tools::all_tool_definitions()
        .into_iter()
        .filter(|d| EXPOSED_TOOLS.contains(&d.name.as_str()))
        .collect()
}

// ── Tool Execution ─────────────────────────────────────────────────

fn execute_tool(
    name: &str,
    input: &serde_json::Value,
    config: &Config,
    db: &crate::db::Db,
) -> serde_json::Value {
    let result = match name {
        "search_history" => execute_search_history(input, db),
        "search_memory" => execute_search_memory(input, db),
        "read_file" => execute_read_file(input),
        "grep_file" => execute_grep_file(input),
        "list_directory" => execute_list_directory(input),
        "glob" => execute_glob(input),
        "man_page" => execute_man_page(input),
        "skill_exists" => execute_skill_exists(input),
        "run_command" => execute_run_command(input, config),
        _ => Err(format!("Unknown tool: {name}")),
    };

    match result {
        Ok(text) => serde_json::json!({
            "content": [{ "type": "text", "text": text }],
        }),
        Err(e) => serde_json::json!({
            "content": [{ "type": "text", "text": format!("Error: {e}") }],
            "isError": true,
        }),
    }
}

fn execute_search_history(input: &serde_json::Value, db: &crate::db::Db) -> Result<String, String> {
    let query = input["query"].as_str().unwrap_or("");
    let limit = input["limit"].as_u64().unwrap_or(20) as usize;
    let results = db.search_history(query, limit).map_err(|e| e.to_string())?;
    if results.is_empty() {
        return Ok("No matching commands found.".to_string());
    }
    let mut out = String::new();
    for cmd in &results {
        out.push_str(&format!(
            "[{}] {} (exit: {})\n  cwd: {}\n",
            cmd.started_at,
            cmd.command,
            cmd.exit_code.unwrap_or(0),
            cmd.cwd.as_deref().unwrap_or("?"),
        ));
    }
    Ok(out)
}

fn execute_search_memory(input: &serde_json::Value, db: &crate::db::Db) -> Result<String, String> {
    let query = input["query"].as_str().unwrap_or("");
    let memory_type_str = input["memory_type"].as_str().unwrap_or("all");
    let limit = input["limit"].as_u64().unwrap_or(10) as usize;
    let memory_type = if memory_type_str == "all" {
        None
    } else {
        Some(
            crate::memory::types::MemoryType::parse(memory_type_str)
                .map_err(|e| e.to_string())?,
        )
    };
    let conn = &db.conn;
    let results =
        crate::memory::search::search_all(conn, query, memory_type, limit)
            .map_err(|e| e.to_string())?;
    if results.is_empty() {
        return Ok("No matching memories found.".to_string());
    }
    let mut out = String::new();
    for r in &results {
        out.push_str(&format!("[{}] {}: {}\n", r.memory_type, r.id, r.summary));
    }
    Ok(out)
}

fn execute_read_file(input: &serde_json::Value) -> Result<String, String> {
    let outcome = crate::tools::read_file::execute_outcome_with_access(
        input,
        SensitiveFileAccess::Block,
    )
    .map_err(|e| e.to_string())?;
    Ok(outcome.into_content())
}

fn execute_grep_file(input: &serde_json::Value) -> Result<String, String> {
    let outcome = crate::tools::grep_file::execute_outcome_with_access(
        input,
        SensitiveFileAccess::Block,
    )
    .map_err(|e| e.to_string())?;
    Ok(outcome.into_content())
}

fn execute_list_directory(input: &serde_json::Value) -> Result<String, String> {
    let outcome = crate::tools::list_directory::execute_outcome_with_access(
        input,
        SensitiveFileAccess::Block,
    )
    .map_err(|e| e.to_string())?;
    Ok(outcome.into_content())
}

fn execute_glob(input: &serde_json::Value) -> Result<String, String> {
    let outcome =
        crate::tools::glob::execute_outcome_with_access(input, SensitiveFileAccess::Block)
            .map_err(|e| e.to_string())?;
    Ok(outcome.into_content())
}

fn execute_man_page(input: &serde_json::Value) -> Result<String, String> {
    let cmd = input["command"].as_str().unwrap_or("");
    let section = input["section"].as_u64().map(|s| s as u8);
    crate::tools::man_page::execute(cmd, section).map_err(|e| e.to_string())
}

fn execute_skill_exists(input: &serde_json::Value) -> Result<String, String> {
    crate::tools::skill_exists::execute(input).map_err(|e| e.to_string())
}

fn execute_run_command(input: &serde_json::Value, config: &Config) -> Result<String, String> {
    let cmd = input["command"].as_str().unwrap_or("");
    if cmd.is_empty() {
        return Err("command is required".to_string());
    }
    let outcome =
        crate::tools::run_command::execute_outcome(cmd, config).map_err(|e| e.to_string())?;
    Ok(outcome.into_content())
}

// ── Server Main Loop ───────────────────────────────────────────────

pub fn run_mcp_server() -> anyhow::Result<()> {
    let config = Config::load().unwrap_or_default();
    let tool_defs = get_exposed_tool_defs();
    let db = crate::db::Db::open()?;

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout_lock = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let request: JsonRpcRequest = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                let resp = JsonRpcResponse::error(None, -32700, format!("Parse error: {e}"));
                write_response(&mut stdout_lock, &resp);
                continue;
            }
        };

        // Ignore notifications (no id)
        if request.id.is_none() {
            continue;
        }

        let response = handle_request(&request, &tool_defs, &config, &db);
        write_response(&mut stdout_lock, &response);
    }

    Ok(())
}

fn handle_request(
    req: &JsonRpcRequest,
    tool_defs: &[ToolDefinition],
    config: &Config,
    db: &crate::db::Db,
) -> JsonRpcResponse {
    match req.method.as_str() {
        "initialize" => {
            let result = serde_json::json!({
                "protocolVersion": "2025-03-26",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "nsh",
                    "version": env!("CARGO_PKG_VERSION"),
                }
            });
            JsonRpcResponse::success(req.id.clone(), result)
        }

        "tools/list" => {
            let tools: Vec<serde_json::Value> = tool_defs.iter().map(tool_def_to_mcp).collect();
            let result = serde_json::json!({ "tools": tools });
            JsonRpcResponse::success(req.id.clone(), result)
        }

        "tools/call" => {
            let params = req.params.as_ref();
            let name = params.and_then(|p| p["name"].as_str()).unwrap_or("");
            let arguments = params
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or(serde_json::json!({}));

            if !tool_defs.iter().any(|d| d.name == name) {
                return JsonRpcResponse::error(
                    req.id.clone(),
                    -32601,
                    format!("Unknown tool: {name}"),
                );
            }

            let result = execute_tool(name, &arguments, config, db);
            JsonRpcResponse::success(req.id.clone(), result)
        }

        "ping" => JsonRpcResponse::success(req.id.clone(), serde_json::json!({})),

        _ => JsonRpcResponse::error(
            req.id.clone(),
            -32601,
            format!("Method not found: {}", req.method),
        ),
    }
}

fn write_response(w: &mut impl Write, resp: &JsonRpcResponse) {
    if let Ok(json) = serde_json::to_string(resp) {
        let _ = writeln!(w, "{json}");
        let _ = w.flush();
    }
}
