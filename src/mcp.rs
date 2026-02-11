use crate::config::{McpConfig, McpServerConfig};
use crate::tools::ToolDefinition;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

const MCP_PROTOCOL_VERSION: &str = "2025-03-26";

#[derive(Serialize)]
struct JsonRpcRequest {
    jsonrpc: &'static str,
    id: u64,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct JsonRpcNotification {
    jsonrpc: &'static str,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct JsonRpcResponse {
    id: Option<u64>,
    result: Option<serde_json::Value>,
    error: Option<JsonRpcError>,
}

#[derive(Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

struct McpToolInfo {
    name: String,
    description: String,
    input_schema: serde_json::Value,
}

enum McpTransport {
    Stdio {
        child: Child,
        stdin: tokio::process::ChildStdin,
        stdout: BufReader<tokio::process::ChildStdout>,
    },
    Http {
        client: reqwest::Client,
        url: String,
        session_id: Option<String>,
        headers: Vec<(String, String)>,
    },
}

struct McpServer {
    transport: McpTransport,
    tools: Vec<McpToolInfo>,
    next_id: u64,
    timeout: Duration,
}

fn find_event_boundary(buf: &[u8]) -> Option<(usize, usize)> {
    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some((pos, 4));
    }
    if let Some(pos) = buf.windows(2).position(|w| w == b"\n\n") {
        return Some((pos, 2));
    }
    None
}

impl McpServer {
    async fn send_request(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> anyhow::Result<serde_json::Value> {
        let id = self.next_id;
        self.next_id += 1;

        match &mut self.transport {
            McpTransport::Stdio { stdin, stdout, .. } => {
                let request = JsonRpcRequest {
                    jsonrpc: "2.0",
                    id,
                    method: method.to_string(),
                    params,
                };
                let mut line = serde_json::to_string(&request)?;
                line.push('\n');
                stdin.write_all(line.as_bytes()).await?;
                stdin.flush().await?;

                let response =
                    tokio::time::timeout(self.timeout, read_stdio_response(stdout, id))
                        .await
                        .map_err(|_| anyhow::anyhow!("MCP stdio request '{method}' timed out"))??;

                if let Some(err) = response.error {
                    anyhow::bail!("MCP error {}: {}", err.code, err.message);
                }
                Ok(response.result.unwrap_or(serde_json::Value::Null))
            }
            McpTransport::Http {
                client,
                url,
                session_id,
                headers,
            } => {
                let request = JsonRpcRequest {
                    jsonrpc: "2.0",
                    id,
                    method: method.to_string(),
                    params,
                };

                let mut req = client
                    .post(url.as_str())
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json, text/event-stream")
                    .json(&request);

                if let Some(sid) = session_id {
                    req = req.header("Mcp-Session-Id", sid.as_str());
                }
                for (k, v) in headers.iter() {
                    req = req.header(k.as_str(), v.as_str());
                }

                let resp = tokio::time::timeout(self.timeout, req.send())
                    .await
                    .map_err(|_| anyhow::anyhow!("MCP HTTP request '{method}' timed out"))??
                    .error_for_status()?;

                // Capture session ID
                if let Some(sid) = resp.headers().get("mcp-session-id") {
                    if let Ok(s) = sid.to_str() {
                        *session_id = Some(s.to_string());
                    }
                }

                let content_type = resp
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();

                if content_type.contains("text/event-stream") {
                    use futures::StreamExt;
                    let sse_fut = async {
                        let mut body_stream = resp.bytes_stream();
                        let mut raw_buffer: Vec<u8> = Vec::new();
                        while let Some(chunk) = body_stream.next().await {
                            let chunk = chunk?;
                            raw_buffer.extend_from_slice(&chunk);

                            while let Some((pos, delim_len)) = find_event_boundary(&raw_buffer) {
                                let event_bytes = raw_buffer[..pos].to_vec();
                                raw_buffer = raw_buffer[pos + delim_len..].to_vec();

                                let event_block = String::from_utf8_lossy(&event_bytes);
                                for line in event_block.lines() {
                                    if let Some(data) = line.strip_prefix("data:").map(|d| d.strip_prefix(' ').unwrap_or(d)) {
                                        let data = data.trim();
                                        if data.is_empty() {
                                            continue;
                                        }
                                        if let Ok(resp) =
                                            serde_json::from_str::<JsonRpcResponse>(data)
                                        {
                                            if resp.id.is_some() {
                                                if let Some(err) = resp.error {
                                                    anyhow::bail!(
                                                        "MCP error {}: {}",
                                                        err.code,
                                                        err.message
                                                    );
                                                }
                                                return Ok(resp
                                                    .result
                                                    .unwrap_or(serde_json::Value::Null));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        anyhow::bail!("No JSON-RPC response found in SSE stream")
                    };
                    tokio::time::timeout(self.timeout, sse_fut)
                        .await
                        .map_err(|_| {
                            anyhow::anyhow!("MCP SSE response for '{method}' timed out")
                        })?
                } else {
                    let rpc_resp: JsonRpcResponse = resp.json().await?;
                    if let Some(err) = rpc_resp.error {
                        anyhow::bail!("MCP error {}: {}", err.code, err.message);
                    }
                    Ok(rpc_resp.result.unwrap_or(serde_json::Value::Null))
                }
            }
        }
    }

    async fn send_notification(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> anyhow::Result<()> {
        let notification = JsonRpcNotification {
            jsonrpc: "2.0",
            method: method.to_string(),
            params,
        };

        match &mut self.transport {
            McpTransport::Stdio { stdin, .. } => {
                let mut line = serde_json::to_string(&notification)?;
                line.push('\n');
                stdin.write_all(line.as_bytes()).await?;
                stdin.flush().await?;
            }
            McpTransport::Http {
                client,
                url,
                session_id,
                headers,
            } => {
                let mut req = client
                    .post(url.as_str())
                    .header("Content-Type", "application/json")
                    .json(&notification);
                if let Some(sid) = session_id {
                    req = req.header("Mcp-Session-Id", sid.as_str());
                }
                for (k, v) in headers.iter() {
                    req = req.header(k.as_str(), v.as_str());
                }
                let _ = req.send().await;
            }
        }
        Ok(())
    }
}

async fn read_stdio_response(
    stdout: &mut BufReader<tokio::process::ChildStdout>,
    expected_id: u64,
) -> anyhow::Result<JsonRpcResponse> {
    loop {
        let mut line = String::new();
        let n = stdout.read_line(&mut line).await?;
        if n == 0 {
            anyhow::bail!("MCP server closed stdout");
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(resp) = serde_json::from_str::<JsonRpcResponse>(trimmed) {
            if resp.id == Some(expected_id) {
                return Ok(resp);
            }
        }
    }
}

pub struct McpClient {
    servers: HashMap<String, McpServer>,
}

impl McpClient {
    pub fn new() -> Self {
        Self {
            servers: HashMap::new(),
        }
    }

    pub async fn start_servers(&mut self, config: &McpConfig) {
        for (name, server_config) in &config.servers {
            match Self::start_server(name, server_config).await {
                Ok(server) => {
                    tracing::debug!(
                        "MCP server '{name}' started with {} tools",
                        server.tools.len()
                    );
                    self.servers.insert(name.clone(), server);
                }
                Err(e) => {
                    tracing::warn!("Failed to start MCP server '{name}': {e}");
                }
            }
        }
    }

    async fn start_server(
        name: &str,
        config: &McpServerConfig,
    ) -> anyhow::Result<McpServer> {
        let timeout = Duration::from_secs(config.timeout_seconds);
        let transport_type = config.effective_transport();

        let transport = match transport_type.as_str() {
            "http" => {
                let url = config
                    .url
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("MCP server '{name}': url required for http transport"))?
                    .clone();
                let client = reqwest::Client::builder()
                    .timeout(timeout)
                    .build()?;
                let headers: Vec<(String, String)> = config
                    .headers
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                McpTransport::Http {
                    client,
                    url,
                    session_id: None,
                    headers,
                }
            }
            _ => {
                let cmd_str = config.command.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("MCP server '{name}': command required for stdio transport")
                })?;

                let mut cmd = Command::new(cmd_str);
                cmd.args(&config.args)
                    .envs(&config.env)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::null());

                let mut child = cmd.spawn().map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to spawn MCP server '{name}' ({cmd_str}): {e}"
                    )
                })?;

                let stdin = child.stdin.take().unwrap();
                let stdout = BufReader::new(child.stdout.take().unwrap());

                McpTransport::Stdio {
                    child,
                    stdin,
                    stdout,
                }
            }
        };

        let mut server = McpServer {
            transport,
            tools: Vec::new(),
            next_id: 1,
            timeout,
        };

        // Initialize
        server
            .send_request(
                "initialize",
                Some(json!({
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {
                        "name": "nsh",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                })),
            )
            .await?;

        server
            .send_notification("notifications/initialized", None)
            .await
            .ok();

        // List tools
        let tools_result = server.send_request("tools/list", None).await?;

        if let Some(tools) = tools_result.get("tools").and_then(|t| t.as_array()) {
            for tool in tools {
                let tool_name = tool
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();
                let description = tool
                    .get("description")
                    .and_then(|d| d.as_str())
                    .unwrap_or("")
                    .to_string();
                let input_schema = tool
                    .get("inputSchema")
                    .cloned()
                    .unwrap_or(json!({"type": "object", "properties": {}}));

                if !tool_name.is_empty() {
                    server.tools.push(McpToolInfo {
                        name: tool_name,
                        description,
                        input_schema,
                    });
                }
            }
        }

        Ok(server)
    }

    pub fn tool_definitions(&self) -> Vec<ToolDefinition> {
        let mut defs = Vec::new();
        for (server_name, server) in &self.servers {
            for tool in &server.tools {
                defs.push(ToolDefinition {
                    name: format!("mcp_{server_name}_{}", tool.name),
                    description: tool.description.clone(),
                    parameters: tool.input_schema.clone(),
                });
            }
        }
        defs
    }

    pub fn has_tool(&self, prefixed_name: &str) -> bool {
        self.parse_tool_name(prefixed_name).is_some()
    }

    fn parse_tool_name<'a>(&'a self, prefixed_name: &'a str) -> Option<(&'a str, &'a str)> {
        let rest = prefixed_name.strip_prefix("mcp_")?;
        let mut keys: Vec<&str> = self.servers.keys().map(|s| s.as_str()).collect();
        keys.sort_by(|a, b| b.len().cmp(&a.len()));
        for server_name in keys {
            if let Some(tool_name) =
                rest.strip_prefix(server_name).and_then(|s| s.strip_prefix('_'))
            {
                return Some((server_name, tool_name));
            }
        }
        None
    }

    pub fn server_info(&self) -> Vec<(String, usize)> {
        self.servers
            .iter()
            .map(|(name, server)| (name.clone(), server.tools.len()))
            .collect()
    }

    pub async fn call_tool(
        &mut self,
        prefixed_name: &str,
        input: serde_json::Value,
    ) -> anyhow::Result<String> {
        let (server_name, tool_name) = self
            .parse_tool_name(prefixed_name)
            .ok_or_else(|| anyhow::anyhow!("Unknown MCP tool: {prefixed_name}"))?;

        let server_name = server_name.to_string();
        let tool_name = tool_name.to_string();

        let server = self
            .servers
            .get_mut(&server_name)
            .ok_or_else(|| anyhow::anyhow!("MCP server '{server_name}' not found"))?;

        let result = server
            .send_request(
                "tools/call",
                Some(json!({
                    "name": tool_name,
                    "arguments": input
                })),
            )
            .await?;

        if let Some(content) = result.get("content").and_then(|c| c.as_array()) {
            let texts: Vec<&str> = content
                .iter()
                .filter_map(|item| item.get("text").and_then(|t| t.as_str()))
                .collect();
            if !texts.is_empty() {
                return Ok(texts.join("\n"));
            }
        }

        Ok(serde_json::to_string_pretty(&result)?)
    }

    pub async fn shutdown(&mut self) {
        for (name, server) in &mut self.servers {
            if let Err(e) = server.send_request("shutdown", None).await {
                tracing::debug!("MCP server '{name}' shutdown error: {e}");
            }
            if let McpTransport::Stdio { ref mut child, .. } = server.transport {
                let _ = child.kill().await;
            }
        }
        self.servers.clear();
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        for (_, server) in &mut self.servers {
            if let McpTransport::Stdio { ref mut child, .. } = server.transport {
                let _ = child.start_kill();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_event_boundary_crlf() {
        let buf = b"data: hello\r\n\r\ndata: world";
        assert_eq!(find_event_boundary(buf), Some((11, 4)));
    }

    #[test]
    fn find_event_boundary_lf() {
        let buf = b"data: hello\n\ndata: world";
        assert_eq!(find_event_boundary(buf), Some((11, 2)));
    }

    #[test]
    fn find_event_boundary_none() {
        let buf = b"data: hello\ndata: world";
        assert_eq!(find_event_boundary(buf), None);
    }

    #[test]
    fn find_event_boundary_at_start() {
        let buf = b"\r\n\r\ndata: hello";
        assert_eq!(find_event_boundary(buf), Some((0, 4)));
    }

    #[test]
    fn find_event_boundary_prefers_crlf() {
        let buf = b"data: hello\r\n\r\nmore\n\nend";
        let result = find_event_boundary(buf);
        assert_eq!(result, Some((11, 4)));
    }

    #[test]
    fn mcp_client_new_creates_empty() {
        let client = McpClient::new();
        assert!(client.servers.is_empty());
    }

    #[test]
    fn mcp_client_tool_definitions_empty() {
        let client = McpClient::new();
        assert!(client.tool_definitions().is_empty());
    }

    #[test]
    fn mcp_client_has_tool_returns_false() {
        let client = McpClient::new();
        assert!(!client.has_tool("mcp_server_tool"));
    }

    #[test]
    fn mcp_client_server_info_empty() {
        let client = McpClient::new();
        assert!(client.server_info().is_empty());
    }

    #[test]
    fn find_event_boundary_empty_buffer() {
        assert_eq!(find_event_boundary(b""), None);
    }

    #[test]
    fn find_event_boundary_single_newline() {
        assert_eq!(find_event_boundary(b"\n"), None);
    }

    #[test]
    fn find_event_boundary_single_crlf() {
        assert_eq!(find_event_boundary(b"\r\n"), None);
    }

    #[test]
    fn find_event_boundary_three_bytes() {
        assert_eq!(find_event_boundary(b"\n\n\n"), Some((0, 2)));
    }

    fn make_populated_client() -> McpClient {
        let mut client = McpClient::new();
        let server = McpServer {
            transport: McpTransport::Http {
                client: reqwest::Client::new(),
                url: "http://localhost".into(),
                session_id: None,
                headers: vec![],
            },
            tools: vec![
                McpToolInfo {
                    name: "search".into(),
                    description: "Search files".into(),
                    input_schema: serde_json::json!({"type": "object", "properties": {"q": {"type": "string"}}}),
                },
                McpToolInfo {
                    name: "read".into(),
                    description: "Read a file".into(),
                    input_schema: serde_json::json!({"type": "object", "properties": {}}),
                },
            ],
            next_id: 1,
            timeout: Duration::from_secs(30),
        };
        client.servers.insert("myserver".into(), server);
        client
    }

    #[test]
    fn parse_tool_name_with_populated_client() {
        let client = make_populated_client();
        let result = client.parse_tool_name("mcp_myserver_search");
        assert_eq!(result, Some(("myserver", "search")));
    }

    #[test]
    fn parse_tool_name_no_prefix() {
        let client = make_populated_client();
        assert!(client.parse_tool_name("myserver_search").is_none());
    }

    #[test]
    fn parse_tool_name_wrong_server() {
        let client = make_populated_client();
        assert!(client.parse_tool_name("mcp_other_search").is_none());
    }

    #[test]
    fn has_tool_populated() {
        let client = make_populated_client();
        assert!(client.has_tool("mcp_myserver_search"));
        assert!(client.has_tool("mcp_myserver_read"));
        assert!(client.has_tool("mcp_myserver_write"));
        assert!(!client.has_tool("mcp_other_search"));
        assert!(!client.has_tool("no_prefix"));
    }

    #[test]
    fn tool_definitions_populated() {
        let client = make_populated_client();
        let defs = client.tool_definitions();
        assert_eq!(defs.len(), 2);
        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"mcp_myserver_search"));
        assert!(names.contains(&"mcp_myserver_read"));
        let search_def = defs.iter().find(|d| d.name == "mcp_myserver_search").unwrap();
        assert_eq!(search_def.description, "Search files");
    }

    #[test]
    fn server_info_populated() {
        let client = make_populated_client();
        let info = client.server_info();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].0, "myserver");
        assert_eq!(info[0].1, 2);
    }

    #[test]
    fn jsonrpc_request_serializes_with_params() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "initialize".to_string(),
            params: Some(serde_json::json!({"key": "value"})),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["id"], 1);
        assert_eq!(json["method"], "initialize");
        assert_eq!(json["params"]["key"], "value");
    }

    #[test]
    fn jsonrpc_request_serializes_without_params() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 42,
            method: "shutdown".to_string(),
            params: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("params").is_none());
        assert_eq!(json["id"], 42);
        assert_eq!(json["method"], "shutdown");
    }

    #[test]
    fn jsonrpc_notification_serializes_without_id() {
        let notif = JsonRpcNotification {
            jsonrpc: "2.0",
            method: "notifications/initialized".to_string(),
            params: None,
        };
        let json = serde_json::to_value(&notif).unwrap();
        assert!(json.get("id").is_none());
        assert!(json.get("params").is_none());
        assert_eq!(json["method"], "notifications/initialized");
    }

    #[test]
    fn jsonrpc_notification_serializes_with_params() {
        let notif = JsonRpcNotification {
            jsonrpc: "2.0",
            method: "progress".to_string(),
            params: Some(serde_json::json!({"token": 1, "value": 50})),
        };
        let json = serde_json::to_value(&notif).unwrap();
        assert!(json.get("id").is_none());
        assert_eq!(json["params"]["token"], 1);
    }

    #[test]
    fn jsonrpc_response_deserializes_success() {
        let json = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#;
        let resp: JsonRpcResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, Some(1));
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn jsonrpc_response_deserializes_error() {
        let json = r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"Method not found"}}"#;
        let resp: JsonRpcResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, Some(2));
        assert!(resp.result.is_none());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32601);
        assert_eq!(err.message, "Method not found");
    }

    #[test]
    fn jsonrpc_response_deserializes_notification_no_id() {
        let json = r#"{"jsonrpc":"2.0","method":"log","params":{}}"#;
        let resp: JsonRpcResponse = serde_json::from_str(json).unwrap();
        assert!(resp.id.is_none());
        assert!(resp.result.is_none());
        assert!(resp.error.is_none());
    }

    #[test]
    fn jsonrpc_response_deserializes_null_result() {
        let json = r#"{"jsonrpc":"2.0","id":5,"result":null}"#;
        let resp: JsonRpcResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, Some(5));
        assert!(resp.result.is_none());
        assert!(resp.error.is_none());
    }

    #[test]
    fn jsonrpc_request_roundtrip() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 7,
            method: "tools/call".to_string(),
            params: Some(serde_json::json!({"name": "search", "arguments": {"q": "test"}})),
        };
        let serialized = serde_json::to_string(&req).unwrap();
        let resp: JsonRpcResponse = serde_json::from_str(&serialized).unwrap();
        assert_eq!(resp.id, Some(7));
    }

    #[test]
    fn find_event_boundary_only_crlf_available() {
        let buf = b"event: message\r\n\r\n";
        assert_eq!(find_event_boundary(buf), Some((14, 4)));
    }

    #[test]
    fn find_event_boundary_multiple_lf_events() {
        let buf = b"data: first\n\ndata: second\n\n";
        let (pos, len) = find_event_boundary(buf).unwrap();
        assert_eq!(pos, 11);
        assert_eq!(len, 2);
        let rest = &buf[pos + len..];
        let (pos2, len2) = find_event_boundary(rest).unwrap();
        assert_eq!(pos2, 12);
        assert_eq!(len2, 2);
    }

    #[test]
    fn find_event_boundary_at_end() {
        let buf = b"data: hello\n\n";
        assert_eq!(find_event_boundary(buf), Some((11, 2)));
    }

    #[test]
    fn mcp_protocol_version_is_set() {
        assert!(!MCP_PROTOCOL_VERSION.is_empty());
    }

    #[test]
    fn parse_tool_name_empty_string() {
        let client = McpClient::new();
        assert!(client.parse_tool_name("").is_none());
    }

    #[test]
    fn parse_tool_name_just_prefix() {
        let client = make_populated_client();
        assert!(client.parse_tool_name("mcp_").is_none());
    }

    #[test]
    fn parse_tool_name_server_no_tool() {
        let client = make_populated_client();
        assert!(client.parse_tool_name("mcp_myserver").is_none());
    }

    #[test]
    fn parse_tool_name_server_trailing_underscore() {
        let client = make_populated_client();
        let result = client.parse_tool_name("mcp_myserver_");
        assert_eq!(result, Some(("myserver", "")));
    }

    #[test]
    fn tool_definitions_have_correct_schema() {
        let client = make_populated_client();
        let defs = client.tool_definitions();
        let search_def = defs.iter().find(|d| d.name == "mcp_myserver_search").unwrap();
        assert_eq!(search_def.parameters["type"], "object");
        assert!(search_def.parameters["properties"]["q"].is_object());
    }

    #[test]
    fn parse_tool_name_longest_server_match() {
        let mut client = McpClient::new();
        let make_server = |tools: Vec<&str>| McpServer {
            transport: McpTransport::Http {
                client: reqwest::Client::new(),
                url: "http://localhost".into(),
                session_id: None,
                headers: vec![],
            },
            tools: tools
                .into_iter()
                .map(|n| McpToolInfo {
                    name: n.into(),
                    description: String::new(),
                    input_schema: serde_json::json!({}),
                })
                .collect(),
            next_id: 1,
            timeout: Duration::from_secs(30),
        };
        client.servers.insert("ab".into(), make_server(vec!["x"]));
        client.servers.insert("ab_cd".into(), make_server(vec!["x"]));
        let result = client.parse_tool_name("mcp_ab_cd_x");
        assert_eq!(result, Some(("ab_cd", "x")));
    }
}
