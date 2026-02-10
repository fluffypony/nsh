use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use crate::daemon::{DaemonRequest, DaemonResponse};

pub fn send_request(session_id: &str, request: &DaemonRequest) -> anyhow::Result<DaemonResponse> {
    let socket_path = crate::daemon::daemon_socket_path(session_id);
    let mut stream = UnixStream::connect(&socket_path)?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;

    let mut json_val = serde_json::to_value(request)?;
    if let serde_json::Value::Object(ref mut map) = json_val {
        map.insert("v".into(), serde_json::json!(crate::daemon::DAEMON_PROTOCOL_VERSION));
    }
    let mut json = serde_json::to_string(&json_val)?;
    json.push('\n');
    stream.write_all(json.as_bytes())?;
    stream.flush()?;

    let mut reader = BufReader::new(&stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line)?;

    Ok(serde_json::from_str(&response_line)?)
}

pub fn try_send_request(session_id: &str, request: &DaemonRequest) -> Option<DaemonResponse> {
    send_request(session_id, request).ok()
}

pub fn is_daemon_running(session_id: &str) -> bool {
    let socket_path = crate::daemon::daemon_socket_path(session_id);
    if !socket_path.exists() {
        return false;
    }
    UnixStream::connect(&socket_path)
        .and_then(|s| {
            s.set_write_timeout(Some(Duration::from_millis(100)))?;
            Ok(s)
        })
        .is_ok()
}
