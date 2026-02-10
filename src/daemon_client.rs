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
        map.insert(
            "v".into(),
            serde_json::json!(crate::daemon::DAEMON_PROTOCOL_VERSION),
        );
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

#[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::{DaemonRequest, DaemonResponse, DAEMON_PROTOCOL_VERSION};
    use std::os::unix::net::UnixListener;

    #[test]
    fn send_request_fails_when_no_socket() {
        let result = send_request("nonexistent_session_xyz", &DaemonRequest::Status);
        assert!(result.is_err());
    }

    #[test]
    fn try_send_request_returns_none_when_no_socket() {
        let result = try_send_request("nonexistent_session_xyz", &DaemonRequest::Status);
        assert!(result.is_none());
    }

    #[test]
    fn is_daemon_running_returns_false_for_nonexistent_session() {
        assert!(!is_daemon_running("nonexistent_session_xyz"));
    }

    #[test]
    fn send_request_includes_protocol_version() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();

        let sock = sock_path.clone();
        let handler = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(&stream);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(parsed["v"], DAEMON_PROTOCOL_VERSION);

            let resp = DaemonResponse::ok();
            let mut resp_json = serde_json::to_string(&resp).unwrap();
            resp_json.push('\n');
            use std::io::Write;
            let mut w = &stream;
            w.write_all(resp_json.as_bytes()).unwrap();
            w.flush().unwrap();
        });

        let mut stream = UnixStream::connect(&sock).unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let request = DaemonRequest::Status;
        let mut json_val = serde_json::to_value(&request).unwrap();
        if let serde_json::Value::Object(ref mut map) = json_val {
            map.insert("v".into(), serde_json::json!(DAEMON_PROTOCOL_VERSION));
        }
        let mut json = serde_json::to_string(&json_val).unwrap();
        json.push('\n');
        stream.write_all(json.as_bytes()).unwrap();
        stream.flush().unwrap();

        let mut reader = BufReader::new(&stream);
        let mut response_line = String::new();
        reader.read_line(&mut response_line).unwrap();
        let resp: DaemonResponse = serde_json::from_str(&response_line).unwrap();
        assert!(matches!(resp, DaemonResponse::Ok { .. }));

        handler.join().unwrap();
    }

    #[test]
    fn send_request_roundtrip_with_mock_server() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("roundtrip.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();

        let sock = sock_path.clone();
        let handler = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(&stream);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();

            let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(parsed["type"], "heartbeat");
            assert_eq!(parsed["session"], "sess-42");

            let resp =
                DaemonResponse::ok_with_data(serde_json::json!({"received": parsed["type"]}));
            let mut resp_json = serde_json::to_string(&resp).unwrap();
            resp_json.push('\n');
            use std::io::Write;
            let mut w = &stream;
            w.write_all(resp_json.as_bytes()).unwrap();
            w.flush().unwrap();
        });

        let mut stream = UnixStream::connect(&sock).unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let request = DaemonRequest::Heartbeat {
            session: "sess-42".into(),
        };
        let mut json_val = serde_json::to_value(&request).unwrap();
        if let serde_json::Value::Object(ref mut map) = json_val {
            map.insert("v".into(), serde_json::json!(DAEMON_PROTOCOL_VERSION));
        }
        let mut json = serde_json::to_string(&json_val).unwrap();
        json.push('\n');
        stream.write_all(json.as_bytes()).unwrap();
        stream.flush().unwrap();

        let mut reader = BufReader::new(&stream);
        let mut response_line = String::new();
        reader.read_line(&mut response_line).unwrap();
        let resp: DaemonResponse = serde_json::from_str(&response_line).unwrap();
        match resp {
            DaemonResponse::Ok { data: Some(d) } => {
                assert_eq!(d["received"], "heartbeat");
            }
            _ => panic!("expected Ok with data"),
        }

        handler.join().unwrap();
    }

    #[test]
    fn send_request_error_response_from_server() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("error.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();

        let sock = sock_path.clone();
        let handler = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(&stream);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();

            let resp = DaemonResponse::error("test error message");
            let mut resp_json = serde_json::to_string(&resp).unwrap();
            resp_json.push('\n');
            use std::io::Write;
            let mut w = &stream;
            w.write_all(resp_json.as_bytes()).unwrap();
            w.flush().unwrap();
        });

        let mut stream = UnixStream::connect(&sock).unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let request = DaemonRequest::Status;
        let mut json_val = serde_json::to_value(&request).unwrap();
        if let serde_json::Value::Object(ref mut map) = json_val {
            map.insert("v".into(), serde_json::json!(DAEMON_PROTOCOL_VERSION));
        }
        let mut json = serde_json::to_string(&json_val).unwrap();
        json.push('\n');
        stream.write_all(json.as_bytes()).unwrap();
        stream.flush().unwrap();

        let mut reader = BufReader::new(&stream);
        let mut response_line = String::new();
        reader.read_line(&mut response_line).unwrap();
        let resp: DaemonResponse = serde_json::from_str(&response_line).unwrap();
        match resp {
            DaemonResponse::Error { message } => {
                assert_eq!(message, "test error message");
            }
            _ => panic!("expected Error response"),
        }

        handler.join().unwrap();
    }

    #[test]
    fn is_daemon_running_false_for_socket_path_that_does_not_exist() {
        let id = format!("test_no_daemon_{}", std::process::id());
        assert!(!is_daemon_running(&id));
    }
}
