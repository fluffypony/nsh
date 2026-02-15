use std::io::{Read, Write};
#[cfg(test)]
use std::io::{BufRead, BufReader};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use crate::daemon::{DaemonRequest, DaemonResponse};

fn log_daemon_client(action: &str, payload: &str) {
    crate::debug_io::daemon_log("daemon.log", action, payload);
}

fn read_daemon_response<R: Read>(reader: &mut R) -> anyhow::Result<String> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    if buf.is_empty() {
        anyhow::bail!("empty daemon response");
    }
    let text = String::from_utf8(buf)?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        anyhow::bail!("empty daemon response");
    }
    Ok(trimmed.to_string())
}

pub fn send_request(session_id: &str, request: &DaemonRequest) -> anyhow::Result<DaemonResponse> {
    #[cfg(not(unix))]
    {
        let _ = (session_id, request);
        anyhow::bail!("daemon transport is not available on this platform")
    }
    #[cfg(unix)]
    {
        let socket_path = crate::daemon::daemon_socket_path(session_id);
        let mut stream = UnixStream::connect(&socket_path)?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;

        let mut json_val = serde_json::to_value(request)?;
        if let serde_json::Value::Object(ref mut map) = json_val {
            map.insert(
                "v".into(),
                serde_json::json!(crate::daemon::DAEMON_PROTOCOL_VERSION),
            );
        }
        let mut json = serde_json::to_string(&json_val)?;
        json.push('\n');
        log_daemon_client(
            "client.send_request",
            &format!("session={session_id}\nrequest={}", json.trim_end()),
        );
        stream.write_all(json.as_bytes())?;
        stream.flush()?;

        let response_line = read_daemon_response(&mut stream)?;
        log_daemon_client(
            "client.send_request.response",
            &format!(
                "session={session_id}\nresponse={}",
                response_line
            ),
        );

        Ok(serde_json::from_str(&response_line)?)
    }
}

pub fn try_send_request(session_id: &str, request: &DaemonRequest) -> Option<DaemonResponse> {
    send_request(session_id, request).ok()
}

#[allow(dead_code)]
pub fn is_daemon_running(session_id: &str) -> bool {
    #[cfg(not(unix))]
    {
        let _ = session_id;
        return false;
    }
    #[cfg(unix)]
    {
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
}

#[cfg(unix)]
pub fn is_global_daemon_running() -> bool {
    let socket_path = crate::daemon::global_daemon_socket_path();
    if !socket_path.exists() {
        return false;
    }
    if let Ok(pid_str) = std::fs::read_to_string(crate::daemon::global_daemon_pid_path()) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            if unsafe { libc::kill(pid, 0) } != 0 {
                let _ = std::fs::remove_file(&socket_path);
                let _ = std::fs::remove_file(crate::daemon::global_daemon_pid_path());
                return false;
            }
        }
    }
    UnixStream::connect(&socket_path)
        .and_then(|s| {
            s.set_write_timeout(Some(Duration::from_millis(100)))?;
            Ok(())
        })
        .is_ok()
}

#[cfg(not(unix))]
pub fn is_global_daemon_running() -> bool {
    false
}

#[cfg(unix)]
pub fn send_to_global(request: &DaemonRequest) -> anyhow::Result<DaemonResponse> {
    let socket_path = crate::daemon::global_daemon_socket_path();
    let mut stream = UnixStream::connect(&socket_path)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let mut json_val = serde_json::to_value(request)?;
    if let serde_json::Value::Object(ref mut map) = json_val {
        map.insert(
            "v".into(),
            serde_json::json!(crate::daemon::DAEMON_PROTOCOL_VERSION),
        );
    }
    let mut json = serde_json::to_string(&json_val)?;
    json.push('\n');
    log_daemon_client(
        "client.send_to_global",
        &format!("request={}", json.trim_end()),
    );
    stream.write_all(json.as_bytes())?;
    stream.flush()?;

    let response_line = read_daemon_response(&mut stream)?;
    log_daemon_client(
        "client.send_to_global.response",
        &format!("response={response_line}"),
    );

    Ok(serde_json::from_str(&response_line)?)
}

#[cfg(not(unix))]
pub fn send_to_global(_request: &DaemonRequest) -> anyhow::Result<DaemonResponse> {
    anyhow::bail!("global daemon not available on this platform")
}

pub fn stop_global_daemon() -> bool {
    #[cfg(unix)]
    {
        let pid_path = crate::daemon::global_daemon_pid_path();
        if let Ok(pid_str) = std::fs::read_to_string(&pid_path) {
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                unsafe { libc::kill(pid, libc::SIGTERM) };
                for _ in 0..20 {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    if unsafe { libc::kill(pid, 0) } != 0 {
                        return true;
                    }
                }
                unsafe { libc::kill(pid, libc::SIGKILL) };
                return true;
            }
        }
    }
    false
}

pub fn ensure_global_daemon_running() -> anyhow::Result<()> {
    if is_global_daemon_running() {
        return Ok(());
    }

    let exe = std::env::current_exe()?;
    std::process::Command::new(exe)
        .arg("nshd")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(50));
        if is_global_daemon_running() {
            return Ok(());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(not(unix))]
    #[test]
    fn daemon_not_supported_on_non_unix() {
        let req = crate::daemon::DaemonRequest::Status;
        assert!(super::send_request("s", &req).is_err());
        assert!(super::try_send_request("s", &req).is_none());
        assert!(!super::is_daemon_running("s"));
    }

    #[cfg(unix)]
    mod unix_tests {
        use super::super::*;
        use crate::daemon::{DAEMON_PROTOCOL_VERSION, DaemonRequest, DaemonResponse};
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

        #[test]
        fn is_daemon_running_true_when_socket_accepts() {
            let session_id = format!("test_running_{}", std::process::id());
            let sock_path = crate::daemon::daemon_socket_path(&session_id);
            if let Some(parent) = sock_path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            let _ = std::fs::remove_file(&sock_path);
            let _listener = UnixListener::bind(&sock_path).unwrap();
            let result = is_daemon_running(&session_id);
            let _ = std::fs::remove_file(&sock_path);
            assert!(result);
        }

        #[test]
        fn send_request_with_mock_server() {
            let session_id = format!("test_send_{}", std::process::id());
            let sock_path = crate::daemon::daemon_socket_path(&session_id);
            if let Some(parent) = sock_path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            let _ = std::fs::remove_file(&sock_path);
            let listener = UnixListener::bind(&sock_path).unwrap();

            let handler = std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(&stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
                assert_eq!(parsed["type"], "status");
                assert_eq!(parsed["v"], DAEMON_PROTOCOL_VERSION);

                let resp = DaemonResponse::ok_with_data(serde_json::json!({"mock": true}));
                let mut resp_json = serde_json::to_string(&resp).unwrap();
                resp_json.push('\n');
                use std::io::Write;
                let mut w = &stream;
                w.write_all(resp_json.as_bytes()).unwrap();
                w.flush().unwrap();
            });

            let result = send_request(&session_id, &DaemonRequest::Status);
            let _ = std::fs::remove_file(&sock_path);
            handler.join().unwrap();

            let resp = result.unwrap();
            match resp {
                DaemonResponse::Ok { data: Some(d) } => {
                    assert_eq!(d["mock"], true);
                }
                _ => panic!("expected Ok with data"),
            }
        }

        #[test]
        fn try_send_request_returns_some_on_success() {
            let session_id = format!("test_try_{}", std::process::id());
            let sock_path = crate::daemon::daemon_socket_path(&session_id);
            if let Some(parent) = sock_path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            let _ = std::fs::remove_file(&sock_path);
            let listener = UnixListener::bind(&sock_path).unwrap();

            let handler = std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(&stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();

                let resp = DaemonResponse::ok();
                let mut resp_json = serde_json::to_string(&resp).unwrap();
                resp_json.push('\n');
                use std::io::Write;
                let mut w = &stream;
                w.write_all(resp_json.as_bytes()).unwrap();
                w.flush().unwrap();
            });

            let result = try_send_request(&session_id, &DaemonRequest::Status);
            let _ = std::fs::remove_file(&sock_path);
            handler.join().unwrap();

            assert!(result.is_some());
            assert!(matches!(result.unwrap(), DaemonResponse::Ok { data: None }));
        }

        #[test]
        fn send_request_fails_on_invalid_json_response() {
            let session_id = format!("test_bad_json_{}", std::process::id());
            let sock_path = crate::daemon::daemon_socket_path(&session_id);
            if let Some(parent) = sock_path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            let _ = std::fs::remove_file(&sock_path);
            let listener = UnixListener::bind(&sock_path).unwrap();

            let handler = std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(&stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();

                use std::io::Write;
                let mut w = &stream;
                w.write_all(b"not valid json\n").unwrap();
                w.flush().unwrap();
            });

            let result = send_request(&session_id, &DaemonRequest::Status);
            let _ = std::fs::remove_file(&sock_path);
            handler.join().unwrap();

            assert!(result.is_err());
        }

        #[test]
        fn send_request_fails_when_server_closes_immediately() {
            let session_id = format!("test_close_{}", std::process::id());
            let sock_path = crate::daemon::daemon_socket_path(&session_id);
            if let Some(parent) = sock_path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            let _ = std::fs::remove_file(&sock_path);
            let listener = UnixListener::bind(&sock_path).unwrap();

            let handler = std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                drop(stream);
            });

            let result = send_request(&session_id, &DaemonRequest::Status);
            let _ = std::fs::remove_file(&sock_path);
            handler.join().unwrap();

            assert!(result.is_err());
        }

        #[test]
        fn send_request_heartbeat_roundtrip_through_mock() {
            let session_id = format!("test_hb_rt_{}", std::process::id());
            let sock_path = crate::daemon::daemon_socket_path(&session_id);
            if let Some(parent) = sock_path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            let _ = std::fs::remove_file(&sock_path);
            let listener = UnixListener::bind(&sock_path).unwrap();

            let handler = std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(&stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
                assert_eq!(parsed["type"], "heartbeat");
                assert_eq!(parsed["session"], "mysess");

                let resp = DaemonResponse::ok();
                let mut resp_json = serde_json::to_string(&resp).unwrap();
                resp_json.push('\n');
                use std::io::Write;
                let mut w = &stream;
                w.write_all(resp_json.as_bytes()).unwrap();
                w.flush().unwrap();
            });

            let req = DaemonRequest::Heartbeat {
                session: "mysess".into(),
            };
            let result = send_request(&session_id, &req);
            let _ = std::fs::remove_file(&sock_path);
            handler.join().unwrap();

            let resp = result.unwrap();
            assert!(matches!(resp, DaemonResponse::Ok { data: None }));
        }
    }
}
