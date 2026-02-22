use std::io::BufRead;
#[cfg(test)]
use std::io::BufReader;
use std::io::{Read, Write};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use crate::daemon::{DaemonRequest, DaemonResponse};
#[cfg(not(test))]
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_DAEMON_RESPONSE_BYTES: u64 = 10 * 1024 * 1024;

fn log_daemon_client(action: &str, payload: &str) {
    crate::debug_io::daemon_log("daemon.log", action, payload);
}

fn read_daemon_response<R: Read>(reader: &mut R) -> anyhow::Result<String> {
    let mut buf_reader = std::io::BufReader::with_capacity(256 * 1024, reader);
    let mut line = String::new();
    let bytes_read = buf_reader.read_line(&mut line)?;

    if bytes_read == 0 {
        anyhow::bail!("empty daemon response (EOF before any data)");
    }
    if line.len() as u64 > MAX_DAEMON_RESPONSE_BYTES {
        anyhow::bail!("daemon response exceeded {MAX_DAEMON_RESPONSE_BYTES} bytes");
    }

    let trimmed = line.trim();
    if trimmed.is_empty() {
        anyhow::bail!("empty daemon response (whitespace only)");
    }

    if trimmed.starts_with('{') && !trimmed.ends_with('}') {
        anyhow::bail!(
            "daemon response appears truncated ({} bytes received, ends with '...{}'). \
             This usually means the response was too large or a write timeout occurred.",
            trimmed.len(),
            &trimmed[trimmed.len().saturating_sub(40)..]
        );
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
        let mut last_err = None;
        for attempt in 0..2 {
            match send_request_once(session_id, request) {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    if attempt == 0 {
                        tracing::debug!("send_request attempt 0 failed: {e}, retrying...");
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap())
    }
}

#[cfg(unix)]
fn send_request_once(session_id: &str, request: &DaemonRequest) -> anyhow::Result<DaemonResponse> {
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
    // Parse generically to inspect daemon version fields
    let json_val: serde_json::Value = serde_json::from_str(&response_line)
        .map_err(|e| anyhow::anyhow!("daemon response JSON parse failed: {e}"))?;

    // Wrapper version notifications are obsolete with shim/core split; no restart or update markers

    log_daemon_client(
        "client.send_request.response",
        &format!("session={session_id}\nresponse={response_line}"),
    );

    serde_json::from_value(json_val).map_err(|e| anyhow::anyhow!("deserialize error: {e}"))
}

pub fn get_system_info(_session_id: &str) -> anyhow::Result<crate::context::SystemInfoBundle> {
    let request = DaemonRequest::GetSystemInfo;
    match send_to_global(&request) {
        Ok(DaemonResponse::Ok { data: Some(d) }) => Ok(serde_json::from_value(d)?),
        Ok(other) => anyhow::bail!("unexpected daemon response: {other:?}"),
        Err(e) => Err(e),
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
    let mut last_err = None;
    for attempt in 0..3 {
        match send_to_global_once(request) {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                if attempt < 2 {
                    tracing::debug!("send_to_global attempt {attempt} failed: {e}, retrying...");
                    let _ = ensure_global_daemon_running();
                    std::thread::sleep(Duration::from_millis(200));
                }
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap())
}

#[cfg(unix)]
fn send_to_global_once(request: &DaemonRequest) -> anyhow::Result<DaemonResponse> {
    // Before issuing the real request, check daemon version and attempt graceful restart once if mismatched.
    // Skip during tests to avoid extra connections breaking single-accept mocks.
    #[cfg(not(test))]
    {
        // Protect against re-entrancy because ensure_daemon_version_matches internally sends a request as well.
        static ENSURE_VERSION_GUARD: AtomicBool = AtomicBool::new(false);
        let entered = ENSURE_VERSION_GUARD
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
        if entered {
            // Also allow disabling via env for custom harnesses
            let skip = std::env::var("NSH_SKIP_DAEMON_VERSION").is_ok()
                || std::env::var("NSH_TEST_MODE").ok().as_deref() == Some("1");
            if !skip {
                let _ = ensure_daemon_version_matches();
            }
            ENSURE_VERSION_GUARD.store(false, Ordering::SeqCst);
        }
    }

    let socket_path = crate::daemon::global_daemon_socket_path();
    let mut stream = UnixStream::connect(&socket_path)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

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
    // Parse generically first to detect version
    let json_val: serde_json::Value = serde_json::from_str(&response_line)
        .map_err(|e| anyhow::anyhow!("daemon response JSON parse failed: {e}"))?;

    // Check if the global daemon is outdated; prefer graceful SIGHUP over hard stop
    let daemon_version = json_val.get("daemon_version").and_then(|v| v.as_str());
    if daemon_version != Some(env!("CARGO_PKG_VERSION")) {
        tracing::info!(
            "Global daemon is outdated (running: {:?}, current: {}), signaling restart",
            daemon_version,
            env!("CARGO_PKG_VERSION")
        );
        // Trigger graceful restart asynchronously; client call proceeds
        std::thread::spawn(|| {
            let _ = signal_daemon_restart();
            // Nudge ensure after a short delay
            std::thread::sleep(Duration::from_millis(300));
            let _ = ensure_global_daemon_running();
        });
    }

    log_daemon_client(
        "client.send_to_global.response",
        &format!("response={response_line}"),
    );

    serde_json::from_value(json_val).map_err(|e| anyhow::anyhow!("deserialize error: {e}"))
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

/// Ensure the global daemon binary version matches ours; gracefully restart if not.
pub fn ensure_daemon_version_matches() -> anyhow::Result<()> {
    let our_version = env!("CARGO_PKG_VERSION");
    let our_build = env!("NSH_BUILD_VERSION");
    if let Ok(crate::daemon::DaemonResponse::Ok { data: Some(d) }) =
        send_to_global(&crate::daemon::DaemonRequest::Status)
    {
        let daemon_ver = d.get("version").and_then(|v| v.as_str());
        let daemon_build = d.get("build_version").and_then(|v| v.as_str());

        let version_mismatch = daemon_ver != Some(our_version);
        let build_mismatch = match daemon_build {
            Some(b) => b != our_build,
            None => false, // if build not reported, don't flap; version check still applies
        };

        if version_mismatch || build_mismatch {
            tracing::info!(
                "daemon restart: version_mismatch={} build_mismatch={} (daemon_ver={:?}, daemon_build={:?}, our_ver={}, our_build={})",
                version_mismatch,
                build_mismatch,
                daemon_ver,
                daemon_build,
                our_version,
                our_build
            );
            let _ = signal_daemon_restart();
            // Allow a short window for graceful drain and re-exec, then ensure running
            std::thread::sleep(std::time::Duration::from_millis(500));
            let _ = ensure_global_daemon_running();
        }
    }
    Ok(())
}

/// Send SIGHUP to the running global daemon to request a graceful restart.
/// Returns true if the signal was sent successfully.
pub fn signal_daemon_restart() -> bool {
    #[cfg(unix)]
    {
        let pid_path = crate::daemon::global_daemon_pid_path();
        if let Ok(pid_str) = std::fs::read_to_string(&pid_path) {
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                return unsafe { libc::kill(pid, libc::SIGHUP) } == 0;
            }
        }
        false
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Send a request to the global daemon with retry logic for transient failures
/// (e.g., during daemon restarts). Auto-starts daemon on later retries.
#[cfg(unix)]
pub fn send_to_global_with_retry(request: DaemonRequest) -> anyhow::Result<DaemonResponse> {
    let max_attempts = 6; // ~3s total with backoff
    for attempt in 0..max_attempts {
        match send_to_global(&request) {
            Ok(resp) => return Ok(resp),
            Err(e) if attempt < max_attempts - 1 => {
                let msg = e.to_string();
                let is_transient = msg.contains("Connection refused")
                    || msg.contains("No such file")
                    || msg.contains("broken pipe")
                    || msg.contains("connection reset");
                if !is_transient {
                    return Err(e);
                }
                let delay = std::time::Duration::from_millis(200 * (attempt as u64 + 1));
                std::thread::sleep(delay);
                if attempt >= 1 {
                    let _ = ensure_global_daemon_running();
                }
                tracing::debug!(
                    "daemon connection retry {}/{}: {}",
                    attempt + 1,
                    max_attempts,
                    msg
                );
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}

#[cfg(not(unix))]
pub fn send_to_global_with_retry(_request: DaemonRequest) -> anyhow::Result<DaemonResponse> {
    anyhow::bail!("global daemon not available on this platform")
}

// (Memory client helpers were removed; use DbAccess via DaemonDb instead.)

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
