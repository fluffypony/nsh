use std::os::fd::BorrowedFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use signal_hook::iterator::Signals;

pub struct CaptureEngine {
    parser: vt100::Parser,
    in_alternate_screen: bool,
    rate_window_start: Instant,
    rate_bytes: usize,
    rate_limit_bps: usize,
    paused_until: Option<Instant>,
    pause_seconds: u64,
    suppressed: bool,
}

impl CaptureEngine {
    pub fn new(
        rows: u16,
        cols: u16,
        rate_limit_bps: usize,
        pause_seconds: u64,
        max_scrollback_lines: usize,
    ) -> Self {
        Self {
            parser: vt100::Parser::new(rows, cols, max_scrollback_lines),
            in_alternate_screen: false,
            rate_window_start: Instant::now(),
            rate_bytes: 0,
            rate_limit_bps,
            paused_until: None,
            pause_seconds,
            suppressed: false,
        }
    }

    pub fn process(&mut self, bytes: &[u8]) {
        if let Some(until) = self.paused_until {
            if Instant::now() < until {
                return;
            }
            self.paused_until = None;
            self.rate_bytes = 0;
            self.rate_window_start = Instant::now();
        }

        let elapsed = self.rate_window_start.elapsed();
        if elapsed >= Duration::from_secs(1) {
            self.rate_bytes = 0;
            self.rate_window_start = Instant::now();
        }
        self.rate_bytes += bytes.len();
        if self.rate_limit_bps > 0 && self.rate_bytes > self.rate_limit_bps {
            self.paused_until =
                Some(Instant::now() + Duration::from_secs(self.pause_seconds));
            self.suppressed = true;
            return;
        }

        let sanitized = sanitize_input(bytes);
        self.parser.process(&sanitized);

        let now_alt = self.parser.screen().alternate_screen();
        if now_alt {
            self.in_alternate_screen = true;
        } else if self.in_alternate_screen {
            self.in_alternate_screen = false;
        }
    }

    pub fn get_lines(&mut self, max_lines: usize) -> String {
        if self.parser.screen().alternate_screen() {
            return String::new();
        }

        let (rows, _) = self.parser.screen().size();
        let rows = rows as usize;

        self.parser.screen_mut().set_scrollback(usize::MAX);
        let total_scrollback = self.parser.screen().scrollback();

        let mut all_lines: Vec<String> = Vec::new();

        if self.suppressed {
            all_lines.push("[nsh: output capture suppressed (high output rate)]".into());
            self.suppressed = false;
        }

        if total_scrollback > 0 {
            let mut offset = total_scrollback;
            loop {
                self.parser.screen_mut().set_scrollback(offset);
                let page = self.parser.screen().contents();
                let page_lines: Vec<&str> = page.lines().collect();
                let unique_count = offset.min(rows).min(page_lines.len());
                // Intentionally drop blank lines from scrollback history
                // to reduce noise; visible screen lines are kept as-is.
                for line in page_lines.iter().take(unique_count) {
                    if !line.trim().is_empty() {
                        all_lines.push(line.to_string());
                    }
                }
                if offset <= rows {
                    break;
                }
                offset = offset.saturating_sub(rows);
            }
        }

        self.parser.screen_mut().set_scrollback(0);
        let visible = self.parser.screen().contents();
        for line in visible.lines() {
            all_lines.push(line.to_string());
        }

        let combined = all_lines.join("\n")
            .replace("\r\n", "\n")
            .replace('\r', "")
            .replace("\x1b[200~", "")
            .replace("\x1b[201~", "");

        let final_lines: Vec<&str> = combined.lines().collect();
        let start = final_lines.len().saturating_sub(max_lines);
        final_lines[start..].join("\n")
    }

    pub fn set_size(&mut self, rows: u16, cols: u16) {
        self.parser.screen_mut().set_size(rows, cols);
    }
}

fn sanitize_input(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .copied()
        .filter(|&b| {
            matches!(
                b,
                0x0A | 0x0D | 0x09 | 0x1B | 0x08 | 0x20..=0x7E | 0x80..=0xFF
            )
        })
        .collect()
}

fn write_all(fd: &BorrowedFd, mut data: &[u8]) -> std::io::Result<()> {
    while !data.is_empty() {
        match rustix::io::write(fd, data) {
            Ok(n) => data = &data[n..],
            Err(e) if e == rustix::io::Errno::INTR => continue,
            Err(e) => return Err(std::io::Error::from_raw_os_error(e.raw_os_error())),
        }
    }
    Ok(())
}

fn child_exited(pid: rustix::process::Pid) -> bool {
    match rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG) {
        Ok(Some(_status)) => true,
        Ok(None) => false,
        Err(e) if e == rustix::io::Errno::INTR => false,
        Err(_) => true,
    }
}

use signal_hook::iterator::backend::Handle as SignalHandle;

struct SignalThread {
    handle: SignalHandle,
    join: std::thread::JoinHandle<()>,
}

impl SignalThread {
    fn close_and_join(self) {
        self.handle.close();
        let _ = self.join.join();
    }
}

fn spawn_signal_thread(
    child_pid: rustix::process::Pid,
    stdin_fd: libc::c_int,
    pty_master_fd: libc::c_int,
    winch_pending: Arc<AtomicBool>,
) -> SignalThread {
    let raw_pid = child_pid.as_raw_nonzero().get();

    let mut signals = Signals::new(&[
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGHUP,
        signal_hook::consts::SIGWINCH,
        signal_hook::consts::SIGCONT,
    ])
    .expect("failed to register signal handlers");

    let handle = signals.handle();

    let join = std::thread::spawn(move || {
        for sig in signals.forever() {
            match sig {
                signal_hook::consts::SIGWINCH => {
                    unsafe {
                        let mut ws: libc::winsize = std::mem::zeroed();
                        if libc::ioctl(stdin_fd, libc::TIOCGWINSZ, &mut ws) == 0 {
                            libc::ioctl(pty_master_fd, libc::TIOCSWINSZ, &ws);
                        }
                        libc::kill(raw_pid, libc::SIGWINCH);
                    }
                    winch_pending.store(true, Ordering::Relaxed);
                }
                signal_hook::consts::SIGCONT => {
                    unsafe {
                        let mut ws: libc::winsize = std::mem::zeroed();
                        if libc::ioctl(stdin_fd, libc::TIOCGWINSZ, &mut ws) == 0 {
                            libc::ioctl(pty_master_fd, libc::TIOCSWINSZ, &ws);
                        }
                        libc::kill(raw_pid, libc::SIGCONT);
                    }
                    winch_pending.store(true, Ordering::Relaxed);
                }
                _ => {
                    unsafe { libc::kill(raw_pid, sig) };
                }
            }
        }
    });

    SignalThread { handle, join }
}

pub fn pump_loop(
    real_stdin: BorrowedFd,
    real_stdout: BorrowedFd,
    pty_master: BorrowedFd,
    capture: &Mutex<CaptureEngine>,
    child_pid: rustix::process::Pid,
) {
    use rustix::event::{poll, PollFd, PollFlags, Timespec};
    use std::os::fd::AsRawFd;

    let stdin_raw = real_stdin.as_raw_fd();
    let pty_master_raw = pty_master.as_raw_fd();
    let winch_pending = Arc::new(AtomicBool::new(false));
    let signal_thread = spawn_signal_thread(
        child_pid,
        stdin_raw,
        pty_master_raw,
        winch_pending.clone(),
    );

    unsafe {
        libc::signal(libc::SIGTSTP, libc::SIG_IGN);
        libc::signal(libc::SIGTTIN, libc::SIG_IGN);
        libc::signal(libc::SIGTTOU, libc::SIG_IGN);
    }

    let session_id =
        std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "default".into());

    let nsh_dir = crate::config::Config::nsh_dir();
    let _ = std::fs::create_dir_all(&nsh_dir);

    let socket_path = nsh_dir
        .join(format!("scrollback_{session_id}.sock"));
    let _ = std::fs::remove_file(&socket_path);
    let listener = match std::os::unix::net::UnixListener::bind(&socket_path) {
        Ok(l) => {
            l.set_nonblocking(true).ok();
            Some(l)
        }
        Err(_) => None,
    };

    let daemon_socket_path = crate::daemon::daemon_socket_path(&session_id);
    let _ = std::fs::remove_file(&daemon_socket_path);
    let daemon_listener = match std::os::unix::net::UnixListener::bind(&daemon_socket_path) {
        Ok(l) => {
            l.set_nonblocking(true).ok();
            Some(l)
        }
        Err(_) => None,
    };

    let (db_tx, db_rx) = std::sync::mpsc::channel();
    let db_thread = std::thread::spawn(move || {
        crate::daemon::run_db_thread(db_rx);
    });

    let pid_path = crate::daemon::daemon_pid_path(&session_id);
    let tmp_pid = pid_path.with_extension("tmp");
    if let Ok(()) = std::fs::write(&tmp_pid, format!("{}", std::process::id())) {
        let _ = std::fs::rename(&tmp_pid, &pid_path);
    }

    let scrollback_path = nsh_dir.join(format!("scrollback_{session_id}"));
    let redact_active_path = nsh_dir.join(format!("redact_active_{session_id}"));

    let mut buf = [0u8; 8192];
    let mut last_activity = Instant::now();
    let mut last_flush = Instant::now();

    loop {
        if winch_pending.swap(false, Ordering::Relaxed) {
            let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
            if unsafe { libc::ioctl(stdin_raw, libc::TIOCGWINSZ, &mut ws) } == 0 {
                if let Ok(mut eng) = capture.lock() {
                    eng.set_size(ws.ws_row, ws.ws_col);
                }
            }
        }

        let idle = last_activity.elapsed() > Duration::from_secs(5);
        let timeout_ns = if idle { 1_000_000_000 } else { 10_000_000 };
        let timeout = Timespec {
            tv_sec: timeout_ns / 1_000_000_000,
            tv_nsec: timeout_ns % 1_000_000_000,
        };

        let mut poll_fds: Vec<PollFd> = vec![
            PollFd::new(&real_stdin, PollFlags::IN),
            PollFd::new(&pty_master, PollFlags::IN),
        ];

        let legacy_idx = listener.as_ref().map(|l| {
            let idx = poll_fds.len();
            poll_fds.push(PollFd::from_borrowed_fd(
                unsafe { BorrowedFd::borrow_raw(std::os::fd::AsRawFd::as_raw_fd(l)) },
                PollFlags::IN,
            ));
            idx
        });

        let daemon_idx = daemon_listener.as_ref().map(|l| {
            let idx = poll_fds.len();
            poll_fds.push(PollFd::from_borrowed_fd(
                unsafe { BorrowedFd::borrow_raw(std::os::fd::AsRawFd::as_raw_fd(l)) },
                PollFlags::IN,
            ));
            idx
        });

        match poll(&mut poll_fds, Some(&timeout)) {
            Ok(0) => {
                if child_exited(child_pid) {
                    break;
                }
                continue;
            }
            Ok(_) => {
                if handle_io(
                    &poll_fds[0], &poll_fds[1], &real_stdin, &real_stdout, &pty_master,
                    &mut buf, capture, &mut last_activity, &mut last_flush,
                    &scrollback_path, &redact_active_path,
                ) {
                    break;
                }

                if let (Some(idx), Some(l)) = (legacy_idx, listener.as_ref()) {
                    if poll_fds[idx].revents().contains(PollFlags::IN) {
                        handle_socket_connection(l, capture);
                    }
                }

                if let (Some(idx), Some(l)) = (daemon_idx, daemon_listener.as_ref()) {
                    if poll_fds[idx].revents().contains(PollFlags::IN) {
                        handle_daemon_connection(l, capture, &db_tx);
                    }
                }
            }
            Err(e) => {
                if e == rustix::io::Errno::INTR {
                    continue;
                }
                continue;
            }
        }
    }

    let _ = db_tx.send(crate::daemon::DbCommand::Shutdown);
    let _ = db_thread.join();
    signal_thread.close_and_join();
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&daemon_socket_path);
    let _ = std::fs::remove_file(&pid_path);
    let _ = std::fs::remove_file(&scrollback_path);
}

fn handle_io(
    stdin_poll: &rustix::event::PollFd,
    pty_poll: &rustix::event::PollFd,
    real_stdin: &BorrowedFd,
    real_stdout: &BorrowedFd,
    pty_master: &BorrowedFd,
    buf: &mut [u8],
    capture: &Mutex<CaptureEngine>,
    last_activity: &mut Instant,
    last_flush: &mut Instant,
    scrollback_path: &std::path::Path,
    redact_active_path: &std::path::Path,
) -> bool {
    use rustix::event::PollFlags;

    if stdin_poll.revents().contains(PollFlags::IN) {
        match rustix::io::read(real_stdin, &mut *buf) {
            Ok(0) => return true,
            Ok(n) => {
                let _ = write_all(pty_master, &buf[..n]);
                *last_activity = Instant::now();
            }
            Err(e) if e == rustix::io::Errno::INTR || e == rustix::io::Errno::AGAIN => {}
            Err(_) => return true,
        }
    }

    if pty_poll.revents().contains(PollFlags::IN) {
        match rustix::io::read(pty_master, &mut *buf) {
            Ok(0) => return true,
            Ok(n) => {
                let _ = write_all(real_stdout, &buf[..n]);
                *last_activity = Instant::now();
                let redacting = redact_active_path.exists();
                if !redacting {
                    if let Ok(mut eng) = capture.lock() {
                        eng.process(&buf[..n]);
                        if last_flush.elapsed() >= Duration::from_secs(2) {
                            let text = eng.get_lines(1000);
                            let tmp = scrollback_path.with_extension("tmp");
                            if let Ok(()) = std::fs::write(&tmp, &text) {
                                let _ = std::fs::rename(&tmp, scrollback_path);
                            }
                            *last_flush = Instant::now();
                        }
                    }
                }
            }
            Err(e) if e == rustix::io::Errno::INTR || e == rustix::io::Errno::AGAIN => {}
            Err(_) => return true,
        }
    }

    if pty_poll.revents().contains(PollFlags::HUP) {
        return true;
    }

    false
}

fn handle_socket_connection(
    listener: &std::os::unix::net::UnixListener,
    capture: &Mutex<CaptureEngine>,
) {
    use std::io::Write;

    if let Ok((mut stream, _)) = listener.accept() {
        stream.set_write_timeout(Some(Duration::from_secs(2))).ok();
        if let Ok(mut eng) = capture.lock() {
            let text = eng.get_lines(1000);
            let _ = stream.write_all(text.as_bytes());
        }
    }
}

fn handle_daemon_connection(
    listener: &std::os::unix::net::UnixListener,
    capture: &Mutex<CaptureEngine>,
    db_tx: &std::sync::mpsc::Sender<crate::daemon::DbCommand>,
) {
    use std::io::{BufRead, BufReader, Write};

    if let Ok((stream, _)) = listener.accept() {
        stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(2))).ok();

        let mut reader = BufReader::new(&stream);
        let mut line = String::new();
        if reader.read_line(&mut line).is_ok() && !line.is_empty() {
            let response = match serde_json::from_str::<crate::daemon::DaemonRequest>(&line) {
                Ok(request) => crate::daemon::handle_daemon_request(request, capture, db_tx),
                Err(e) => crate::daemon::DaemonResponse::error(format!("invalid request: {e}")),
            };
            if let Ok(json) = serde_json::to_string(&response) {
                let mut writer = stream;
                let _ = writer.write_all(json.as_bytes());
                let _ = writer.write_all(b"\n");
                let _ = writer.flush();
            }
        }
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capture_engine_basic() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000);
        eng.process(b"line one\r\nline two\r\nline three\r\n");
        let lines = eng.get_lines(10);
        assert!(lines.contains("line one"));
        assert!(lines.contains("line two"));
        assert!(lines.contains("line three"));
    }

    #[test]
    fn test_capture_engine_empty() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000);
        let lines = eng.get_lines(10);
        assert!(lines.trim().is_empty());
    }

    #[test]
    fn test_sanitize_input_strips_null_and_bell() {
        let input = b"hello\x00\x07world";
        let sanitized = sanitize_input(input);
        assert_eq!(sanitized, b"helloworld");
    }

    #[test]
    fn test_sanitize_input_preserves_controls() {
        let input = b"hello\n\r\t\x1b[31mworld\x08";
        let sanitized = sanitize_input(input);
        assert_eq!(sanitized, input.to_vec());
    }

    #[test]
    fn test_capture_engine_rate_limit() {
        let mut eng = CaptureEngine::new(24, 80, 100, 2, 10_000);
        eng.process(&vec![b'A'; 200]);
        let lines = eng.get_lines(100);
        assert!(lines.contains("[nsh: output capture suppressed"));
    }

    #[test]
    fn test_alt_screen_content_excluded() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000);
        eng.process(b"before alt\r\n");
        eng.process(b"\x1b[?1049h");
        eng.process(b"TUI content\r\n");
        let output = eng.get_lines(100);
        assert!(output.is_empty() || !output.contains("TUI content"));
    }
}
