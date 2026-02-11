use std::os::fd::BorrowedFd;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
    history_lines: Vec<String>,
    max_history_lines: usize,
    prev_visible: Vec<String>,
    mark_state: Option<(usize, Vec<String>)>,
    #[allow(dead_code)]
    capture_mode: String,
    alt_screen_mode: String,
}

impl CaptureEngine {
    pub fn new(
        rows: u16,
        cols: u16,
        rate_limit_bps: usize,
        pause_seconds: u64,
        max_scrollback_lines: usize,
        capture_mode: String,
        alt_screen_mode: String,
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
            history_lines: Vec::new(),
            max_history_lines: max_scrollback_lines,
            prev_visible: Vec::new(),
            mark_state: None,
            capture_mode,
            alt_screen_mode,
        }
    }

    fn push_history_line(&mut self, line: String) {
        if line.trim().is_empty() {
            return;
        }
        self.history_lines.push(line);
        if self.max_history_lines > 0 && self.history_lines.len() > self.max_history_lines {
            let excess = self.history_lines.len() - self.max_history_lines;
            self.history_lines.drain(0..excess);
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
            self.paused_until = Some(Instant::now() + Duration::from_secs(self.pause_seconds));
            if !self.suppressed {
                self.suppressed = true;
                self.push_history_line("[nsh: output capture suppressed (high output rate)]".into());
            }
            return;
        }

        let sanitized = sanitize_input(bytes);
        self.parser.process(&sanitized);

        let now_alt = self.parser.screen().alternate_screen();
        if now_alt {
            self.in_alternate_screen = true;
            return;
        } else if self.in_alternate_screen {
            self.in_alternate_screen = false;
            if self.alt_screen_mode != "snapshot" {
                self.prev_visible.clear();
            }
        }

        self.parser.screen_mut().set_scrollback(0);
        let visible = self.parser.screen().contents();
        let cur_lines: Vec<String> = visible.lines().map(|l| l.to_string()).collect();

        if !self.prev_visible.is_empty() {
            let scrolled = detect_scrolled_lines(&self.prev_visible, &cur_lines);
            for line in scrolled {
                self.push_history_line(line);
            }
        }

        self.prev_visible = cur_lines;
    }

    pub fn get_lines(&self, max_lines: usize) -> String {
        if self.parser.screen().alternate_screen() {
            return String::new();
        }

        let visible = self.parser.screen().contents();
        let vis_lines: Vec<&str> = visible.lines().collect();

        let history_needed = max_lines.saturating_sub(vis_lines.len());
        let history_start = self.history_lines.len().saturating_sub(history_needed);
        let mut result: Vec<&str> = self.history_lines[history_start..]
            .iter()
            .map(|s| s.as_str())
            .collect();
        result.extend(vis_lines);

        let final_start = result.len().saturating_sub(max_lines);
        let combined = result[final_start..].join("\n");

        combined
            .replace("\r\n", "\n")
            .replace('\r', "")
            .replace("\x1b[200~", "")
            .replace("\x1b[201~", "")
    }

    #[allow(dead_code)]
    pub fn total_line_count(&self) -> usize {
        self.history_lines.len()
    }

    pub fn mark(&mut self) {
        self.parser.screen_mut().set_scrollback(0);
        let visible = self.parser.screen().contents();
        let cur_lines: Vec<String> = visible.lines().map(|l| l.to_string()).collect();
        self.mark_state = Some((self.history_lines.len(), cur_lines));
    }

    pub fn capture_since_mark(&mut self, max_bytes: usize) -> Option<String> {
        let (mark_hist_len, mark_visible) = self.mark_state.take()?;

        self.parser.screen_mut().set_scrollback(0);
        let visible = self.parser.screen().contents();
        let cur_visible: Vec<&str> = visible.lines().collect();

        let clamped_mark = mark_hist_len.min(self.history_lines.len());
        let new_history: Vec<&str> = self.history_lines[clamped_mark..]
            .iter()
            .map(|s| s.as_str())
            .collect();

        let overlap = longest_suffix_prefix_overlap(
            &mark_visible.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            &cur_visible,
        );
        let trimmed_visible = if overlap < cur_visible.len() {
            &cur_visible[overlap..]
        } else {
            &[]
        };

        let mut all: Vec<&str> = Vec::new();
        all.extend_from_slice(&new_history);
        all.extend_from_slice(trimmed_visible);

        if all.is_empty() {
            return Some(String::new());
        }

        let joined = all.join("\n");
        Some(truncate_for_storage(&joined, max_bytes))
    }

    pub fn set_size(&mut self, rows: u16, cols: u16) {
        self.parser.screen_mut().set_size(rows, cols);
        self.prev_visible.clear();
    }
}

fn detect_scrolled_lines(prev: &[String], cur: &[String]) -> Vec<String> {
    let overlap = longest_suffix_prefix_overlap(
        &prev.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        &cur.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
    );
    if overlap == 0 && !prev.is_empty() && !cur.is_empty() {
        return prev.to_vec();
    }
    let scrolled_count = prev.len().saturating_sub(overlap);
    prev[..scrolled_count].to_vec()
}

fn longest_suffix_prefix_overlap(a: &[&str], b: &[&str]) -> usize {
    let max_possible = a.len().min(b.len());
    for len in (1..=max_possible).rev() {
        let suffix_start = a.len() - len;
        if a[suffix_start..] == b[..len] {
            return len;
        }
    }
    0
}

pub fn truncate_for_storage(output: &str, max_bytes: usize) -> String {
    let lines: Vec<&str> = output.lines().collect();
    let result = if lines.len() <= 150 {
        output.to_string()
    } else {
        let first = lines[..100].join("\n");
        let last = lines[lines.len() - 50..].join("\n");
        format!(
            "{first}\n[... {} lines omitted ...]\n{last}",
            lines.len() - 150
        )
    };
    if result.len() <= max_bytes {
        result
    } else {
        crate::util::truncate_bytes(&result, max_bytes).to_string() + "\n[... truncated by nsh]"
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

    let mut signals = Signals::new([
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
    capture: Arc<Mutex<CaptureEngine>>,
    child_pid: rustix::process::Pid,
) {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    use std::os::fd::AsRawFd;

    let stdin_raw = real_stdin.as_raw_fd();
    let pty_master_raw = pty_master.as_raw_fd();
    let winch_pending = Arc::new(AtomicBool::new(false));
    let signal_thread =
        spawn_signal_thread(child_pid, stdin_raw, pty_master_raw, winch_pending.clone());

    let config = crate::config::Config::load().unwrap_or_default();
    let max_output_bytes = config.context.max_output_storage_bytes;
    let active_conns = Arc::new(AtomicUsize::new(0));

    unsafe {
        libc::signal(libc::SIGTSTP, libc::SIG_IGN);
        libc::signal(libc::SIGTTIN, libc::SIG_IGN);
        libc::signal(libc::SIGTTOU, libc::SIG_IGN);
    }

    let session_id = std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "default".into());

    let nsh_dir = crate::config::Config::nsh_dir();
    let _ = std::fs::create_dir_all(&nsh_dir);

    let socket_path = nsh_dir.join(format!("scrollback_{session_id}.sock"));
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

    // Set PTY master to non-blocking to prevent deadlock:
    // Without this, write_all to pty_master can block when the PTY buffer is full,
    // while the shell is blocked writing to the PTY slave (circular wait).
    {
        use std::os::fd::AsRawFd;
        let flags = unsafe { libc::fcntl(pty_master.as_raw_fd(), libc::F_GETFL) };
        if flags >= 0 {
            unsafe { libc::fcntl(pty_master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
        }
    }

    let mut buf = [0u8; 8192];
    let mut last_activity = Instant::now();
    let mut last_flush = Instant::now();
    let mut pending_pty_write: Vec<u8> = Vec::new();
    const MAX_PENDING: usize = 256 * 1024;

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

        let stdin_flags = if pending_pty_write.len() < MAX_PENDING {
            PollFlags::IN
        } else {
            PollFlags::empty()
        };
        let pty_flags = if pending_pty_write.is_empty() {
            PollFlags::IN
        } else {
            PollFlags::IN | PollFlags::OUT
        };
        let mut poll_fds: Vec<PollFd> = vec![
            PollFd::new(&real_stdin, stdin_flags),
            PollFd::new(&pty_master, pty_flags),
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
                    &poll_fds[0],
                    &poll_fds[1],
                    &real_stdin,
                    &real_stdout,
                    &pty_master,
                    &mut buf,
                    &capture,
                    &mut last_activity,
                    &mut last_flush,
                    &scrollback_path,
                    &redact_active_path,
                    &mut pending_pty_write,
                ) {
                    break;
                }

                if let (Some(idx), Some(l)) = (legacy_idx, listener.as_ref()) {
                    if poll_fds[idx].revents().contains(PollFlags::IN) {
                        handle_socket_connection(l, &capture);
                    }
                }

                if let (Some(idx), Some(l)) = (daemon_idx, daemon_listener.as_ref()) {
                    if poll_fds[idx].revents().contains(PollFlags::IN) {
                        handle_daemon_connection(
                            l,
                            &capture,
                            &db_tx,
                            max_output_bytes,
                            &active_conns,
                        );
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

#[allow(clippy::too_many_arguments)]
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
    pending_pty_write: &mut Vec<u8>,
) -> bool {
    use rustix::event::PollFlags;

    if pty_poll.revents().contains(PollFlags::OUT) && !pending_pty_write.is_empty() {
        match rustix::io::write(pty_master, pending_pty_write) {
            Ok(n) => {
                pending_pty_write.drain(0..n);
            }
            Err(e) if e == rustix::io::Errno::INTR || e == rustix::io::Errno::AGAIN => {}
            Err(_) => return true,
        }
    }

    if stdin_poll.revents().contains(PollFlags::IN) {
        match rustix::io::read(real_stdin, &mut *buf) {
            Ok(0) => return true,
            Ok(n) => {
                if pending_pty_write.is_empty() {
                    match rustix::io::write(pty_master, &buf[..n]) {
                        Ok(written) if written < n => {
                            pending_pty_write.extend_from_slice(&buf[written..n]);
                        }
                        Ok(_) => {}
                        Err(e) if e == rustix::io::Errno::AGAIN => {
                            pending_pty_write.extend_from_slice(&buf[..n]);
                        }
                        Err(e) if e == rustix::io::Errno::INTR => {
                            pending_pty_write.extend_from_slice(&buf[..n]);
                        }
                        Err(_) => return true,
                    }
                } else {
                    pending_pty_write.extend_from_slice(&buf[..n]);
                }
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

fn check_peer_uid(stream: &std::os::unix::net::UnixStream) -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            tracing::warn!("Rejecting daemon connection: SO_PEERCRED failed");
            return false;
        }
        if cred.uid != unsafe { libc::getuid() } {
            tracing::warn!("Rejecting daemon connection from uid {}", cred.uid);
            return false;
        }
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        let mut euid: libc::uid_t = 0;
        let mut egid: libc::gid_t = 0;
        let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut euid, &mut egid) };
        if rc != 0 {
            tracing::warn!("Rejecting daemon connection: getpeereid failed");
            return false;
        }
        if euid != unsafe { libc::getuid() } {
            tracing::warn!("Rejecting daemon connection from uid {}", euid);
            return false;
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        tracing::warn!("Rejecting daemon connection: peer UID check not implemented for this platform");
        return false;
    }
    true
}

fn handle_socket_connection(
    listener: &std::os::unix::net::UnixListener,
    capture: &Mutex<CaptureEngine>,
) {
    use std::io::Write;

    if let Ok((mut stream, _)) = listener.accept() {
        if !check_peer_uid(&stream) {
            return;
        }
        stream.set_write_timeout(Some(Duration::from_secs(2))).ok();
        if let Ok(eng) = capture.lock() {
            let text = eng.get_lines(1000);
            let _ = stream.write_all(text.as_bytes());
        }
    }
}

fn handle_daemon_connection(
    listener: &std::os::unix::net::UnixListener,
    capture: &Arc<Mutex<CaptureEngine>>,
    db_tx: &std::sync::mpsc::Sender<crate::daemon::DbCommand>,
    max_output_bytes: usize,
    active_conns: &Arc<AtomicUsize>,
) {
    const MAX_CONCURRENT: usize = 8;

    if let Ok((stream, _)) = listener.accept() {
        if !check_peer_uid(&stream) {
            return;
        }

        if active_conns.load(Ordering::Relaxed) >= MAX_CONCURRENT {
            tracing::debug!("daemon: rejecting connection, at max concurrent limit");
            return;
        }

        let capture = Arc::clone(capture);
        let db_tx = db_tx.clone();
        let active = Arc::clone(active_conns);
        active.fetch_add(1, Ordering::Relaxed);

        match std::thread::Builder::new()
            .name("nsh-daemon-conn".into())
            .spawn(move || {
                handle_daemon_connection_inner(stream, &capture, &db_tx, max_output_bytes);
                active.fetch_sub(1, Ordering::Relaxed);
            }) {
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("daemon: failed to spawn connection handler thread: {e}");
                active_conns.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
}

fn handle_daemon_connection_inner(
    stream: std::os::unix::net::UnixStream,
    capture: &Mutex<CaptureEngine>,
    db_tx: &std::sync::mpsc::Sender<crate::daemon::DbCommand>,
    max_output_bytes: usize,
) {
    use std::io::{BufRead, BufReader, Write};

    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_millis(500)))
        .ok();

    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    let read_result = reader.read_line(&mut line);
    let response = match read_result {
        Ok(0) => return,
        Ok(n) if n > 256 * 1024 => crate::daemon::DaemonResponse::error("request too large"),
        Ok(_) => {
            let raw: serde_json::Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(e) => {
                    let resp = crate::daemon::DaemonResponse::error(format!("invalid JSON: {e}"));
                    if let Ok(json) = serde_json::to_string(&resp) {
                        let mut writer = stream;
                        let _ = writer.write_all(json.as_bytes());
                        let _ = writer.write_all(b"\n");
                        let _ = writer.flush();
                    }
                    return;
                }
            };
            let client_version = raw.get("v").and_then(|v| v.as_u64()).unwrap_or(1);
            if client_version > crate::daemon::DAEMON_PROTOCOL_VERSION as u64 {
                tracing::warn!(
                    "daemon: client protocol version {client_version} > server {}",
                    crate::daemon::DAEMON_PROTOCOL_VERSION
                );
            }
            match serde_json::from_value::<crate::daemon::DaemonRequest>(raw) {
                Ok(request) => {
                    crate::daemon::handle_daemon_request(request, capture, db_tx, max_output_bytes)
                }
                Err(e) => crate::daemon::DaemonResponse::error(format!("invalid request: {e}")),
            }
        }
        Err(_) => return,
    };
    if let Ok(mut json_val) = serde_json::to_value(&response) {
        if let serde_json::Value::Object(ref mut map) = json_val {
            map.insert(
                "v".into(),
                serde_json::json!(crate::daemon::DAEMON_PROTOCOL_VERSION),
            );
        }
        if let Ok(json) = serde_json::to_string(&json_val) {
            let mut writer = stream;
            let _ = writer.write_all(json.as_bytes());
            let _ = writer.write_all(b"\n");
            let _ = writer.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capture_engine_basic() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"line one\r\nline two\r\nline three\r\n");
        let lines = eng.get_lines(10);
        assert!(lines.contains("line one"));
        assert!(lines.contains("line two"));
        assert!(lines.contains("line three"));
    }

    #[test]
    fn test_capture_engine_empty() {
        let eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
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
        let mut eng = CaptureEngine::new(24, 80, 100, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(&[b'A'; 200]);
        let lines = eng.get_lines(100);
        assert!(lines.contains("[nsh: output capture suppressed"));
    }

    #[test]
    fn test_alt_screen_content_excluded() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"before alt\r\n");
        eng.process(b"\x1b[?1049h");
        eng.process(b"TUI content\r\n");
        let output = eng.get_lines(100);
        assert!(output.is_empty() || !output.contains("TUI content"));
    }

    #[test]
    fn test_mark_and_capture() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"before mark\r\n");
        eng.mark();
        eng.process(b"after mark line 1\r\nafter mark line 2\r\n");
        let captured = eng.capture_since_mark(65536).unwrap();
        assert!(captured.contains("after mark line 1"));
        assert!(captured.contains("after mark line 2"));
        assert!(!captured.contains("before mark"));
    }

    #[test]
    fn test_capture_without_mark_returns_none() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"some output\r\n");
        assert!(eng.capture_since_mark(65536).is_none());
    }

    #[test]
    fn test_total_line_count() {
        let mut eng = CaptureEngine::new(4, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        for i in 0..10 {
            eng.process(format!("line {i}\r\n").as_bytes());
        }
        assert!(eng.total_line_count() > 0);
    }

    #[test]
    fn test_truncate_for_storage_short() {
        let input = "line 1\nline 2\nline 3";
        let result = truncate_for_storage(input, 65536);
        assert_eq!(result, input);
    }

    #[test]
    fn test_truncate_for_storage_many_lines() {
        let lines: Vec<String> = (0..200).map(|i| format!("line {i}")).collect();
        let input = lines.join("\n");
        let result = truncate_for_storage(&input, 65536);
        assert!(result.contains("line 0"));
        assert!(result.contains("line 99"));
        assert!(result.contains("lines omitted"));
        assert!(result.contains("line 199"));
        assert!(!result.contains("line 100\n"));
    }

    #[test]
    fn test_longest_suffix_prefix_overlap() {
        let a = vec!["a", "b", "c", "d"];
        let b = vec!["c", "d", "e", "f"];
        assert_eq!(longest_suffix_prefix_overlap(&a, &b), 2);

        let c = vec!["x", "y"];
        let d = vec!["a", "b"];
        assert_eq!(longest_suffix_prefix_overlap(&c, &d), 0);

        let e = vec!["a", "b", "c"];
        let f = vec!["a", "b", "c"];
        assert_eq!(longest_suffix_prefix_overlap(&e, &f), 3);
    }

    #[test]
    fn test_capture_engine_new_is_empty() {
        let eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        assert_eq!(eng.total_line_count(), 0);
        assert!(eng.get_lines(100).trim().is_empty());
    }

    #[test]
    fn test_get_lines_respects_max_lines() {
        let mut eng = CaptureEngine::new(4, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        for i in 0..20 {
            eng.process(format!("line {i}\r\n").as_bytes());
        }
        let output = eng.get_lines(5);
        let lines: Vec<&str> = output.lines().collect();
        assert!(lines.len() <= 5);
    }

    #[test]
    fn test_get_lines_with_max_one() {
        let mut eng = CaptureEngine::new(4, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        for i in 0..10 {
            eng.process(format!("line {i}\r\n").as_bytes());
        }
        let output = eng.get_lines(1);
        let lines: Vec<&str> = output.lines().filter(|l| !l.is_empty()).collect();
        assert!(lines.len() <= 1);
    }

    #[test]
    fn test_get_lines_large_limit_returns_all() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"alpha\r\nbeta\r\ngamma\r\n");
        let output = eng.get_lines(10000);
        assert!(output.contains("alpha"));
        assert!(output.contains("beta"));
        assert!(output.contains("gamma"));
    }

    #[test]
    fn test_mark_capture_empty_after_mark() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"before\r\n");
        eng.mark();
        let captured = eng.capture_since_mark(65536).unwrap();
        assert!(captured.is_empty() || !captured.contains("before"));
    }

    #[test]
    fn test_mark_consumes_state() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.mark();
        eng.process(b"data\r\n");
        let first = eng.capture_since_mark(65536);
        assert!(first.is_some());
        let second = eng.capture_since_mark(65536);
        assert!(second.is_none());
    }

    #[test]
    fn test_mark_overwrite() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"old\r\n");
        eng.mark();
        eng.process(b"middle\r\n");
        eng.mark();
        eng.process(b"newest\r\n");
        let captured = eng.capture_since_mark(65536).unwrap();
        assert!(captured.contains("newest"));
    }

    #[test]
    fn test_history_accumulates_scrolled_lines() {
        let mut eng = CaptureEngine::new(4, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        for i in 0..20 {
            eng.process(format!("scrolled line {i}\r\n").as_bytes());
        }
        assert!(eng.total_line_count() > 0);
        let output = eng.get_lines(100);
        assert!(output.contains("scrolled line 0"));
    }

    #[test]
    fn test_set_size_clears_prev_visible() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"hello\r\n");
        eng.set_size(40, 120);
        eng.process(b"world\r\n");
        let output = eng.get_lines(100);
        assert!(output.contains("world"));
    }

    #[test]
    fn test_sanitize_input_empty() {
        assert!(sanitize_input(b"").is_empty());
    }

    #[test]
    fn test_sanitize_input_all_filtered() {
        let input = b"\x00\x01\x02\x03\x04\x05\x06\x07";
        assert!(sanitize_input(input).is_empty());
    }

    #[test]
    fn test_sanitize_input_high_bytes_preserved() {
        let input: Vec<u8> = (0x80..=0xFF).collect();
        let result = sanitize_input(&input);
        assert_eq!(result, input);
    }

    #[test]
    fn test_detect_scrolled_lines_partial_overlap() {
        let prev: Vec<String> = vec!["a", "b", "c", "d"].into_iter().map(String::from).collect();
        let cur: Vec<String> = vec!["c", "d", "e", "f"].into_iter().map(String::from).collect();
        let scrolled = detect_scrolled_lines(&prev, &cur);
        assert_eq!(scrolled, vec!["a", "b"]);
    }

    #[test]
    fn test_detect_scrolled_lines_no_overlap() {
        let prev: Vec<String> = vec!["a", "b"].into_iter().map(String::from).collect();
        let cur: Vec<String> = vec!["x", "y"].into_iter().map(String::from).collect();
        let scrolled = detect_scrolled_lines(&prev, &cur);
        assert_eq!(scrolled, vec!["a", "b"]);
    }

    #[test]
    fn test_detect_scrolled_lines_identical() {
        let prev: Vec<String> = vec!["a", "b"].into_iter().map(String::from).collect();
        let cur = prev.clone();
        let scrolled = detect_scrolled_lines(&prev, &cur);
        assert!(scrolled.is_empty());
    }

    #[test]
    fn test_detect_scrolled_lines_empty_inputs() {
        let empty: Vec<String> = vec![];
        let non_empty: Vec<String> = vec!["a".into()];
        assert!(detect_scrolled_lines(&empty, &non_empty).is_empty());
        assert!(detect_scrolled_lines(&empty, &empty).is_empty());
    }

    #[test]
    fn test_longest_suffix_prefix_overlap_empty() {
        let empty: Vec<&str> = vec![];
        let non_empty = vec!["a"];
        assert_eq!(longest_suffix_prefix_overlap(&empty, &non_empty), 0);
        assert_eq!(longest_suffix_prefix_overlap(&non_empty, &empty), 0);
        assert_eq!(longest_suffix_prefix_overlap(&empty, &empty), 0);
    }

    #[test]
    fn test_longest_suffix_prefix_overlap_single_match() {
        let a = vec!["x"];
        let b = vec!["x"];
        assert_eq!(longest_suffix_prefix_overlap(&a, &b), 1);
    }

    #[test]
    fn test_longest_suffix_prefix_overlap_single_no_match() {
        let a = vec!["x"];
        let b = vec!["y"];
        assert_eq!(longest_suffix_prefix_overlap(&a, &b), 0);
    }

    #[test]
    fn test_truncate_for_storage_exact_150_lines() {
        let lines: Vec<String> = (0..150).map(|i| format!("line {i}")).collect();
        let input = lines.join("\n");
        let result = truncate_for_storage(&input, 65536);
        assert_eq!(result, input);
    }

    #[test]
    fn test_truncate_for_storage_byte_limit() {
        let lines: Vec<String> = (0..10).map(|i| format!("line {i}")).collect();
        let input = lines.join("\n");
        let result = truncate_for_storage(&input, 20);
        assert!(result.len() <= 20 + "[... truncated by nsh]".len() + 1);
        assert!(result.contains("[... truncated by nsh]"));
    }

    #[test]
    fn test_truncate_for_storage_empty() {
        let result = truncate_for_storage("", 65536);
        assert_eq!(result, "");
    }

    #[test]
    fn test_alt_screen_enter_and_exit() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"before\r\n");
        eng.process(b"\x1b[?1049h");
        eng.process(b"in alt\r\n");
        eng.process(b"\x1b[?1049l");
        eng.process(b"after\r\n");
        let output = eng.get_lines(100);
        assert!(output.contains("after"));
        assert!(!output.contains("in alt"));
    }

    #[test]
    fn test_alt_screen_snapshot_mode() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "snapshot".into());
        eng.process(b"visible\r\n");
        eng.process(b"\x1b[?1049h");
        eng.process(b"\x1b[?1049l");
        let output = eng.get_lines(100);
        assert!(output.contains("visible"));
    }

    #[test]
    fn test_capture_since_mark_with_scrolled_history() {
        let mut eng = CaptureEngine::new(4, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        for i in 0..10 {
            eng.process(format!("pre {i}\r\n").as_bytes());
        }
        eng.mark();
        for i in 0..10 {
            eng.process(format!("post {i}\r\n").as_bytes());
        }
        let captured = eng.capture_since_mark(65536).unwrap();
        assert!(captured.contains("post 0"));
        assert!(!captured.contains("pre 0"));
    }

    #[test]
    fn test_capture_since_mark_respects_max_bytes() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.mark();
        for i in 0..50 {
            eng.process(format!("data line {i}\r\n").as_bytes());
        }
        let captured = eng.capture_since_mark(30).unwrap();
        assert!(captured.len() <= 30 + "[... truncated by nsh]".len() + 1);
    }

    #[test]
    fn test_process_strips_bracket_paste() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"\x1b[200~pasted text\x1b[201~\r\n");
        let output = eng.get_lines(100);
        assert!(!output.contains("\x1b[200~"));
        assert!(!output.contains("\x1b[201~"));
    }

    #[test]
    fn test_rate_limit_does_not_trigger_when_disabled() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(&[b'X'; 1_000_000]);
        let lines = eng.get_lines(100);
        assert!(!lines.contains("suppressed"));
    }

    #[test]
    fn test_multiple_processes_accumulate() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"first\r\n");
        eng.process(b"second\r\n");
        eng.process(b"third\r\n");
        let output = eng.get_lines(100);
        assert!(output.contains("first"));
        assert!(output.contains("second"));
        assert!(output.contains("third"));
    }

    #[test]
    fn test_get_lines_zero() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"some data\r\n");
        let output = eng.get_lines(0);
        assert!(output.is_empty());
    }

    #[test]
    fn test_rate_limit_suppressed_only_once() {
        let mut eng = CaptureEngine::new(24, 80, 100, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(&[b'A'; 200]);
        eng.process(&[b'B'; 200]);
        eng.process(&[b'C'; 200]);
        let lines = eng.get_lines(1000);
        let count = lines.matches("[nsh: output capture suppressed").count();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_rate_limit_paused_data_dropped() {
        let mut eng = CaptureEngine::new(24, 80, 50, 1, 10_000, "vt100".into(), "drop".into());
        eng.process(&[b'X'; 100]);
        assert!(eng.paused_until.is_some());
        eng.process(b"should be dropped\r\n");
        let output = eng.get_lines(1000);
        assert!(!output.contains("should be dropped"));
    }

    #[test]
    fn test_rate_limit_pause_seconds_configurable() {
        let mut eng = CaptureEngine::new(24, 80, 50, 5, 10_000, "vt100".into(), "drop".into());
        eng.process(&[b'X'; 100]);
        assert!(eng.paused_until.is_some());
        let until = eng.paused_until.unwrap();
        let expected_min = Instant::now() + Duration::from_secs(4);
        assert!(until >= expected_min);
    }

    #[test]
    fn test_process_empty_bytes() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"");
        assert_eq!(eng.total_line_count(), 0);
        assert!(eng.get_lines(100).trim().is_empty());
    }

    #[test]
    fn test_get_lines_returns_empty_on_alt_screen() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"normal content\r\n");
        eng.process(b"\x1b[?1049h");
        eng.process(b"alt content\r\n");
        let output = eng.get_lines(100);
        assert!(output.is_empty());
    }

    #[test]
    fn test_alt_screen_drop_mode_clears_prev_visible() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"line A\r\nline B\r\n");
        assert!(!eng.prev_visible.is_empty());
        eng.process(b"\x1b[?1049h");
        eng.in_alternate_screen = true;
        eng.prev_visible = vec!["something".into()];
        eng.process(b"\x1b[?1049l");
        let vis_after_leave = eng.prev_visible.clone();
        assert!(
            vis_after_leave.is_empty()
                || !vis_after_leave.iter().any(|l| l.contains("something")),
        );
    }

    #[test]
    fn test_alt_screen_snapshot_mode_preserves_prev_visible() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "snapshot".into());
        eng.process(b"line A\r\nline B\r\n");
        let before = eng.prev_visible.clone();
        eng.process(b"\x1b[?1049h");
        eng.process(b"\x1b[?1049l");
        assert_eq!(eng.prev_visible, before);
    }

    #[test]
    fn test_alt_screen_enter_process_leave_cycle() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"before1\r\n");
        eng.process(b"\x1b[?1049h");
        eng.process(b"alt1\r\n");
        eng.process(b"\x1b[?1049l");
        eng.process(b"middle\r\n");
        eng.process(b"\x1b[?1049h");
        eng.process(b"alt2\r\n");
        eng.process(b"\x1b[?1049l");
        eng.process(b"after\r\n");
        let output = eng.get_lines(1000);
        assert!(output.contains("after"));
        assert!(!output.contains("alt1"));
        assert!(!output.contains("alt2"));
    }

    #[test]
    fn test_detect_scrolled_lines_empty_prev_nonempty_cur() {
        let prev: Vec<String> = vec![];
        let cur: Vec<String> = vec!["a".into(), "b".into()];
        let scrolled = detect_scrolled_lines(&prev, &cur);
        assert!(scrolled.is_empty());
    }

    #[test]
    fn test_detect_scrolled_lines_nonempty_prev_empty_cur() {
        let prev: Vec<String> = vec!["a".into(), "b".into()];
        let cur: Vec<String> = vec![];
        let scrolled = detect_scrolled_lines(&prev, &cur);
        assert_eq!(scrolled, vec!["a", "b"]);
    }

    #[test]
    fn test_detect_scrolled_lines_full_overlap() {
        let prev: Vec<String> = vec!["a".into(), "b".into()];
        let cur: Vec<String> = vec!["a".into(), "b".into(), "c".into()];
        let scrolled = detect_scrolled_lines(&prev, &cur);
        assert!(scrolled.is_empty());
    }

    #[test]
    fn test_detect_scrolled_lines_single_line_scroll() {
        let prev: Vec<String> = vec!["a".into(), "b".into(), "c".into()];
        let cur: Vec<String> = vec!["b".into(), "c".into(), "d".into()];
        let scrolled = detect_scrolled_lines(&prev, &cur);
        assert_eq!(scrolled, vec!["a"]);
    }

    #[test]
    fn test_longest_suffix_prefix_overlap_full_match_different_lengths() {
        let a = vec!["x", "y", "z"];
        let b = vec!["x", "y", "z", "w"];
        assert_eq!(longest_suffix_prefix_overlap(&a, &b), 3);
    }

    #[test]
    fn test_longest_suffix_prefix_overlap_b_shorter_than_a() {
        let a = vec!["a", "b", "c", "d"];
        let b = vec!["d"];
        assert_eq!(longest_suffix_prefix_overlap(&a, &b), 1);
    }

    #[test]
    fn test_longest_suffix_prefix_overlap_no_match_long() {
        let a = vec!["a", "b", "c"];
        let b = vec!["d", "e", "f"];
        assert_eq!(longest_suffix_prefix_overlap(&a, &b), 0);
    }

    #[test]
    fn test_truncate_for_storage_exactly_151_lines() {
        let lines: Vec<String> = (0..151).map(|i| format!("line {i}")).collect();
        let input = lines.join("\n");
        let result = truncate_for_storage(&input, 65536);
        assert!(result.contains("line 0"));
        assert!(result.contains("line 99"));
        assert!(result.contains("[... 1 lines omitted ...]"));
        assert!(result.contains("line 150"));
    }

    #[test]
    fn test_truncate_for_storage_single_line() {
        let result = truncate_for_storage("only one line", 65536);
        assert_eq!(result, "only one line");
    }

    #[test]
    fn test_truncate_for_storage_zero_max_bytes() {
        let result = truncate_for_storage("hello", 0);
        assert!(result.contains("[... truncated by nsh]"));
    }

    #[test]
    fn test_truncate_for_storage_many_lines_and_byte_limit() {
        let lines: Vec<String> = (0..200).map(|i| format!("line {i}")).collect();
        let input = lines.join("\n");
        let result = truncate_for_storage(&input, 50);
        assert!(result.contains("[... truncated by nsh]"));
    }

    #[test]
    fn test_sanitize_input_preserves_tab() {
        let input = b"\t";
        assert_eq!(sanitize_input(input), b"\t".to_vec());
    }

    #[test]
    fn test_sanitize_input_preserves_backspace() {
        let input = b"\x08";
        assert_eq!(sanitize_input(input), b"\x08".to_vec());
    }

    #[test]
    fn test_sanitize_input_preserves_escape() {
        let input = b"\x1b";
        assert_eq!(sanitize_input(input), b"\x1b".to_vec());
    }

    #[test]
    fn test_sanitize_input_mixed() {
        let input = b"a\x00b\x01c\x02d\x1be\nf\rg\th\x08";
        let expected = b"abcd\x1be\nf\rg\th\x08";
        assert_eq!(sanitize_input(input), expected.to_vec());
    }

    #[test]
    fn test_sanitize_input_printable_ascii_range() {
        let input: Vec<u8> = (0x20..=0x7E).collect();
        let result = sanitize_input(&input);
        assert_eq!(result, input);
    }

    #[test]
    fn test_sanitize_input_filters_0x7f() {
        let input = b"\x7f";
        assert!(sanitize_input(input).is_empty());
    }

    #[test]
    fn test_capture_since_mark_no_new_output() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"content\r\n");
        eng.mark();
        let captured = eng.capture_since_mark(65536).unwrap();
        assert!(captured.is_empty());
    }

    #[test]
    fn test_capture_since_mark_with_only_visible_changes() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.mark();
        eng.process(b"new visible line\r\n");
        let captured = eng.capture_since_mark(65536).unwrap();
        assert!(captured.contains("new visible line"));
    }

    #[test]
    fn test_mark_on_fresh_engine() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.mark();
        eng.process(b"first output\r\n");
        let captured = eng.capture_since_mark(65536).unwrap();
        assert!(captured.contains("first output"));
    }

    #[test]
    fn test_set_size_different_dimensions() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"hello\r\n");
        eng.set_size(10, 40);
        eng.process(b"smaller screen\r\n");
        let output = eng.get_lines(100);
        assert!(output.contains("smaller screen"));
    }

    #[test]
    fn test_set_size_multiple_times() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"a\r\n");
        eng.set_size(40, 120);
        eng.process(b"b\r\n");
        eng.set_size(10, 40);
        eng.process(b"c\r\n");
        let output = eng.get_lines(100);
        assert!(output.contains("c"));
    }

    #[test]
    fn test_process_whitespace_only_lines_not_in_history() {
        let mut eng = CaptureEngine::new(4, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        for _ in 0..10 {
            eng.process(b"   \r\n");
        }
        for line in &eng.history_lines {
            assert!(!line.trim().is_empty());
        }
    }

    #[test]
    fn test_process_crlf_handling() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"line1\r\nline2\r\n");
        let output = eng.get_lines(100);
        assert!(!output.contains("\r\n"));
        assert!(output.contains("line1"));
        assert!(output.contains("line2"));
    }

    #[test]
    fn test_get_lines_history_plus_visible() {
        let mut eng = CaptureEngine::new(4, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        for i in 0..20 {
            eng.process(format!("line{i}\r\n").as_bytes());
        }
        let output = eng.get_lines(50);
        assert!(output.contains("line0"));
        assert!(output.contains("line19"));
    }

    #[test]
    fn test_process_ansi_color_sequences() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"\x1b[31mred text\x1b[0m\r\n");
        let output = eng.get_lines(100);
        assert!(output.contains("red text"));
    }

    #[test]
    fn test_process_cursor_movement() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"hello\x1b[5Dworld\r\n");
        let output = eng.get_lines(100);
        assert!(output.contains("world"));
    }

    #[test]
    fn test_process_backspace() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"abc\x08x\r\n");
        let output = eng.get_lines(100);
        assert!(output.contains("abx"));
    }

    #[test]
    fn test_capture_since_mark_max_bytes_with_many_lines() {
        let mut eng = CaptureEngine::new(4, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.mark();
        for i in 0..200 {
            eng.process(format!("post mark line {i}\r\n").as_bytes());
        }
        let captured = eng.capture_since_mark(100).unwrap();
        assert!(captured.len() <= 100 + "[... truncated by nsh]".len() + 1);
    }

    #[test]
    fn test_rate_limit_window_reset() {
        let mut eng = CaptureEngine::new(24, 80, 1000, 2, 10_000, "vt100".into(), "drop".into());
        eng.rate_bytes = 500;
        eng.rate_window_start = Instant::now() - Duration::from_secs(2);
        eng.process(b"after reset\r\n");
        assert_eq!(eng.rate_bytes, b"after reset\r\n".len());
        let output = eng.get_lines(100);
        assert!(output.contains("after reset"));
    }

    #[test]
    fn test_total_line_count_no_scrolling() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"a\r\nb\r\n");
        assert_eq!(eng.total_line_count(), 0);
    }

    #[test]
    fn test_get_lines_strips_bracket_paste_markers() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"normal text\r\n");
        eng.history_lines
            .push("line with \x1b[200~paste\x1b[201~ inside".into());
        let output = eng.get_lines(1000);
        assert!(!output.contains("\x1b[200~"));
        assert!(!output.contains("\x1b[201~"));
    }

    #[test]
    fn test_capture_since_mark_overlap_equals_cur_visible_len() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"same line\r\n");
        eng.mark();
        let captured = eng.capture_since_mark(65536).unwrap();
        assert!(captured.is_empty());
    }

    #[test]
    fn test_detect_scrolled_lines_both_empty() {
        let empty: Vec<String> = vec![];
        let scrolled = detect_scrolled_lines(&empty, &empty);
        assert!(scrolled.is_empty());
    }

    #[test]
    fn test_longest_suffix_prefix_overlap_one_element_lists() {
        assert_eq!(longest_suffix_prefix_overlap(&["a"], &["a"]), 1);
        assert_eq!(longest_suffix_prefix_overlap(&["a"], &["b"]), 0);
    }

    #[test]
    fn test_longest_suffix_prefix_overlap_suffix_in_middle() {
        let a = vec!["a", "b", "c"];
        let b = vec!["b", "c", "d"];
        assert_eq!(longest_suffix_prefix_overlap(&a, &b), 2);
    }

    #[test]
    fn test_process_large_single_line() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        let long_line = "A".repeat(500);
        eng.process(format!("{long_line}\r\n").as_bytes());
        let output = eng.get_lines(100);
        assert!(output.contains("AAAA"));
    }

    #[test]
    fn test_set_size_clears_prev_visible_each_time() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"content\r\n");
        assert!(!eng.prev_visible.is_empty());
        eng.set_size(30, 100);
        assert!(eng.prev_visible.is_empty());
        eng.process(b"more\r\n");
        assert!(!eng.prev_visible.is_empty());
        eng.set_size(20, 60);
        assert!(eng.prev_visible.is_empty());
    }

    #[test]
    fn test_truncate_for_storage_149_lines_no_truncation() {
        let lines: Vec<String> = (0..149).map(|i| format!("line {i}")).collect();
        let input = lines.join("\n");
        let result = truncate_for_storage(&input, 65536);
        assert_eq!(result, input);
    }

    #[test]
    fn test_truncate_for_storage_200_lines_keeps_first_100_last_50() {
        let lines: Vec<String> = (0..200).map(|i| format!("L{i:04}")).collect();
        let input = lines.join("\n");
        let result = truncate_for_storage(&input, 65536);
        assert!(result.contains("L0000"));
        assert!(result.contains("L0099"));
        assert!(result.contains("[... 50 lines omitted ...]"));
        assert!(result.contains("L0150"));
        assert!(result.contains("L0199"));
        assert!(!result.contains("\nL0100\n"));
    }

    #[test]
    fn test_mark_state_is_none_initially() {
        let eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        assert!(eng.mark_state.is_none());
    }

    #[test]
    fn test_mark_sets_mark_state() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"data\r\n");
        eng.mark();
        assert!(eng.mark_state.is_some());
    }

    #[test]
    fn test_in_alternate_screen_initially_false() {
        let eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        assert!(!eng.in_alternate_screen);
    }

    #[test]
    fn test_process_sets_in_alternate_screen() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"\x1b[?1049h");
        assert!(eng.in_alternate_screen);
    }

    #[test]
    fn test_rate_limit_suppressed_flag_persists() {
        let mut eng = CaptureEngine::new(24, 80, 100, 2, 10_000, "vt100".into(), "drop".into());
        assert!(!eng.suppressed);
        eng.process(&[b'A'; 200]);
        assert!(eng.suppressed);
    }

    #[test]
    fn test_capture_since_mark_with_large_history_and_visible() {
        let mut eng = CaptureEngine::new(4, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        for i in 0..50 {
            eng.process(format!("pre{i}\r\n").as_bytes());
        }
        eng.mark();
        for i in 0..50 {
            eng.process(format!("post{i}\r\n").as_bytes());
        }
        let captured = eng.capture_since_mark(65536).unwrap();
        assert!(captured.contains("post0"));
        assert!(captured.contains("post49"));
        assert!(!captured.contains("pre0"));
    }

    #[test]
    fn test_get_lines_with_exact_max() {
        let mut eng = CaptureEngine::new(4, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        for i in 0..10 {
            eng.process(format!("L{i}\r\n").as_bytes());
        }
        let output = eng.get_lines(3);
        let lines: Vec<&str> = output.lines().filter(|l| !l.is_empty()).collect();
        assert!(lines.len() <= 3);
    }

    #[test]
    fn test_sanitize_input_only_control_chars_filtered() {
        for b in 0x00..=0x1Fu8 {
            let input = [b];
            let result = sanitize_input(&input);
            match b {
                0x0A | 0x0D | 0x09 | 0x1B | 0x08 => assert_eq!(result, vec![b]),
                _ => assert!(result.is_empty(), "byte {b:#04x} should be filtered"),
            }
        }
    }
}
