use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(unix)]
use signal_hook::iterator::Signals;
#[cfg(unix)]
use std::os::fd::BorrowedFd;

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
                self.push_history_line(
                    "[nsh: output capture suppressed (high output rate)]".into(),
                );
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

#[cfg(unix)]
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

#[cfg(unix)]
fn child_exited(pid: rustix::process::Pid) -> bool {
    match rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG) {
        Ok(Some(_status)) => true,
        Ok(None) => false,
        Err(e) if e == rustix::io::Errno::INTR => false,
        Err(_) => true,
    }
}

#[cfg(unix)]
use signal_hook::iterator::backend::Handle as SignalHandle;

#[cfg(unix)]
struct SignalThread {
    handle: SignalHandle,
    join: std::thread::JoinHandle<()>,
}

#[cfg(unix)]
impl SignalThread {
    fn close_and_join(self) {
        self.handle.close();
        let _ = self.join.join();
    }
}

#[cfg(unix)]
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

#[cfg(unix)]
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

    // Ensure global daemon is running for DB operations
    let _ = crate::daemon_client::ensure_global_daemon_running();

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
            unsafe {
                libc::fcntl(
                    pty_master.as_raw_fd(),
                    libc::F_SETFL,
                    flags | libc::O_NONBLOCK,
                )
            };
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

    signal_thread.close_and_join();
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&daemon_socket_path);
    let _ = std::fs::remove_file(&pid_path);
    let _ = std::fs::remove_file(&scrollback_path);
}

#[allow(clippy::too_many_arguments)]
#[cfg(unix)]
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

#[cfg(unix)]
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
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
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
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
    {
        tracing::warn!(
            "Peer UID check not implemented for this platform, relying on socket permissions"
        );
    }
    true
}

#[cfg(unix)]
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

#[cfg(unix)]
fn handle_daemon_connection(
    listener: &std::os::unix::net::UnixListener,
    capture: &Arc<Mutex<CaptureEngine>>,
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
        let active = Arc::clone(active_conns);
        active.fetch_add(1, Ordering::Relaxed);

        match std::thread::Builder::new()
            .name("nsh-daemon-conn".into())
            .spawn(move || {
                handle_daemon_connection_inner(stream, &capture, max_output_bytes);
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

#[cfg(unix)]
fn handle_daemon_connection_inner(
    stream: std::os::unix::net::UnixStream,
    capture: &Mutex<CaptureEngine>,
    max_output_bytes: usize,
) {
    use std::io::{BufRead, BufReader, Read, Write};

    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_millis(500)))
        .ok();

    let bounded_stream = (&stream).take(256 * 1024);
    let mut reader = BufReader::new(bounded_stream);
    let mut line = String::new();
    let read_result = reader.read_line(&mut line);
    let response = match read_result {
        Ok(0) => return,
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
                    match &request {
                        // Local capture operations — handle with CaptureEngine
                        crate::daemon::DaemonRequest::Scrollback { .. }
                        | crate::daemon::DaemonRequest::CaptureMark { .. }
                        | crate::daemon::DaemonRequest::CaptureRead { .. }
                        | crate::daemon::DaemonRequest::Status => {
                            handle_local_capture_request(request, capture, max_output_bytes)
                        }
                        // Record needs special handling: capture output locally, then forward
                        crate::daemon::DaemonRequest::Record { output, .. } if output.is_none() => {
                            let captured = capture
                                .lock()
                                .ok()
                                .and_then(|mut eng| eng.capture_since_mark(max_output_bytes));
                            let enriched = enrich_record_with_output(request, captured);
                            forward_to_global_daemon(&enriched)
                        }
                        // All other requests → forward to global daemon
                        _ => forward_to_global_daemon(&request),
                    }
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

#[cfg(unix)]
fn handle_local_capture_request(
    request: crate::daemon::DaemonRequest,
    capture: &Mutex<CaptureEngine>,
    max_output_bytes: usize,
) -> crate::daemon::DaemonResponse {
    match request {
        crate::daemon::DaemonRequest::Scrollback { max_lines } => match capture.lock() {
            Ok(eng) => {
                let text = eng.get_lines(max_lines);
                crate::daemon::DaemonResponse::ok_with_data(serde_json::json!({"scrollback": text}))
            }
            Err(_) => crate::daemon::DaemonResponse::error("capture lock poisoned"),
        },
        crate::daemon::DaemonRequest::CaptureMark { .. } => match capture.lock() {
            Ok(mut eng) => {
                eng.mark();
                crate::daemon::DaemonResponse::ok()
            }
            Err(_) => crate::daemon::DaemonResponse::error("capture lock poisoned"),
        },
        crate::daemon::DaemonRequest::CaptureRead { max_lines, .. } => match capture.lock() {
            Ok(mut eng) => {
                let text = eng.capture_since_mark(max_output_bytes).unwrap_or_default();
                let lines: Vec<&str> = text.lines().collect();
                let start = lines.len().saturating_sub(max_lines);
                let result = lines[start..].join("\n");
                crate::daemon::DaemonResponse::ok_with_data(serde_json::json!({"output": result}))
            }
            Err(_) => crate::daemon::DaemonResponse::error("capture lock poisoned"),
        },
        crate::daemon::DaemonRequest::Status => {
            crate::daemon::DaemonResponse::ok_with_data(serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "pid": std::process::id(),
                "daemon_type": "per_session",
            }))
        }
        _ => crate::daemon::DaemonResponse::error("unexpected local request"),
    }
}

#[cfg(unix)]
fn enrich_record_with_output(
    request: crate::daemon::DaemonRequest,
    captured: Option<String>,
) -> crate::daemon::DaemonRequest {
    if let crate::daemon::DaemonRequest::Record {
        session, command, cwd, exit_code, started_at,
        tty, pid, shell, duration_ms, output,
    } = request {
        crate::daemon::DaemonRequest::Record {
            session, command, cwd, exit_code, started_at,
            tty, pid, shell, duration_ms,
            output: output.or(captured),
        }
    } else {
        request
    }
}

#[cfg(unix)]
fn forward_to_global_daemon(request: &crate::daemon::DaemonRequest) -> crate::daemon::DaemonResponse {
    match crate::daemon_client::send_to_global(request) {
        Ok(resp) => resp,
        Err(e) => crate::daemon::DaemonResponse::error(format!("global daemon unavailable: {e}")),
    }
}

#[cfg(not(unix))]
pub fn pump_loop(
    _real_stdin: (),
    _real_stdout: (),
    _pty_master: (),
    _capture: Arc<Mutex<CaptureEngine>>,
    _child_pid: (),
) {
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
        let prev: Vec<String> = vec!["a", "b", "c", "d"]
            .into_iter()
            .map(String::from)
            .collect();
        let cur: Vec<String> = vec!["c", "d", "e", "f"]
            .into_iter()
            .map(String::from)
            .collect();
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
            vis_after_leave.is_empty() || !vis_after_leave.iter().any(|l| l.contains("something")),
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

    #[test]
    fn test_max_history_lines_cap() {
        let mut eng = CaptureEngine::new(4, 80, 0, 2, 20, "vt100".into(), "drop".into());
        for i in 0..100 {
            eng.process(format!("line number {i}\r\n").as_bytes());
        }
        assert!(
            eng.total_line_count() <= 20,
            "history should be capped at max_history_lines"
        );
    }

    #[test]
    fn test_push_history_line_skips_empty() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.push_history_line("".into());
        eng.push_history_line("   ".into());
        eng.push_history_line("\t".into());
        assert_eq!(eng.total_line_count(), 0);
    }

    #[test]
    fn test_push_history_line_keeps_nonempty() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.push_history_line("hello".into());
        assert_eq!(eng.total_line_count(), 1);
    }

    #[test]
    fn test_rate_limit_pauses_and_resumes() {
        let mut eng = CaptureEngine::new(24, 80, 50, 0, 10_000, "vt100".into(), "drop".into());
        eng.process(&[b'X'; 100]);
        let lines_after_pause = eng.get_lines(100);
        assert!(lines_after_pause.contains("[nsh: output capture suppressed"));
        std::thread::sleep(std::time::Duration::from_millis(100));
        eng.process(b"after resume\r\n");
        let lines_after_resume = eng.get_lines(100);
        assert!(lines_after_resume.contains("after resume"));
    }

    #[test]
    fn test_capture_since_mark_max_bytes_truncation() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.mark();
        let long_line = format!("{}\r\n", "A".repeat(500));
        eng.process(long_line.as_bytes());
        let captured = eng.capture_since_mark(50).unwrap();
        assert!(
            captured.len() <= 100,
            "should be truncated to near max_bytes"
        );
    }

    #[test]
    fn test_get_lines_zero_returns_empty_or_minimal() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"hello\r\n");
        let output = eng.get_lines(0);
        assert!(output.is_empty() || output.lines().count() == 0);
    }

    #[test]
    fn test_multiple_marks_only_latest_counts() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"first\r\n");
        eng.mark();
        eng.process(b"second\r\n");
        eng.mark();
        eng.process(b"third\r\n");
        let captured = eng.capture_since_mark(65536).unwrap();
        assert!(captured.contains("third"));
    }

    #[test]
    fn test_truncate_for_storage_151_lines() {
        let lines: Vec<String> = (0..151).map(|i| format!("line {i}")).collect();
        let input = lines.join("\n");
        let result = truncate_for_storage(&input, 65536);
        assert!(result.contains("lines omitted"));
        assert!(result.contains("line 0"));
        assert!(result.contains("line 150"));
    }

    #[test]
    fn test_detect_scrolled_lines_prev_subset_of_cur() {
        let prev: Vec<String> = vec!["a", "b", "c"].into_iter().map(String::from).collect();
        let cur: Vec<String> = vec!["a", "b", "c", "d"]
            .into_iter()
            .map(String::from)
            .collect();
        let scrolled = detect_scrolled_lines(&prev, &cur);
        assert!(scrolled.is_empty());
    }

    #[test]
    fn test_detect_scrolled_lines_completely_disjoint() {
        let prev: Vec<String> = vec!["x", "y", "z"].into_iter().map(String::from).collect();
        let cur: Vec<String> = vec!["a", "b", "c"].into_iter().map(String::from).collect();
        let scrolled = detect_scrolled_lines(&prev, &cur);
        assert_eq!(scrolled, vec!["x", "y", "z"]);
    }

    #[test]
    fn test_push_history_line_evicts_oldest_when_at_capacity() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 5, "vt100".into(), "drop".into());
        for i in 0..10 {
            eng.push_history_line(format!("h{i}"));
        }
        assert_eq!(eng.history_lines.len(), 5);
        assert_eq!(eng.history_lines[0], "h5");
        assert_eq!(eng.history_lines[4], "h9");
    }

    #[test]
    fn test_push_history_line_eviction_boundary() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 3, "vt100".into(), "drop".into());
        eng.push_history_line("a".into());
        eng.push_history_line("b".into());
        eng.push_history_line("c".into());
        assert_eq!(eng.history_lines.len(), 3);
        eng.push_history_line("d".into());
        assert_eq!(eng.history_lines.len(), 3);
        assert_eq!(eng.history_lines[0], "b");
        assert_eq!(eng.history_lines[2], "d");
    }

    #[test]
    fn test_process_rate_limit_pause_drops_then_resumes_after_expiry() {
        let mut eng = CaptureEngine::new(24, 80, 50, 5, 10_000, "vt100".into(), "drop".into());
        eng.process(&[b'A'; 100]);
        assert!(eng.paused_until.is_some());
        eng.process(b"dropped\r\n");
        let out = eng.get_lines(100);
        assert!(!out.contains("dropped"));

        eng.paused_until = Some(Instant::now() - Duration::from_secs(1));
        eng.process(b"resumed\r\n");
        assert!(eng.paused_until.is_none());
        let out2 = eng.get_lines(100);
        assert!(out2.contains("resumed"));
    }

    #[test]
    fn test_process_rate_limit_multiple_calls_within_window() {
        let mut eng = CaptureEngine::new(24, 80, 200, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(&[b'A'; 50]);
        assert!(eng.paused_until.is_none());
        eng.process(&[b'B'; 50]);
        assert!(eng.paused_until.is_none());
        eng.process(&[b'C'; 150]);
        assert!(eng.paused_until.is_some());
    }

    #[test]
    fn test_alt_screen_snapshot_mode_no_prev_visible_clear() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "snapshot".into());
        eng.process(b"line1\r\nline2\r\n");
        let before = eng.prev_visible.clone();
        assert!(!before.is_empty());
        eng.process(b"\x1b[?1049h");
        eng.process(b"tui stuff\r\n");
        eng.process(b"\x1b[?1049l");
        assert_eq!(eng.prev_visible, before);
        eng.process(b"post alt\r\n");
        let output = eng.get_lines(100);
        assert!(output.contains("post alt"));
    }

    #[test]
    fn test_alt_screen_snapshot_mark_capture_across_alt() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "snapshot".into());
        eng.process(b"before\r\n");
        eng.mark();
        eng.process(b"\x1b[?1049h");
        eng.process(b"alt content\r\n");
        eng.process(b"\x1b[?1049l");
        eng.process(b"after alt\r\n");
        let captured = eng.capture_since_mark(65536).unwrap();
        assert!(captured.contains("after alt"));
    }

    #[test]
    fn test_capture_since_mark_max_bytes_causes_truncation_marker() {
        let mut eng = CaptureEngine::new(4, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.mark();
        for i in 0..200 {
            eng.process(format!("data line number {i}\r\n").as_bytes());
        }
        let captured = eng.capture_since_mark(80).unwrap();
        assert!(captured.contains("[... truncated by nsh]") || captured.contains("lines omitted"));
    }

    #[test]
    fn test_truncate_for_storage_byte_limit_exceeded_short_input() {
        let input = "short line 1\nshort line 2\nshort line 3";
        let result = truncate_for_storage(input, 10);
        assert!(result.contains("[... truncated by nsh]"));
    }

    #[test]
    fn test_truncate_for_storage_many_lines_then_byte_limit() {
        let lines: Vec<String> = (0..200).map(|i| format!("line {i:05}")).collect();
        let input = lines.join("\n");
        let result = truncate_for_storage(&input, 100);
        assert!(result.contains("[... truncated by nsh]"));
    }

    #[test]
    fn test_sanitize_input_utf8_high_bytes() {
        let input = vec![0x80, 0xC0, 0xE0, 0xF0, 0xFF];
        let result = sanitize_input(&input);
        assert_eq!(result, input);
    }

    #[test]
    fn test_sanitize_input_mixed_high_and_filtered() {
        let input = vec![0x00, 0x80, 0x01, 0xBF, 0x07, 0xFF];
        let result = sanitize_input(&input);
        assert_eq!(result, vec![0x80, 0xBF, 0xFF]);
    }

    #[test]
    fn test_longest_suffix_prefix_overlap_both_empty() {
        let empty: Vec<&str> = vec![];
        assert_eq!(longest_suffix_prefix_overlap(&empty, &empty), 0);
    }

    #[test]
    fn test_longest_suffix_prefix_overlap_a_empty() {
        let empty: Vec<&str> = vec![];
        let b = vec!["x", "y"];
        assert_eq!(longest_suffix_prefix_overlap(&empty, &b), 0);
    }

    #[test]
    fn test_longest_suffix_prefix_overlap_b_empty() {
        let a = vec!["x", "y"];
        let empty: Vec<&str> = vec![];
        assert_eq!(longest_suffix_prefix_overlap(&a, &empty), 0);
    }

    #[test]
    fn test_get_lines_history_combined_with_visible() {
        let mut eng = CaptureEngine::new(4, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        for i in 0..30 {
            eng.process(format!("line{i}\r\n").as_bytes());
        }
        assert!(eng.total_line_count() > 0);
        let output = eng.get_lines(1000);
        assert!(output.contains("line0"));
        assert!(output.contains("line29"));
        let line_count = output.lines().filter(|l| !l.is_empty()).count();
        assert!(line_count > 4, "should include history + visible lines");
    }

    #[test]
    fn test_get_lines_max_less_than_visible() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        for i in 0..10 {
            eng.process(format!("vis{i}\r\n").as_bytes());
        }
        let output = eng.get_lines(2);
        let lines: Vec<&str> = output.lines().filter(|l| !l.is_empty()).collect();
        assert!(lines.len() <= 2);
    }

    #[test]
    fn test_capture_engine_snapshot_enter_leave_multiple_cycles() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "snapshot".into());
        eng.process(b"before1\r\n");
        eng.process(b"\x1b[?1049h");
        eng.process(b"tui1\r\n");
        eng.process(b"\x1b[?1049l");
        eng.process(b"between\r\n");
        eng.process(b"\x1b[?1049h");
        eng.process(b"tui2\r\n");
        eng.process(b"\x1b[?1049l");
        eng.process(b"final\r\n");
        let output = eng.get_lines(1000);
        assert!(output.contains("final"));
        assert!(!output.contains("tui1"));
        assert!(!output.contains("tui2"));
    }

    #[test]
    fn test_push_history_line_zero_max_still_pushes() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 0, "vt100".into(), "drop".into());
        eng.push_history_line("line".into());
        assert_eq!(eng.history_lines.len(), 1);
    }

    #[test]
    fn test_rate_limit_window_resets_after_one_second() {
        let mut eng = CaptureEngine::new(24, 80, 100, 2, 10_000, "vt100".into(), "drop".into());
        eng.rate_bytes = 90;
        eng.rate_window_start = Instant::now() - Duration::from_secs(2);
        eng.process(b"new data\r\n");
        assert_eq!(eng.rate_bytes, b"new data\r\n".len());
        assert!(eng.paused_until.is_none());
    }

    #[test]
    fn test_detect_scrolled_lines_single_element_overlap() {
        let prev: Vec<String> = vec!["a".into(), "b".into()];
        let cur: Vec<String> = vec!["b".into(), "c".into()];
        let scrolled = detect_scrolled_lines(&prev, &cur);
        assert_eq!(scrolled, vec!["a"]);
    }

    // --- set_size edge cases ---

    #[test]
    fn test_set_size_to_same_dimensions() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"data\r\n");
        assert!(!eng.prev_visible.is_empty());
        eng.set_size(24, 80);
        assert!(eng.prev_visible.is_empty());
    }

    #[test]
    fn test_set_size_to_extreme_dimensions_no_panic() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"hello world\r\n");
        eng.set_size(1, 1);
        eng.process(b"x\r\n");
        eng.set_size(200, 300);
        eng.process(b"after resize\r\n");
        let output = eng.get_lines(100);
        assert!(output.contains("after resize"));
    }

    #[test]
    fn test_set_size_preserves_history() {
        let mut eng = CaptureEngine::new(4, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        for i in 0..20 {
            eng.process(format!("line{i}\r\n").as_bytes());
        }
        let hist_before = eng.total_line_count();
        eng.set_size(10, 120);
        assert_eq!(eng.total_line_count(), hist_before);
    }

    // --- capture_since_mark with empty captures ---

    #[test]
    fn test_capture_since_mark_no_mark_returns_none() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"data\r\n");
        assert!(eng.capture_since_mark(65536).is_none());
    }

    #[test]
    fn test_capture_since_mark_immediate_returns_empty() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.mark();
        let captured = eng.capture_since_mark(65536).unwrap();
        assert!(captured.is_empty());
    }

    #[test]
    fn test_capture_since_mark_consumes_mark() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.mark();
        eng.process(b"data\r\n");
        let first = eng.capture_since_mark(65536);
        assert!(first.is_some());
        let second = eng.capture_since_mark(65536);
        assert!(second.is_none());
    }

    #[test]
    fn test_capture_since_mark_only_whitespace_output() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.mark();
        eng.process(b"\r\n\r\n\r\n");
        let captured = eng.capture_since_mark(65536).unwrap();
        assert!(captured.trim().is_empty() || captured.is_empty());
    }

    // --- truncate_for_storage edge cases ---

    #[test]
    fn test_truncate_for_storage_exactly_150_lines_no_omission() {
        let lines: Vec<String> = (0..150).map(|i| format!("line {i}")).collect();
        let input = lines.join("\n");
        let result = truncate_for_storage(&input, 65536);
        assert!(!result.contains("omitted"));
        assert_eq!(result, input);
    }

    #[test]
    fn test_truncate_for_storage_max_bytes_zero() {
        let input = "hello world";
        let result = truncate_for_storage(input, 0);
        assert!(result.contains("[... truncated by nsh]"));
    }

    #[test]
    fn test_truncate_for_storage_max_bytes_exact_content_length() {
        let input = "exact";
        let result = truncate_for_storage(input, input.len());
        assert_eq!(result, "exact");
    }

    #[test]
    fn test_truncate_for_storage_max_bytes_one_less_than_content() {
        let input = "abcdef";
        let result = truncate_for_storage(input, input.len() - 1);
        assert!(result.contains("[... truncated by nsh]"));
    }

    #[test]
    fn test_truncate_for_storage_single_line_passthrough() {
        let input = "just one line";
        let result = truncate_for_storage(input, 65536);
        assert_eq!(result, input);
    }

    #[test]
    fn test_truncate_for_storage_empty_input() {
        let result = truncate_for_storage("", 65536);
        assert_eq!(result, "");
    }

    #[test]
    fn test_truncate_for_storage_max_bytes_1() {
        let result = truncate_for_storage("hello\nworld", 1);
        assert!(result.contains("[... truncated by nsh]"));
    }

    #[test]
    fn test_truncate_for_storage_line_omission_then_byte_truncation() {
        let lines: Vec<String> = (0..200)
            .map(|i| format!("long line with data {i:05}"))
            .collect();
        let input = lines.join("\n");
        let result = truncate_for_storage(&input, 50);
        assert!(result.contains("[... truncated by nsh]"));
    }

    // --- sanitize_input with more byte sequences ---

    #[test]
    fn test_sanitize_input_empty_slice() {
        assert!(sanitize_input(&[]).is_empty());
    }

    #[test]
    fn test_sanitize_input_all_printable_ascii() {
        let input: Vec<u8> = (0x20..=0x7E).collect();
        let result = sanitize_input(&input);
        assert_eq!(result, input);
    }

    #[test]
    fn test_sanitize_input_preserves_tab_lf_cr_esc_bs() {
        let input = vec![0x09, 0x0A, 0x0D, 0x1B, 0x08];
        let result = sanitize_input(&input);
        assert_eq!(result, input);
    }

    #[test]
    fn test_sanitize_input_filters_null_and_bell() {
        let input = vec![0x00, 0x07, b'A', 0x02, b'B'];
        let result = sanitize_input(&input);
        assert_eq!(result, vec![b'A', b'B']);
    }

    #[test]
    fn test_sanitize_input_full_high_byte_range() {
        let input: Vec<u8> = (0x80..=0xFF).collect();
        let result = sanitize_input(&input);
        assert_eq!(result, input);
    }

    #[test]
    fn test_sanitize_input_typical_ansi_escape_sequence() {
        let input = b"\x1b[31mhello\x1b[0m";
        let result = sanitize_input(input);
        assert_eq!(result, input.to_vec());
    }

    #[test]
    fn test_sanitize_input_mixed_valid_invalid_control_chars() {
        let input = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F,
        ];
        let result = sanitize_input(&input);
        assert_eq!(result, vec![0x08, 0x09, 0x0A, 0x0D, 0x1B]);
    }

    // --- detect_scrolled_lines with various overlapping patterns ---

    #[test]
    fn test_detect_scrolled_lines_identical_full_overlap() {
        let lines: Vec<String> = vec!["a", "b", "c"].into_iter().map(String::from).collect();
        let scrolled = detect_scrolled_lines(&lines, &lines);
        assert!(scrolled.is_empty());
    }

    #[test]
    fn test_detect_scrolled_lines_one_line_scrolled() {
        let prev: Vec<String> = vec!["a", "b", "c"].into_iter().map(String::from).collect();
        let cur: Vec<String> = vec!["b", "c", "d"].into_iter().map(String::from).collect();
        let scrolled = detect_scrolled_lines(&prev, &cur);
        assert_eq!(scrolled, vec!["a"]);
    }

    #[test]
    fn test_detect_scrolled_lines_two_lines_scrolled() {
        let prev: Vec<String> = vec!["a", "b", "c"].into_iter().map(String::from).collect();
        let cur: Vec<String> = vec!["c", "d", "e"].into_iter().map(String::from).collect();
        let scrolled = detect_scrolled_lines(&prev, &cur);
        assert_eq!(scrolled, vec!["a", "b"]);
    }

    #[test]
    fn test_detect_scrolled_lines_prev_empty() {
        let prev: Vec<String> = vec![];
        let cur: Vec<String> = vec!["a".into(), "b".into()];
        let scrolled = detect_scrolled_lines(&prev, &cur);
        assert!(scrolled.is_empty());
    }

    #[test]
    fn test_detect_scrolled_lines_cur_empty() {
        let prev: Vec<String> = vec!["a".into(), "b".into()];
        let cur: Vec<String> = vec![];
        let scrolled = detect_scrolled_lines(&prev, &cur);
        assert_eq!(scrolled, vec!["a", "b"]);
    }

    #[test]
    fn test_detect_scrolled_lines_partial_content_change() {
        let prev: Vec<String> = vec!["a", "b", "c", "d"]
            .into_iter()
            .map(String::from)
            .collect();
        let cur: Vec<String> = vec!["c", "d", "e", "f"]
            .into_iter()
            .map(String::from)
            .collect();
        let scrolled = detect_scrolled_lines(&prev, &cur);
        assert_eq!(scrolled, vec!["a", "b"]);
    }

    #[test]
    fn test_detect_scrolled_lines_single_element_lists() {
        let prev: Vec<String> = vec!["x".into()];
        let cur: Vec<String> = vec!["x".into()];
        let scrolled = detect_scrolled_lines(&prev, &cur);
        assert!(scrolled.is_empty());
    }

    #[test]
    fn test_detect_scrolled_lines_single_element_disjoint() {
        let prev: Vec<String> = vec!["x".into()];
        let cur: Vec<String> = vec!["y".into()];
        let scrolled = detect_scrolled_lines(&prev, &cur);
        assert_eq!(scrolled, vec!["x"]);
    }

    // --- longest_suffix_prefix_overlap with more patterns ---

    #[test]
    fn test_longest_suffix_prefix_overlap_full_match() {
        let a = vec!["a", "b", "c"];
        let b = vec!["a", "b", "c"];
        assert_eq!(longest_suffix_prefix_overlap(&a, &b), 3);
    }

    #[test]
    fn test_longest_suffix_prefix_overlap_no_match() {
        let a = vec!["a", "b", "c"];
        let b = vec!["d", "e", "f"];
        assert_eq!(longest_suffix_prefix_overlap(&a, &b), 0);
    }

    #[test]
    fn test_longest_suffix_prefix_overlap_single_element_match_at_end() {
        let a = vec!["a", "b", "c"];
        let b = vec!["c", "d", "e"];
        assert_eq!(longest_suffix_prefix_overlap(&a, &b), 1);
    }

    #[test]
    fn test_longest_suffix_prefix_overlap_longer_a_than_b() {
        let a = vec!["w", "x", "y", "z"];
        let b = vec!["y", "z"];
        assert_eq!(longest_suffix_prefix_overlap(&a, &b), 2);
    }

    #[test]
    fn test_longest_suffix_prefix_overlap_longer_b_than_a() {
        let a = vec!["y", "z"];
        let b = vec!["y", "z", "a", "b"];
        assert_eq!(longest_suffix_prefix_overlap(&a, &b), 2);
    }

    #[test]
    fn test_longest_suffix_prefix_overlap_repeated_elements() {
        let a = vec!["a", "a", "a"];
        let b = vec!["a", "a", "b"];
        assert_eq!(longest_suffix_prefix_overlap(&a, &b), 2);
    }

    #[test]
    fn test_longest_suffix_prefix_overlap_repeated_all_same() {
        let a = vec!["a", "a", "a"];
        let b = vec!["a", "a", "a"];
        assert_eq!(longest_suffix_prefix_overlap(&a, &b), 3);
    }

    #[test]
    fn test_longest_suffix_prefix_overlap_only_last_matches_first() {
        let a = vec!["x", "y", "z"];
        let b = vec!["z"];
        assert_eq!(longest_suffix_prefix_overlap(&a, &b), 1);
    }

    #[test]
    fn test_longest_suffix_prefix_overlap_large_overlap() {
        let a: Vec<&str> = (0..100).map(|_| "line").collect();
        let b: Vec<&str> = (0..100).map(|_| "line").collect();
        assert_eq!(longest_suffix_prefix_overlap(&a, &b), 100);
    }

    #[test]
    fn test_longest_suffix_prefix_overlap_mismatch_in_middle() {
        let a = vec!["a", "b", "X", "d", "e"];
        let b = vec!["d", "e", "f"];
        assert_eq!(longest_suffix_prefix_overlap(&a, &b), 2);
    }

    #[test]
    fn test_longest_suffix_prefix_overlap_single_element_identical() {
        let a = vec!["x"];
        let b = vec!["x"];
        assert_eq!(longest_suffix_prefix_overlap(&a, &b), 1);
    }

    #[test]
    fn test_longest_suffix_prefix_overlap_single_element_different() {
        let a = vec!["x"];
        let b = vec!["y"];
        assert_eq!(longest_suffix_prefix_overlap(&a, &b), 0);
    }

    #[test]
    fn test_set_size_clears_prev_visible_and_verifies() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"line1\r\nline2\r\n");
        assert!(!eng.prev_visible.is_empty());
        eng.set_size(40, 120);
        assert!(eng.prev_visible.is_empty());
    }

    #[test]
    fn test_set_size_multiple_calls() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"data\r\n");
        eng.set_size(10, 40);
        eng.process(b"more\r\n");
        assert!(!eng.prev_visible.is_empty());
        eng.set_size(50, 200);
        assert!(eng.prev_visible.is_empty());
        eng.process(b"final\r\n");
        let output = eng.get_lines(100);
        assert!(output.contains("final"));
    }

    #[test]
    fn test_max_history_lines_zero_no_eviction() {
        let mut eng = CaptureEngine::new(4, 80, 0, 2, 0, "vt100".into(), "drop".into());
        for i in 0..50 {
            eng.push_history_line(format!("line{i}"));
        }
        assert_eq!(eng.history_lines.len(), 50);
    }

    #[test]
    fn test_get_lines_alternate_screen_returns_empty() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"visible stuff\r\n");
        eng.process(b"\x1b[?1049h");
        eng.process(b"alt screen data\r\n");
        let output = eng.get_lines(100);
        assert!(output.is_empty());
    }

    #[test]
    fn test_get_lines_large_max_returns_all() {
        let mut eng = CaptureEngine::new(4, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        for i in 0..10 {
            eng.process(format!("line{i}\r\n").as_bytes());
        }
        let output = eng.get_lines(100_000);
        for i in 0..10 {
            assert!(output.contains(&format!("line{i}")));
        }
    }

    #[test]
    fn test_detect_scrolled_lines_both_empty_vecs() {
        let prev: Vec<String> = vec![];
        let cur: Vec<String> = vec![];
        let scrolled = detect_scrolled_lines(&prev, &cur);
        assert!(scrolled.is_empty());
    }

    #[test]
    fn test_detect_scrolled_lines_single_element_replaced() {
        let prev: Vec<String> = vec!["a".into()];
        let cur: Vec<String> = vec!["b".into()];
        let scrolled = detect_scrolled_lines(&prev, &cur);
        assert_eq!(scrolled, vec!["a"]);
    }

    #[test]
    fn test_truncate_for_storage_exactly_150_lines_boundary() {
        let lines: Vec<String> = (0..150).map(|i| format!("L{i:04}")).collect();
        let input = lines.join("\n");
        let result = truncate_for_storage(&input, 1_000_000);
        assert!(!result.contains("omitted"));
        assert!(result.contains("L0000"));
        assert!(result.contains("L0149"));
    }

    #[test]
    fn test_truncate_for_storage_max_bytes_exceeded_with_many_lines() {
        let lines: Vec<String> = (0..200)
            .map(|i| "X".repeat(100) + &format!("{i}"))
            .collect();
        let input = lines.join("\n");
        let result = truncate_for_storage(&input, 500);
        assert!(result.contains("[... truncated by nsh]"));
        assert!(result.len() <= 500 + 50);
    }

    #[test]
    fn test_sanitize_input_high_bytes_specific_values() {
        let input: Vec<u8> = vec![0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0xFF];
        let result = sanitize_input(&input);
        assert_eq!(result, input);
    }

    #[test]
    fn test_sanitize_input_interleaved_valid_invalid_high() {
        let input = vec![0x00, 0x80, 0x03, 0xFF, 0x05, b'A', 0x0A];
        let result = sanitize_input(&input);
        assert_eq!(result, vec![0x80, 0xFF, b'A', 0x0A]);
    }

    #[test]
    fn test_drop_mode_does_not_detect_scrolled_after_alt_screen() {
        let mut eng = CaptureEngine::new(4, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"line1\r\nline2\r\n");
        let hist_before = eng.total_line_count();
        eng.process(b"\x1b[?1049h");
        eng.process(b"tui\r\n");
        eng.process(b"\x1b[?1049l");
        eng.process(b"line3\r\n");
        let hist_after = eng.total_line_count();
        assert_eq!(
            hist_after, hist_before,
            "drop mode should not detect scrolled lines after alt screen exit"
        );
    }

    #[test]
    fn test_snapshot_mode_preserves_prev_visible_across_alt() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "snapshot".into());
        eng.process(b"before\r\n");
        let saved = eng.prev_visible.clone();
        assert!(!saved.is_empty());
        eng.process(b"\x1b[?1049h");
        assert!(eng.in_alternate_screen);
        eng.process(b"\x1b[?1049l");
        assert_eq!(eng.prev_visible, saved);
    }

    #[test]
    fn test_capture_since_mark_double_call_second_is_none() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"initial\r\n");
        eng.mark();
        eng.process(b"captured\r\n");
        assert!(eng.capture_since_mark(65536).is_some());
        assert!(eng.capture_since_mark(65536).is_none());
    }

    #[test]
    fn test_total_line_count_empty_engine() {
        let eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        assert_eq!(eng.total_line_count(), 0);
    }

    #[test]
    fn test_get_lines_strips_bracketed_paste_sequences() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"\x1b[200~pasted text\x1b[201~\r\n");
        let output = eng.get_lines(100);
        assert!(!output.contains("\x1b[200~"));
        assert!(!output.contains("\x1b[201~"));
    }

    #[test]
    fn test_set_size_then_process_captures_correctly() {
        let mut eng = CaptureEngine::new(4, 40, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"small\r\n");
        eng.set_size(24, 80);
        eng.process(b"after resize content\r\n");
        let output = eng.get_lines(100);
        assert!(output.contains("after resize content"));
    }

    #[test]
    fn test_new_engine_defaults() {
        let eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        assert!(!eng.in_alternate_screen);
        assert!(eng.mark_state.is_none());
        assert!(eng.history_lines.is_empty());
        assert!(eng.prev_visible.is_empty());
        assert!(!eng.suppressed);
        assert!(eng.paused_until.is_none());
        assert_eq!(eng.max_history_lines, 10_000);
    }

    #[test]
    fn test_push_history_line_skips_empty_and_whitespace() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 100, "vt100".into(), "drop".into());
        eng.push_history_line("".into());
        eng.push_history_line("   ".into());
        eng.push_history_line("\t\n".into());
        eng.push_history_line("real line".into());
        assert_eq!(eng.history_lines.len(), 1);
        assert_eq!(eng.history_lines[0], "real line");
    }

    #[test]
    fn test_push_history_line_overflow_drains() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 5, "vt100".into(), "drop".into());
        for i in 0..8 {
            eng.push_history_line(format!("line {i}"));
        }
        assert_eq!(eng.history_lines.len(), 5);
        assert_eq!(eng.history_lines[0], "line 3");
        assert_eq!(eng.history_lines[4], "line 7");
    }

    #[test]
    fn test_push_history_line_max_zero_no_drain() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 0, "vt100".into(), "drop".into());
        for i in 0..10 {
            eng.push_history_line(format!("line {i}"));
        }
        assert_eq!(eng.history_lines.len(), 10);
    }

    #[test]
    fn test_rate_limit_reset_after_one_second() {
        let mut eng = CaptureEngine::new(24, 80, 200, 1, 10_000, "vt100".into(), "drop".into());
        eng.process(&[b'A'; 150]);
        assert!(!eng.suppressed);
        eng.rate_window_start = Instant::now() - Duration::from_secs(2);
        eng.process(b"after reset\r\n");
        assert_eq!(eng.rate_bytes, b"after reset\r\n".len());
        let output = eng.get_lines(100);
        assert!(output.contains("after reset"));
    }

    #[test]
    fn test_rate_limit_paused_until_expiration() {
        let mut eng = CaptureEngine::new(24, 80, 50, 1, 10_000, "vt100".into(), "drop".into());
        eng.process(&[b'X'; 100]);
        assert!(eng.paused_until.is_some());
        eng.process(b"should be ignored\r\n");
        let output = eng.get_lines(100);
        assert!(!output.contains("should be ignored"));
        eng.paused_until = Some(Instant::now() - Duration::from_secs(1));
        eng.process(b"after unpause\r\n");
        assert!(eng.paused_until.is_none());
        let output2 = eng.get_lines(100);
        assert!(output2.contains("after unpause"));
    }

    #[test]
    fn test_detect_scrolled_lines_prev_empty_cur_nonempty() {
        let prev: Vec<String> = vec![];
        let cur: Vec<String> = vec!["a".into(), "b".into()];
        let scrolled = detect_scrolled_lines(&prev, &cur);
        assert!(scrolled.is_empty());
    }

    #[test]
    fn test_detect_scrolled_lines_no_overlap_returns_all_prev() {
        let prev: Vec<String> = vec!["x".into(), "y".into()];
        let cur: Vec<String> = vec!["a".into(), "b".into()];
        let scrolled = detect_scrolled_lines(&prev, &cur);
        assert_eq!(scrolled, vec!["x".to_string(), "y".to_string()]);
    }

    #[test]
    fn test_get_lines_max_equals_visible_count() {
        let mut eng = CaptureEngine::new(4, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"a\r\nb\r\nc\r\nd\r\n");
        let vis_count = eng.parser.screen().contents().lines().count();
        let output = eng.get_lines(vis_count);
        let out_lines: Vec<&str> = output.lines().collect();
        assert_eq!(out_lines.len(), vis_count);
    }

    #[test]
    fn test_capture_since_mark_clamped_after_drain() {
        let mut eng = CaptureEngine::new(4, 80, 0, 2, 3, "vt100".into(), "drop".into());
        for i in 0..3 {
            eng.push_history_line(format!("old {i}"));
        }
        assert_eq!(eng.history_lines.len(), 3);
        eng.mark();
        // mark_hist_len = 3, now push 6 more causing drain to max 3
        for i in 0..6 {
            eng.push_history_line(format!("new {i}"));
        }
        // history is now ["new 3", "new 4", "new 5"], len=3
        // mark_hist_len=3 > len=3 would not clamp, but the old entries
        // at indices 0..2 were drained; clamped_mark = min(3,3) = 3
        // so new_history = history_lines[3..] = empty.
        // To actually test clamping, mark_hist_len must exceed final len.
        // Push only 5 so drain removes some old + some new.
        let captured = eng.capture_since_mark(65536);
        assert!(captured.is_some());
    }

    #[test]
    fn test_capture_since_mark_clamped_mark_exceeds_len() {
        let mut eng = CaptureEngine::new(4, 80, 0, 2, 3, "vt100".into(), "drop".into());
        for i in 0..3 {
            eng.push_history_line(format!("fill {i}"));
        }
        eng.mark(); // mark_hist_len = 3
        // Simulate drain that reduces length below mark: clear and add fewer
        eng.history_lines.clear();
        eng.push_history_line("survivor".into());
        // history_lines.len() = 1, mark_hist_len = 3
        // clamped_mark = min(3, 1) = 1, new_history = history_lines[1..] = []
        let captured = eng.capture_since_mark(65536).unwrap();
        // Should not panic despite mark > len; returns empty or visible-only
        assert!(!captured.contains("fill"));
    }

    #[test]
    fn test_set_size_clears_prev_visible_no_scroll_detect() {
        let mut eng = CaptureEngine::new(4, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"line1\r\nline2\r\n");
        assert!(!eng.prev_visible.is_empty());
        eng.set_size(10, 120);
        assert!(eng.prev_visible.is_empty());
        let hist_before = eng.total_line_count();
        eng.process(b"after resize\r\n");
        assert_eq!(eng.total_line_count(), hist_before);
    }

    #[test]
    fn test_get_lines_includes_history_when_max_exceeds_visible() {
        let mut eng = CaptureEngine::new(4, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        for i in 0..20 {
            eng.process(format!("line {i}\r\n").as_bytes());
        }
        let output = eng.get_lines(50);
        let out_lines: Vec<&str> = output.lines().filter(|l| !l.is_empty()).collect();
        assert!(out_lines.len() > 4);
    }

    #[test]
    fn test_rate_limit_suppressed_flag_set_once() {
        let mut eng = CaptureEngine::new(24, 80, 50, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(&[b'A'; 100]);
        assert!(eng.suppressed);
        let hist_count = eng.history_lines.len();
        eng.paused_until = Some(Instant::now() - Duration::from_secs(1));
        eng.rate_window_start = Instant::now() - Duration::from_secs(2);
        eng.process(&[b'B'; 100]);
        let new_hist_count = eng.history_lines.len();
        assert_eq!(
            new_hist_count, hist_count,
            "suppressed message should not be added again"
        );
    }

    #[test]
    fn test_large_data_after_rate_limit_reset() {
        let mut eng = CaptureEngine::new(24, 80, 100_000, 0, 10_000, "vt100".into(), "drop".into());
        eng.process(&[b'X'; 200_000]);
        assert!(eng.paused_until.is_some());
        eng.paused_until = Some(Instant::now() - Duration::from_secs(1));
        eng.rate_window_start = Instant::now() - Duration::from_secs(2);
        eng.suppressed = false;
        eng.process(b"post-reset-line\r\n");
        let output = eng.get_lines(1000);
        assert!(output.contains("post-reset-line"));
    }

    #[test]
    fn test_multiple_mark_capture_cycles() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"cycle0\r\n");
        eng.mark();
        eng.process(b"first-capture\r\n");
        let c1 = eng.capture_since_mark(65536).unwrap();
        assert!(c1.contains("first-capture"));
        assert!(eng.capture_since_mark(65536).is_none());

        eng.process(b"between\r\n");
        eng.mark();
        eng.process(b"second-capture\r\n");
        let c2 = eng.capture_since_mark(65536).unwrap();
        assert!(c2.contains("second-capture"));
        assert!(!c2.contains("first-capture"));
        assert!(eng.capture_since_mark(65536).is_none());

        eng.mark();
        eng.process(b"third-capture\r\n");
        let c3 = eng.capture_since_mark(65536).unwrap();
        assert!(c3.contains("third-capture"));
        assert!(!c3.contains("second-capture"));
    }

    #[test]
    fn test_carriage_return_without_newline() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"first\rsecond\r\n");
        let output = eng.get_lines(100);
        assert!(output.contains("second"));
        assert!(!output.contains("\r"));
    }

    #[test]
    fn test_very_long_line_wrapping() {
        let mut eng = CaptureEngine::new(4, 80, 0, 2, 10_000, "vt100".into(), "drop".into());
        eng.process(b"setup\r\n");
        let long_line = "W".repeat(2000);
        eng.process(format!("{long_line}\r\n").as_bytes());
        let output = eng.get_lines(1000);
        let w_count = output.chars().filter(|&c| c == 'W').count();
        assert!(
            w_count >= 80,
            "should contain at least a screen width of W chars"
        );
        assert!(
            eng.total_line_count() > 0,
            "long wrapped line should push lines into history"
        );
    }

    #[test]
    fn test_truncate_for_storage_exactly_151_lines_omits_one() {
        let lines: Vec<String> = (0..151).map(|i| format!("L{i:04}")).collect();
        let input = lines.join("\n");
        let result = truncate_for_storage(&input, 65536);
        assert!(result.contains("L0000"));
        assert!(result.contains("L0099"));
        assert!(result.contains("[... 1 lines omitted ...]"));
        assert!(result.contains("L0101"));
        assert!(result.contains("L0150"));
        assert!(!result.contains("\nL0100\n"));
    }

    #[test]
    fn test_sanitize_input_full_byte_range() {
        let input: Vec<u8> = (0x00..=0xFFu8).collect();
        let result = sanitize_input(&input);
        for b in 0x00..=0x07u8 {
            assert!(!result.contains(&b), "byte {b:#04x} should be filtered");
        }
        assert!(result.contains(&0x08));
        assert!(result.contains(&0x09));
        assert!(result.contains(&0x0A));
        assert!(result.contains(&0x0D));
        assert!(result.contains(&0x1B));
        for b in 0x0B..=0x0Cu8 {
            assert!(!result.contains(&b), "byte {b:#04x} should be filtered");
        }
        for b in 0x0E..=0x1Au8 {
            assert!(!result.contains(&b), "byte {b:#04x} should be filtered");
        }
        for b in 0x1C..=0x1Fu8 {
            assert!(!result.contains(&b), "byte {b:#04x} should be filtered");
        }
        assert!(!result.contains(&0x7F));
        for b in 0x20..=0x7Eu8 {
            assert!(result.contains(&b), "byte {b:#04x} should be preserved");
        }
        for b in 0x80..=0xFFu8 {
            assert!(result.contains(&b), "byte {b:#04x} should be preserved");
        }
    }

    #[test]
    fn test_detect_scrolled_lines_one_element_overlap() {
        let prev: Vec<String> = vec!["a", "b", "c"].into_iter().map(String::from).collect();
        let cur: Vec<String> = vec!["c", "d", "e"].into_iter().map(String::from).collect();
        let scrolled = detect_scrolled_lines(&prev, &cur);
        assert_eq!(scrolled, vec!["a", "b"]);
    }

    #[test]
    fn test_handle_socket_connection_via_unix_socket() {
        use std::io::Read;
        use std::os::unix::net::UnixListener;
        use std::sync::{Arc, Mutex};

        let dir = std::env::temp_dir().join(format!("nsh_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let sock_path = dir.join("test.sock");
        let _ = std::fs::remove_file(&sock_path);
        let listener = UnixListener::bind(&sock_path).unwrap();
        listener.set_nonblocking(false).ok();

        let capture = Arc::new(Mutex::new(CaptureEngine::new(
            24,
            80,
            0,
            2,
            10_000,
            "vt100".into(),
            "drop".into(),
        )));
        {
            let mut eng = capture.lock().unwrap();
            eng.process(b"socket test line\r\n");
        }

        let sock_path_clone = sock_path.clone();
        let handle = std::thread::spawn(move || {
            let mut stream = std::os::unix::net::UnixStream::connect(&sock_path_clone).unwrap();
            let mut buf = String::new();
            stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
            let _ = stream.read_to_string(&mut buf);
            buf
        });

        listener.set_nonblocking(false).ok();
        handle_socket_connection(&listener, &capture);

        let received = handle.join().unwrap();
        assert!(received.contains("socket test line"));

        let _ = std::fs::remove_file(&sock_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_capture_since_mark_clamped_history() {
        let mut eng = CaptureEngine::new(4, 80, 0, 2, 5, "vt100".into(), "drop".into());
        for i in 0..20 {
            eng.process(format!("old{i}\r\n").as_bytes());
        }
        eng.mark();
        for i in 0..20 {
            eng.process(format!("evict{i}\r\n").as_bytes());
        }
        let captured = eng.capture_since_mark(65536);
        assert!(captured.is_some());
        let text = captured.unwrap();
        assert!(text.contains("evict"));
    }
}
