use std::os::fd::BorrowedFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct CaptureEngine {
    parser: vt100::Parser,
    in_alternate_screen: bool,
    accumulated_lines: Vec<String>,
    prev_screen_contents: String,
    max_accumulated_lines: usize,
    rate_window_start: Instant,
    rate_bytes: usize,
    rate_limit_bps: usize,
    paused_until: Option<Instant>,
    pause_seconds: u64,
}

impl CaptureEngine {
    pub fn new(
        rows: u16,
        cols: u16,
        rate_limit_bps: usize,
        pause_seconds: u64,
        max_accumulated_lines: usize,
    ) -> Self {
        Self {
            parser: vt100::Parser::new(rows, cols, 1000),
            in_alternate_screen: false,
            accumulated_lines: Vec::new(),
            prev_screen_contents: String::new(),
            max_accumulated_lines,
            rate_window_start: Instant::now(),
            rate_bytes: 0,
            rate_limit_bps,
            paused_until: None,
            pause_seconds,
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
            self.accumulated_lines
                .push("[nsh: output capture suppressed (high output rate)]".into());
            return;
        }

        let sanitized = sanitize_input(bytes);
        self.parser.process(&sanitized);

        let now_alt = self.parser.screen().alternate_screen();
        if now_alt {
            self.in_alternate_screen = true;
            return;
        }
        if self.in_alternate_screen && !now_alt {
            self.in_alternate_screen = false;
            self.prev_screen_contents = self.parser.screen().contents();
            return;
        }

        let current = self.parser.screen().contents();
        if current != self.prev_screen_contents {
            let prev_lines: Vec<&str> = self.prev_screen_contents.lines().collect();
            let curr_lines: Vec<&str> = current.lines().collect();

            if curr_lines.len() >= prev_lines.len() && !prev_lines.is_empty() {
                let mut scrolled_off = 0;
                for (i, prev_line) in prev_lines.iter().enumerate() {
                    if i < curr_lines.len() && curr_lines[i] != *prev_line {
                        break;
                    }
                    if i >= curr_lines.len() {
                        scrolled_off = prev_lines.len() - i;
                        break;
                    }
                }

                if scrolled_off == 0 && curr_lines.len() > prev_lines.len() {
                    for line in &curr_lines[prev_lines.len()..] {
                        if !line.trim().is_empty() {
                            self.accumulated_lines.push(line.to_string());
                        }
                    }
                }
            } else if prev_lines.len() > curr_lines.len() {
                for line in &prev_lines[..prev_lines.len() - curr_lines.len()] {
                    if !line.trim().is_empty() {
                        self.accumulated_lines.push(line.to_string());
                    }
                }
            }

            if self.accumulated_lines.len() > self.max_accumulated_lines {
                let excess = self.accumulated_lines.len() - self.max_accumulated_lines;
                self.accumulated_lines.drain(..excess);
            }

            self.prev_screen_contents = current;
        }
    }

    pub fn get_lines(&self, max_lines: usize) -> String {
        let screen_text = self.parser.screen().contents();
        let mut all_lines: Vec<&str> = self
            .accumulated_lines
            .iter()
            .map(|s| s.as_str())
            .collect();
        for line in screen_text.lines() {
            all_lines.push(line);
        }

        let mut combined = all_lines.join("\n");
        combined = combined.replace("\r\n", "\n").replace('\r', "");
        combined = combined.replace("\x1b[200~", "").replace("\x1b[201~", "");

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

static WINCH_PENDING: AtomicBool = AtomicBool::new(false);

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
    setup_signal_forwarding(child_pid, stdin_raw, pty_master_raw);

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

    let scrollback_path = nsh_dir.join(format!("scrollback_{session_id}"));
    let redact_active_path = nsh_dir.join(format!("redact_active_{session_id}"));

    let mut buf = [0u8; 8192];
    let mut last_activity = Instant::now();
    let mut last_flush = Instant::now();

    loop {
        if WINCH_PENDING.swap(false, Ordering::Relaxed) {
            let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
            if unsafe { libc::ioctl(stdin_raw, libc::TIOCGWINSZ, &mut ws) } == 0 {
                if let Ok(mut eng) = capture.lock() {
                    eng.set_size(ws.ws_row, ws.ws_col);
                }
            }
        }

        let idle = last_activity.elapsed() > Duration::from_secs(5);
        let timeout_ns = if idle { 1_000_000_000 } else { 10_000_000 };

        let has_listener = listener.is_some();
        if has_listener {
            let listener_fd = listener.as_ref().unwrap();
            let mut fds = [
                PollFd::new(&real_stdin, PollFlags::IN),
                PollFd::new(&pty_master, PollFlags::IN),
                PollFd::from_borrowed_fd(
                    unsafe {
                        BorrowedFd::borrow_raw(
                            std::os::fd::AsRawFd::as_raw_fd(listener_fd),
                        )
                    },
                    PollFlags::IN,
                ),
            ];
            let timeout = Timespec {
                tv_sec: timeout_ns / 1_000_000_000,
                tv_nsec: timeout_ns % 1_000_000_000,
            };
            match poll(&mut fds, Some(&timeout)) {
                Ok(0) => {
                    if child_exited(child_pid) {
                        break;
                    }
                    continue;
                }
                Ok(_) => {
                    if handle_io(
                        &fds[0], &fds[1], &real_stdin, &real_stdout, &pty_master,
                        &mut buf, capture, &mut last_activity, &mut last_flush,
                        &scrollback_path, &redact_active_path,
                    ) {
                        break;
                    }
                    if fds[2].revents().contains(PollFlags::IN) {
                        handle_socket_connection(listener_fd, capture);
                    }
                }
                Err(e) => {
                    if e == rustix::io::Errno::INTR {
                        continue;
                    }
                    continue;
                }
            }
        } else {
            let mut fds = [
                PollFd::new(&real_stdin, PollFlags::IN),
                PollFd::new(&pty_master, PollFlags::IN),
            ];
            let timeout = Timespec {
                tv_sec: timeout_ns / 1_000_000_000,
                tv_nsec: timeout_ns % 1_000_000_000,
            };
            match poll(&mut fds, Some(&timeout)) {
                Ok(0) => {
                    if child_exited(child_pid) {
                        break;
                    }
                    continue;
                }
                Ok(_) => {
                    if handle_io(
                        &fds[0], &fds[1], &real_stdin, &real_stdout, &pty_master,
                        &mut buf, capture, &mut last_activity, &mut last_flush,
                        &scrollback_path, &redact_active_path,
                    ) {
                        break;
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
    }

    let _ = std::fs::remove_file(&socket_path);
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
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .ok();
        if let Ok(eng) = capture.lock() {
            let text = eng.get_lines(1000);
            let _ = stream.write_all(text.as_bytes());
        }
    }
}

fn setup_signal_forwarding(
    child_pid: rustix::process::Pid,
    stdin_fd: libc::c_int,
    pty_master_fd: libc::c_int,
) {
    let raw_pid = child_pid.as_raw_nonzero().get();

    for sig in [
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGHUP,
    ] {
        unsafe {
            let _ = signal_hook::low_level::register(sig, move || {
                libc::kill(raw_pid, sig);
            });
        }
    }

    unsafe {
        let _ = signal_hook::low_level::register(
            signal_hook::consts::SIGWINCH,
            move || {
                let mut ws: libc::winsize = std::mem::zeroed();
                if libc::ioctl(stdin_fd, libc::TIOCGWINSZ, &mut ws) == 0 {
                    libc::ioctl(pty_master_fd, libc::TIOCSWINSZ, &ws);
                }
                libc::kill(raw_pid, libc::SIGWINCH);
                WINCH_PENDING.store(true, Ordering::Relaxed);
            },
        );
    }

    unsafe {
        let _ = signal_hook::low_level::register(
            signal_hook::consts::SIGCONT,
            move || {
                let mut ws: libc::winsize = std::mem::zeroed();
                if libc::ioctl(stdin_fd, libc::TIOCGWINSZ, &mut ws) == 0 {
                    libc::ioctl(pty_master_fd, libc::TIOCSWINSZ, &ws);
                }
                libc::kill(raw_pid, libc::SIGCONT);
            },
        );
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
        let eng = CaptureEngine::new(24, 80, 0, 2, 10_000);
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
    fn test_capture_engine_alt_screen_detection() {
        let mut eng = CaptureEngine::new(24, 80, 0, 2, 10_000);
        eng.process(b"normal text\r\n");
        eng.process(b"\x1b[?1049h");
        assert!(eng.in_alternate_screen);
        eng.process(b"alt screen content\r\n");
        eng.process(b"\x1b[?1049l");
        assert!(!eng.in_alternate_screen);
    }
}
