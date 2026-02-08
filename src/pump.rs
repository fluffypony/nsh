use std::os::fd::BorrowedFd;
use std::sync::Mutex;

/// Circular scrollback buffer that captures PTY output.
pub struct ScrollbackBuffer {
    data: Vec<u8>,
    capacity: usize,
    write_pos: usize,
    data_size: usize,
}

impl ScrollbackBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: vec![0u8; capacity],
            capacity,
            write_pos: 0,
            data_size: 0,
        }
    }

    pub fn append(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.data[self.write_pos] = b;
            self.write_pos = (self.write_pos + 1) % self.capacity;
        }
        self.data_size =
            (self.data_size + bytes.len()).min(self.capacity);
    }

    /// Extract last `max_lines` lines, ANSI-stripped.
    pub fn get_lines(&self, max_lines: usize) -> String {
        let raw = self.linearize();
        let stripped = crate::ansi::strip(&raw);
        let lines: Vec<&str> = stripped.lines().collect();
        let start = lines.len().saturating_sub(max_lines);
        lines[start..].join("\n")
    }

    fn linearize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.data_size);
        if self.data_size < self.capacity {
            out.extend_from_slice(&self.data[..self.data_size]);
        } else {
            // Buffer has wrapped: read from write_pos to end, then
            // start to write_pos.
            out.extend_from_slice(&self.data[self.write_pos..]);
            out.extend_from_slice(&self.data[..self.write_pos]);
        }
        out
    }
}

/// Write all bytes to an fd, retrying on partial writes.
fn write_all(fd: &BorrowedFd, mut data: &[u8]) -> std::io::Result<()> {
    while !data.is_empty() {
        match rustix::io::write(fd, data) {
            Ok(n) => data = &data[n..],
            Err(e) => {
                return Err(std::io::Error::from_raw_os_error(
                    e.raw_os_error(),
                ))
            }
        }
    }
    Ok(())
}

/// Check whether a child process has exited (non-blocking).
fn child_exited(pid: rustix::process::Pid) -> bool {
    match rustix::process::waitpid(
        Some(pid),
        rustix::process::WaitOptions::NOHANG,
    ) {
        Ok(Some(_status)) => true,  // child exited
        Ok(None) => false,          // still running
        Err(_) => true,             // error (e.g. ECHILD) — treat as exited
    }
}

/// Main pump loop — runs in the parent process after fork.
/// Forwards stdin → PTY master, PTY master → stdout,
/// and captures output into the scrollback buffer.
pub fn pump_loop(
    real_stdin: BorrowedFd,
    real_stdout: BorrowedFd,
    pty_master: BorrowedFd,
    scrollback: &Mutex<ScrollbackBuffer>,
    child_pid: rustix::process::Pid,
) {
    use rustix::event::{poll, PollFd, PollFlags, Timespec};

    // Set up signal forwarding
    use std::os::fd::AsRawFd;
    let stdin_raw = real_stdin.as_raw_fd();
    let pty_master_raw = pty_master.as_raw_fd();
    setup_signal_forwarding(child_pid, stdin_raw, pty_master_raw);

    // Flush scrollback to file periodically so `nsh query` can read it
    let session_id = std::env::var("NSH_SESSION_ID")
        .unwrap_or_else(|_| "default".into());
    let scrollback_path = crate::config::Config::nsh_dir()
        .join(format!("scrollback_{session_id}"));

    let mut buf = [0u8; 8192];
    let mut last_flush = std::time::Instant::now();

    loop {
        let mut fds = [
            PollFd::new(&real_stdin, PollFlags::IN),
            PollFd::new(&pty_master, PollFlags::IN),
        ];

        let timeout = Timespec { tv_sec: 0, tv_nsec: 100_000_000 };
        match poll(&mut fds, Some(&timeout)) {
            Ok(0) => {
                if child_exited(child_pid) {
                    break;
                }
                continue;
            }
            Ok(_) => {}
            Err(_) => continue, // EINTR from signal
        }

        // stdin → PTY master (user typing)
        if fds[0].revents().contains(PollFlags::IN) {
            match rustix::io::read(&real_stdin, &mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let _ = write_all(&pty_master, &buf[..n]);
                }
                Err(_) => break,
            }
        }

        // PTY master → stdout (shell output) + scrollback capture
        if fds[1].revents().contains(PollFlags::IN) {
            match rustix::io::read(&pty_master, &mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let _ = write_all(&real_stdout, &buf[..n]);
                    if let Ok(mut sb) = scrollback.lock() {
                        sb.append(&buf[..n]);
                        if last_flush.elapsed()
                            >= std::time::Duration::from_secs(1)
                        {
                            let _ = std::fs::write(
                                &scrollback_path,
                                sb.linearize(),
                            );
                            last_flush = std::time::Instant::now();
                        }
                    }
                }
                Err(_) => break,
            }
        }

        // HUP on PTY means shell exited
        if fds[1].revents().contains(PollFlags::HUP) {
            break;
        }
    }

    // Clean up scrollback file
    let _ = std::fs::remove_file(&scrollback_path);
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
                if libc::ioctl(stdin_fd, libc::TIOCGWINSZ, &mut ws)
                    == 0
                {
                    libc::ioctl(
                        pty_master_fd,
                        libc::TIOCSWINSZ,
                        &ws,
                    );
                }
                libc::kill(raw_pid, libc::SIGWINCH);
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrollback_buffer_append_and_get_lines() {
        let mut sb = ScrollbackBuffer::new(1024);
        sb.append(b"line one\nline two\nline three\n");

        let lines = sb.get_lines(10);
        assert!(lines.contains("line one"));
        assert!(lines.contains("line two"));
        assert!(lines.contains("line three"));
    }

    #[test]
    fn test_scrollback_buffer_wrap_around() {
        let mut sb = ScrollbackBuffer::new(16);
        sb.append(b"AAAAAAAAAAAAAAAA");
        assert_eq!(sb.data_size, 16);

        sb.append(b"BBBB");
        assert_eq!(sb.data_size, 16);

        let raw = sb.linearize();
        let s = String::from_utf8_lossy(&raw);
        assert!(
            s.starts_with("AAAAAAAAAAAA"),
            "should start with remaining A's"
        );
        assert!(
            s.ends_with("BBBB"),
            "should end with B's"
        );
        assert_eq!(raw.len(), 16);
    }

    #[test]
    fn test_scrollback_buffer_empty() {
        let sb = ScrollbackBuffer::new(1024);
        let lines = sb.get_lines(10);
        assert!(lines.is_empty());
    }
}
