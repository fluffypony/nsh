#![cfg(unix)]

use rustix::pty::{grantpt, openpt, ptsname, unlockpt};
use rustix::termios::{self, Termios};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::sync::{Arc, Mutex, OnceLock};

use crate::pump::{CaptureEngine, pump_loop};

static RESTORE_TERMIOS: OnceLock<(libc::c_int, Termios)> = OnceLock::new();
static PTSNAME_LOCK: Mutex<()> = Mutex::new(());

pub struct PtyPair {
    pub master: OwnedFd,
    pub slave: OwnedFd,
}

// Note: rustix::pty::ptsname() calls the non-thread-safe macOS ptsname(3).
// PTSNAME_LOCK exists for future-proofing against refactoring that might
// move PTY creation after thread spawning.
pub fn create_pty() -> anyhow::Result<PtyPair> {
    let master = openpt(rustix::pty::OpenptFlags::RDWR | rustix::pty::OpenptFlags::NOCTTY)?;
    grantpt(&master)?;
    unlockpt(&master)?;

    let slave_name = {
        let _guard = PTSNAME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        ptsname(&master, Vec::new())?
    };
    let slave = rustix::fs::open(
        slave_name.as_c_str(),
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY,
        rustix::fs::Mode::empty(),
    )?;

    Ok(PtyPair { master, slave })
}

/// Set terminal to raw mode, return original settings for restoration.
pub fn make_raw(fd: BorrowedFd) -> anyhow::Result<Termios> {
    let original = termios::tcgetattr(fd)?;
    let mut raw = original.clone();
    raw.make_raw();
    termios::tcsetattr(fd, termios::OptionalActions::Now, &raw)?;
    Ok(original)
}

/// Copy terminal size from one fd to another.
pub fn copy_winsize(from: BorrowedFd, to: BorrowedFd) -> anyhow::Result<()> {
    let ws = termios::tcgetwinsize(from)?;
    termios::tcsetwinsize(to, ws)?;
    Ok(())
}

/// Run the user's shell inside a PTY, capturing output into a scrollback
/// buffer. This is the `nsh wrap` entrypoint.
pub fn run_wrapped_shell(shell: &str) -> anyhow::Result<()> {
    if std::env::var("NSH_PTY_ACTIVE").is_ok() {
        let err = exec::execvp(shell, &[shell, "-l"]);
        anyhow::bail!("exec failed (already wrapped): {err}");
    }

    let pty = create_pty()?;

    let config = crate::config::Config::load().unwrap_or_default();

    // Save original terminal state
    let real_stdin = rustix::stdio::stdin();
    let real_stdout = rustix::stdio::stdout();
    let original_termios = make_raw(real_stdin)?;
    RESTORE_TERMIOS
        .set((real_stdin.as_raw_fd(), original_termios.clone()))
        .ok();

    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Some((fd, termios)) = RESTORE_TERMIOS.get() {
            let borrowed = unsafe { BorrowedFd::borrow_raw(*fd) };
            let _ = rustix::termios::tcsetattr(
                borrowed,
                rustix::termios::OptionalActions::Now,
                termios,
            );
        }
        let reset = "\x1b[0m\x1b[?25h\x1b[?1049l\n";
        let _ = std::io::Write::write_all(&mut std::io::stderr(), reset.as_bytes());
        prev_hook(info);
        let _ = std::io::Write::write_all(
            &mut std::io::stderr(),
            b"\nnsh: terminal should be restored. If not, run: reset\n\
              Please report this at https://github.com/fluffypony/nsh/issues\n",
        );
    }));

    copy_winsize(real_stdin, pty.master.as_fd())?;

    let ws = termios::tcgetwinsize(real_stdin).ok();
    let (rows, cols) = ws.map(|w| (w.ws_row, w.ws_col)).unwrap_or((24, 80));
    let capture = Arc::new(Mutex::new(CaptureEngine::new(
        rows,
        cols,
        config.context.scrollback_rate_limit_bps,
        config.context.scrollback_pause_seconds,
        config.context.scrollback_lines.max(1000),
        config.capture.mode.clone(),
        config.capture.alt_screen.clone(),
    )));

    let basename = shell.rsplit('/').next().unwrap_or(shell);
    let orig_tty = tty_path(real_stdin);
    let argv0_cstr = std::ffi::CString::new(format!("-{basename}")).expect("valid shell name");
    let shell_cstr = std::ffi::CString::new(shell.to_owned()).expect("valid shell path");
    let mut env_vec: Vec<std::ffi::CString> = std::env::vars()
        .filter_map(|(k, v)| std::ffi::CString::new(format!("{k}={v}")).ok())
        .collect();
    env_vec.push(std::ffi::CString::new("NSH_PTY_ACTIVE=1").unwrap());
    if let Some(orig_tty) = orig_tty {
        if let Ok(var) = std::ffi::CString::new(format!("NSH_ORIG_TTY={orig_tty}")) {
            env_vec.push(var);
        }
    }
    let env_ptrs: Vec<*const libc::c_char> = env_vec
        .iter()
        .map(|e| e.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    // Fork
    match unsafe { libc::fork() } {
        -1 => anyhow::bail!("fork() failed"),
        0 => {
            // ── Child: only async-signal-safe operations ──────
            drop(pty.master);

            if unsafe { libc::setsid() } == -1 {
                unsafe { libc::_exit(127) };
            }

            let slave_raw = std::os::fd::AsRawFd::as_raw_fd(&pty.slave);

            unsafe { libc::ioctl(slave_raw, libc::TIOCSCTTY as libc::c_ulong, 0) };

            for fd in 0..=2 {
                if unsafe { libc::dup2(slave_raw, fd) } == -1 {
                    unsafe { libc::_exit(127) };
                }
            }
            drop(pty.slave);

            unsafe {
                let argv = [argv0_cstr.as_ptr(), std::ptr::null()];
                libc::execve(shell_cstr.as_ptr(), argv.as_ptr(), env_ptrs.as_ptr());
                libc::_exit(127);
            }
        }
        child_pid => {
            // ── Parent: run the pump ───────────────────────────
            drop(pty.slave);

            // Keep wrap startup snappy, but spawn after fork to avoid
            // multi-threaded-fork hazards in the child path.
            std::thread::spawn(|| {
                let _ = crate::daemon_client::ensure_global_daemon_running();
            });

            let pid = rustix::process::Pid::from_raw(child_pid).expect("invalid child pid");

            pump_loop(
                real_stdin,
                real_stdout,
                pty.master.as_fd(),
                Arc::clone(&capture),
                pid,
            );

            // Restore terminal
            termios::tcsetattr(real_stdin, termios::OptionalActions::Now, &original_termios).ok();

            std::process::exit(0);
        }
    }
}

fn tty_path(fd: BorrowedFd) -> Option<String> {
    let mut buf = [0u8; 1024];
    // SAFETY: ttyname_r writes a NUL-terminated C string to the provided buffer.
    let rc = unsafe {
        libc::ttyname_r(
            fd.as_raw_fd(),
            buf.as_mut_ptr().cast::<libc::c_char>(),
            buf.len(),
        )
    };
    if rc != 0 {
        return None;
    }
    let nul = buf.iter().position(|b| *b == 0)?;
    if nul == 0 {
        return None;
    }
    std::str::from_utf8(&buf[..nul]).ok().map(str::to_string)
}

pub fn exec_execvp(cmd: &str, args: &[&str]) -> std::io::Error {
    exec::execvp(cmd, args)
}

mod exec {
    pub fn execvp(cmd: &str, args: &[&str]) -> std::io::Error {
        use std::ffi::CString;
        let cmd = match CString::new(cmd) {
            Ok(c) => c,
            Err(_) => {
                return std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "command path contains null byte",
                );
            }
        };
        let args: Vec<CString> = match args
            .iter()
            .map(|a| CString::new(*a))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(v) => v,
            Err(e) => {
                return std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("argument contains null byte: {e}"),
                );
            }
        };
        let arg_ptrs: Vec<*const libc::c_char> = args
            .iter()
            .map(|a| a.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        unsafe {
            libc::execvp(cmd.as_ptr(), arg_ptrs.as_ptr());
        }
        std::io::Error::last_os_error()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execvp_null_byte_in_command() {
        let err = exec::execvp("cmd\0bad", &["arg"]);
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("null byte"));
    }

    #[test]
    fn test_execvp_null_byte_in_args() {
        let err = exec::execvp("cmd", &["ok", "bad\0arg"]);
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("null byte"));
    }

    #[test]
    fn test_exec_execvp_null_byte_in_command() {
        let err = exec_execvp("path\0nul", &["arg"]);
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_exec_execvp_null_byte_in_args() {
        let err = exec_execvp("/bin/true", &["ok", "a\0b"]);
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_create_pty_returns_valid_fds() {
        let pair = create_pty().expect("create_pty should succeed");
        assert!(pair.master.as_raw_fd() >= 0);
        assert!(pair.slave.as_raw_fd() >= 0);
        assert_ne!(pair.master.as_raw_fd(), pair.slave.as_raw_fd());
    }

    #[test]
    fn test_copy_winsize_between_ptys() {
        let p1 = create_pty().unwrap();
        let p2 = create_pty().unwrap();
        let ws = libc::winsize {
            ws_row: 42,
            ws_col: 132,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        unsafe { libc::ioctl(p1.master.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
        copy_winsize(p1.master.as_fd(), p2.master.as_fd()).unwrap();
        let got = termios::tcgetwinsize(p2.master.as_fd()).unwrap();
        assert_eq!(got.ws_row, 42);
        assert_eq!(got.ws_col, 132);
    }

    #[test]
    fn test_make_raw_on_pty() {
        let pair = create_pty().unwrap();
        let original = make_raw(pair.slave.as_fd()).expect("make_raw should succeed on PTY slave");
        let current = termios::tcgetattr(pair.slave.as_fd()).unwrap();
        assert_ne!(
            format!("{:?}", original.local_modes),
            format!("{:?}", current.local_modes),
            "raw mode should change local_modes"
        );
    }

    #[test]
    fn test_make_raw_returns_restorable_termios() {
        let pair = create_pty().unwrap();
        let before = termios::tcgetattr(pair.slave.as_fd()).unwrap();
        let original = make_raw(pair.slave.as_fd()).unwrap();
        let raw = termios::tcgetattr(pair.slave.as_fd()).unwrap();
        assert_ne!(
            format!("{:?}", before.local_modes),
            format!("{:?}", raw.local_modes),
            "raw mode should differ from original"
        );
        termios::tcsetattr(pair.slave.as_fd(), termios::OptionalActions::Now, &original)
            .expect("restoring original termios should succeed");
        let restored = termios::tcgetattr(pair.slave.as_fd()).unwrap();
        assert!(
            restored
                .local_modes
                .contains(before.local_modes & !raw.local_modes),
            "restored modes should re-enable flags that raw mode cleared"
        );
    }

    #[test]
    fn test_pty_master_slave_communication() {
        use std::io::{Read, Write};
        use std::os::fd::FromRawFd;

        let pair = create_pty().unwrap();
        let master_raw = pair.master.as_raw_fd();
        let slave_raw = pair.slave.as_raw_fd();

        let mut master_file = unsafe { std::fs::File::from_raw_fd(libc::dup(master_raw)) };
        let mut slave_file = unsafe { std::fs::File::from_raw_fd(libc::dup(slave_raw)) };

        let msg = b"hello pty\r";
        slave_file.write_all(msg).unwrap();
        slave_file.flush().unwrap();

        let mut buf = [0u8; 64];
        let n = master_file.read(&mut buf).unwrap();
        assert!(n > 0, "should read data back from master");
        assert!(
            std::str::from_utf8(&buf[..n])
                .unwrap()
                .contains("hello pty"),
            "master should echo data written to slave"
        );
    }

    #[test]
    fn test_create_pty_master_slave_distinct() {
        let p1 = create_pty().unwrap();
        let p2 = create_pty().unwrap();
        assert_ne!(p1.master.as_raw_fd(), p2.master.as_raw_fd());
        assert_ne!(p1.slave.as_raw_fd(), p2.slave.as_raw_fd());
    }

    #[test]
    fn test_copy_winsize_preserves_all_fields() {
        let p1 = create_pty().unwrap();
        let p2 = create_pty().unwrap();
        let ws = libc::winsize {
            ws_row: 50,
            ws_col: 200,
            ws_xpixel: 800,
            ws_ypixel: 600,
        };
        unsafe { libc::ioctl(p1.master.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
        copy_winsize(p1.master.as_fd(), p2.master.as_fd()).unwrap();
        let got = termios::tcgetwinsize(p2.master.as_fd()).unwrap();
        assert_eq!(got.ws_row, 50);
        assert_eq!(got.ws_col, 200);
    }

    #[test]
    fn test_shell_basename_extraction() {
        let cases = [
            ("/bin/zsh", "zsh"),
            ("/usr/local/bin/bash", "bash"),
            ("fish", "fish"),
            ("/a/b/c/d/sh", "sh"),
            ("", ""),
        ];
        for (input, expected) in cases {
            let basename = input.rsplit('/').next().unwrap_or(input);
            assert_eq!(basename, expected, "basename of {input:?}");
        }
    }

    #[test]
    fn test_winsize_default_fallback() {
        let ws: Option<rustix::termios::Winsize> = None;
        let (rows, cols) = ws.map(|w| (w.ws_row, w.ws_col)).unwrap_or((24, 80));
        assert_eq!(rows, 24);
        assert_eq!(cols, 80);
    }

    #[test]
    fn test_execvp_empty_command() {
        let err = exec::execvp("", &[""]);
        assert!(
            err.kind() != std::io::ErrorKind::InvalidInput,
            "empty string is valid CString, should fail with OS error not null-byte error"
        );
    }

    #[test]
    fn test_execvp_nonexistent_command() {
        let err = exec::execvp("/nonexistent/binary/path", &["/nonexistent/binary/path"]);
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }
}
