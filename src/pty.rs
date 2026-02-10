use rustix::pty::{grantpt, openpt, ptsname, unlockpt};
use rustix::termios::{self, Termios};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::sync::{Mutex, OnceLock};

use crate::pump::{pump_loop, CaptureEngine};

static RESTORE_TERMIOS: OnceLock<(libc::c_int, Termios)> = OnceLock::new();

pub struct PtyPair {
    pub master: OwnedFd,
    pub slave: OwnedFd,
}

// Note: rustix::pty::ptsname() calls the non-thread-safe macOS ptsname(3).
// Currently safe because PTY creation happens before fork(). If PTY creation
// ever moves to a threaded context, a Mutex around ptsname would be needed.
pub fn create_pty() -> anyhow::Result<PtyPair> {
    let master = openpt(
        rustix::pty::OpenptFlags::RDWR
            | rustix::pty::OpenptFlags::NOCTTY,
    )?;
    grantpt(&master)?;
    unlockpt(&master)?;

    let slave_name = ptsname(&master, Vec::new())?;
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
pub fn copy_winsize(
    from: BorrowedFd,
    to: BorrowedFd,
) -> anyhow::Result<()> {
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
    RESTORE_TERMIOS.set((real_stdin.as_raw_fd(), original_termios.clone())).ok();

    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Some((fd, termios)) = RESTORE_TERMIOS.get() {
            let borrowed = unsafe { BorrowedFd::borrow_raw(*fd) };
            let _ = rustix::termios::tcsetattr(borrowed, rustix::termios::OptionalActions::Now, termios);
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
    let capture = Mutex::new(CaptureEngine::new(
        rows,
        cols,
        config.context.scrollback_rate_limit_bps,
        config.context.scrollback_pause_seconds,
        config.context.scrollback_lines.max(1000),
        config.capture.mode.clone(),
        config.capture.alt_screen.clone(),
    ));

    // Fork
    match unsafe { libc::fork() } {
        -1 => anyhow::bail!("fork() failed"),
        0 => {
            // ── Child: exec the shell ──────────────────────────
            drop(pty.master);

            if unsafe { libc::setsid() } == -1 {
                eprintln!("nsh: setsid failed");
                unsafe { libc::_exit(127) };
            }

            let slave_raw =
                std::os::fd::AsRawFd::as_raw_fd(&pty.slave);

            if unsafe {
                libc::ioctl(
                    slave_raw,
                    libc::TIOCSCTTY as libc::c_ulong,
                    0,
                )
            } == -1
            {
                eprintln!("nsh: TIOCSCTTY failed");
            }

            for fd in 0..=2 {
                if unsafe { libc::dup2(slave_raw, fd) } == -1 {
                    eprintln!("nsh: dup2({fd}) failed");
                    unsafe { libc::_exit(127) };
                }
            }
            drop(pty.slave);

            unsafe {
                let key = b"NSH_PTY_ACTIVE\0";
                let val = b"1\0";
                libc::setenv(
                    key.as_ptr() as *const libc::c_char,
                    val.as_ptr() as *const libc::c_char,
                    1,
                );
            }

            // Login shell convention: prepend '-' to basename in argv[0]
            let basename = shell.rsplit('/').next().unwrap_or(shell);
            let argv0 = format!("-{basename}");
            let err = exec::execvp(
                shell,
                &[&argv0],
            );
            eprintln!("nsh: exec failed: {err}");
            unsafe { libc::_exit(127) };
        }
        child_pid => {
            // ── Parent: run the pump ───────────────────────────
            drop(pty.slave);

            let pid = rustix::process::Pid::from_raw(child_pid)
                .expect("invalid child pid");

            pump_loop(
                real_stdin,
                real_stdout,
                pty.master.as_fd(),
                &capture,
                pid,
            );

            // Restore terminal
            termios::tcsetattr(
                real_stdin,
                termios::OptionalActions::Now,
                &original_termios,
            )
            .ok();

            std::process::exit(0);
        }
    }
}

mod exec {
    pub fn execvp(cmd: &str, args: &[&str]) -> std::io::Error {
        use std::ffi::CString;
        let cmd = match CString::new(cmd) {
            Ok(c) => c,
            Err(_) => return std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "command path contains null byte",
            ),
        };
        let args: Vec<CString> = args.iter().filter_map(|a| CString::new(*a).ok()).collect();
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
