use rustix::pty::{grantpt, openpt, ptsname, unlockpt};
use rustix::termios::{self, Termios};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::Mutex;

use crate::pump::{pump_loop, ScrollbackBuffer};

pub struct PtyPair {
    pub master: OwnedFd,
    pub slave: OwnedFd,
}

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
    let pty = create_pty()?;

    // Save original terminal state
    let real_stdin = rustix::stdio::stdin();
    let real_stdout = rustix::stdio::stdout();
    let original_termios = make_raw(real_stdin)?;
    copy_winsize(real_stdin, pty.master.as_fd())?;

    let scrollback_capacity = 1_048_576; // 1 MB default
    let scrollback = Mutex::new(ScrollbackBuffer::new(scrollback_capacity));

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

            // Exec the shell
            let err = exec::execvp(
                shell,
                &[shell, "-l"],
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
                &scrollback,
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

// Note: `exec` crate provides execvp. If unavailable, use libc::execvp
// directly. For the initial build, this module compiles with a stub — the
// full PTY wrapping can be iterated on.
mod exec {
    pub fn execvp(_cmd: &str, _args: &[&str]) -> std::io::Error {
        use std::ffi::CString;
        let cmd = CString::new(_cmd).unwrap();
        let args: Vec<CString> =
            _args.iter().map(|a| CString::new(*a).unwrap()).collect();
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
