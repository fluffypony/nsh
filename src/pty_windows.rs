//! Windows PTY wrapping via ConPTY (Windows Pseudo Console).
//!
//! Uses CreatePseudoConsole and related Win32 APIs to spawn a child
//! shell with a pseudo-terminal. This enables full terminal capture
//! and PTY wrapping on native Windows (Windows 10 1809+).
//!
//! Fallback: Returns a descriptive error if ConPTY is not available.

#[cfg(windows)]
use std::io::{self, Read, Write};

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, S_OK},
    System::{
        Console::{
            ClosePseudoConsole, CreatePseudoConsole, ResizePseudoConsole, COORD, HPCON,
        },
        Pipes::CreatePipe,
        Threading::{
            CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
            InitializeProcThreadAttributeList, UpdateProcThreadAttribute,
            WaitForSingleObject, EXTENDED_STARTUPINFO_PRESENT, INFINITE,
            PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, STARTUPINFOEXW,
        },
    },
};

pub fn run_wrapped_shell(
    _shell: &str,
    _wrap_config: &crate::shim::ShimWrapConfig,
    _parent_bootstrap: Option<fn()>,
) -> anyhow::Result<()> {
    #[cfg(not(windows))]
    {
        anyhow::bail!(
            "PTY wrapping is not supported on this platform.\n\
             nsh query, history, and tools work without wrapping."
        );
    }

    #[cfg(windows)]
    {
        run_conpty_shell(_shell, _wrap_config, _parent_bootstrap)
    }
}

#[cfg(windows)]
fn run_conpty_shell(
    shell: &str,
    _wrap_config: &crate::shim::ShimWrapConfig,
    _parent_bootstrap: Option<fn()>,
) -> anyhow::Result<()> {
    use std::mem::zeroed;
    use std::ptr::null_mut;

    // Default terminal size
    let size = COORD { X: 80, Y: 24 };

    // Create pipes for ConPTY I/O
    let mut pty_input_read: HANDLE = INVALID_HANDLE_VALUE;
    let mut pty_input_write: HANDLE = INVALID_HANDLE_VALUE;
    let mut pty_output_read: HANDLE = INVALID_HANDLE_VALUE;
    let mut pty_output_write: HANDLE = INVALID_HANDLE_VALUE;

    unsafe {
        if CreatePipe(&mut pty_input_read, &mut pty_input_write, null_mut(), 0) == 0 {
            anyhow::bail!("Failed to create input pipe for ConPTY");
        }
        if CreatePipe(&mut pty_output_read, &mut pty_output_write, null_mut(), 0) == 0 {
            CloseHandle(pty_input_read);
            CloseHandle(pty_input_write);
            anyhow::bail!("Failed to create output pipe for ConPTY");
        }
    }

    // Create the pseudo console
    let mut hpc: HPCON = 0;
    let hr = unsafe { CreatePseudoConsole(size, pty_input_read, pty_output_write, 0, &mut hpc) };
    if hr != S_OK {
        unsafe {
            CloseHandle(pty_input_read);
            CloseHandle(pty_input_write);
            CloseHandle(pty_output_read);
            CloseHandle(pty_output_write);
        }
        anyhow::bail!("CreatePseudoConsole failed (HRESULT: 0x{hr:08x}). Windows 10 1809+ required.");
    }

    // Close the pipe ends that are now owned by the pseudo console
    unsafe {
        CloseHandle(pty_input_read);
        CloseHandle(pty_output_write);
    }

    // Set up proc thread attribute list for the pseudo console
    let mut attr_list_size: usize = 0;
    unsafe {
        InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut attr_list_size);
    }
    let mut attr_list_buf = vec![0u8; attr_list_size];
    let attr_list = attr_list_buf.as_mut_ptr() as *mut _;
    unsafe {
        if InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_list_size) == 0 {
            ClosePseudoConsole(hpc);
            anyhow::bail!("InitializeProcThreadAttributeList failed");
        }
        if UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
            hpc as *mut _,
            std::mem::size_of::<HPCON>(),
            null_mut(),
            null_mut(),
        ) == 0
        {
            DeleteProcThreadAttributeList(attr_list);
            ClosePseudoConsole(hpc);
            anyhow::bail!("UpdateProcThreadAttribute failed");
        }
    }

    // Prepare the startup info
    let mut si: STARTUPINFOEXW = unsafe { zeroed() };
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.lpAttributeList = attr_list;

    // Encode shell path as wide string, quoting to handle paths with spaces
    let quoted_shell = if shell.contains(' ') && !shell.starts_with('"') {
        format!("\"{shell}\"")
    } else {
        shell.to_string()
    };
    let mut cmd_line: Vec<u16> = quoted_shell.encode_utf16().chain(std::iter::once(0)).collect();

    // Create the child process
    let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };
    let created = unsafe {
        CreateProcessW(
            null_mut(),
            cmd_line.as_mut_ptr(),
            null_mut(),
            null_mut(),
            0, // bInheritHandles = FALSE
            EXTENDED_STARTUPINFO_PRESENT,
            null_mut(),
            null_mut(),
            &si.StartupInfo as *const _ as *mut _,
            &mut pi,
        )
    };

    if created == 0 {
        unsafe {
            DeleteProcThreadAttributeList(attr_list);
            ClosePseudoConsole(hpc);
            CloseHandle(pty_input_write);
            CloseHandle(pty_output_read);
        }
        anyhow::bail!("CreateProcessW failed for shell: {shell}");
    }

    // Close the thread handle (we only need the process handle)
    unsafe { CloseHandle(pi.hThread) };

    // Spawn I/O pump threads
    let input_handle = pty_input_write;
    let output_handle = pty_output_read;

    // Output pump: ConPTY output → stdout
    let output_thread = std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut stdout = io::stdout();
        loop {
            let mut bytes_read: u32 = 0;
            let ok = unsafe {
                windows_sys::Win32::Storage::FileSystem::ReadFile(
                    output_handle,
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    &mut bytes_read,
                    null_mut(),
                )
            };
            if ok == 0 || bytes_read == 0 {
                break;
            }
            let _ = stdout.write_all(&buf[..bytes_read as usize]);
            let _ = stdout.flush();
        }
    });

    // Input pump: stdin → ConPTY input
    let input_thread = std::thread::spawn(move || {
        let mut buf = [0u8; 1024];
        let stdin = io::stdin();
        let mut stdin_lock = stdin.lock();
        loop {
            match stdin_lock.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut written: u32 = 0;
                    let ok = unsafe {
                        windows_sys::Win32::Storage::FileSystem::WriteFile(
                            input_handle,
                            buf.as_ptr(),
                            n as u32,
                            &mut written,
                            null_mut(),
                        )
                    };
                    if ok == 0 {
                        break;
                    }
                }
            }
        }
    });

    // Wait for child process to exit
    unsafe {
        WaitForSingleObject(pi.hProcess, INFINITE);
    }

    // Cleanup: close pseudo console first (on a separate thread to avoid deadlock
    // with the output pump — ClosePseudoConsole can block while output is being drained)
    let hpc_handle = hpc;
    let close_thread = std::thread::spawn(move || unsafe {
        ClosePseudoConsole(hpc_handle);
    });

    let _ = output_thread.join();
    let _ = input_thread.join();
    let _ = close_thread.join();

    // Get exit code
    let mut exit_code: u32 = 0;
    unsafe {
        GetExitCodeProcess(pi.hProcess, &mut exit_code);
        CloseHandle(pi.hProcess);
        DeleteProcThreadAttributeList(attr_list);
        CloseHandle(pty_input_write);
        CloseHandle(pty_output_read);
    }

    std::process::exit(exit_code as i32);
}

pub fn exec_execvp(cmd: &str, args: &[&str]) -> std::io::Error {
    exec::execvp(cmd, args)
}

pub mod exec {
    pub fn execvp(_cmd: &str, _args: &[&str]) -> std::io::Error {
        #[cfg(windows)]
        {
            use std::process::Command;
            let status = Command::new(_cmd).args(_args).status();
            match status {
                Ok(s) => std::process::exit(s.code().unwrap_or(1)),
                Err(e) => e,
            }
        }
        #[cfg(not(windows))]
        {
            std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "exec-replacement is not available on this platform",
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(windows))]
    fn run_wrapped_shell_returns_error_on_non_windows() {
        let err = run_wrapped_shell("pwsh", &crate::shim::ShimWrapConfig::default(), None)
            .expect_err("run_wrapped_shell should fail on non-windows");
        let text = err.to_string();
        assert!(text.contains("not supported"));
    }

    #[test]
    #[cfg(not(windows))]
    fn exec_execvp_reports_unsupported_kind() {
        let err = exec_execvp("cmd", &["/c", "echo hello"]);
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }
}
