use crate::config::RedactionConfig;
use std::io::{BufReader, Read, Write};
use std::process::Child;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub(crate) struct PumpedChild {
    pub(crate) child: Child,
    last_output: Arc<Mutex<Instant>>,
    stdout_thread: JoinHandle<String>,
    stderr_thread: JoinHandle<String>,
}

impl PumpedChild {
    pub(crate) fn last_output_age(&self) -> Duration {
        self.last_output
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .elapsed()
    }

    pub(crate) fn finish(self) -> (String, String) {
        let stdout = self.stdout_thread.join().unwrap_or_default();
        let stderr = self.stderr_thread.join().unwrap_or_default();
        (stdout, stderr)
    }
}

pub(crate) fn attach_output_pumps(
    mut child: Child,
    redaction: &RedactionConfig,
    echo_output: bool,
) -> PumpedChild {
    let last_output = Arc::new(Mutex::new(Instant::now()));
    let stdout_thread = spawn_output_reader(
        child.stdout.take(),
        redaction.clone(),
        echo_output,
        Arc::clone(&last_output),
    );
    let stderr_thread = spawn_output_reader(
        child.stderr.take(),
        redaction.clone(),
        echo_output,
        Arc::clone(&last_output),
    );

    PumpedChild {
        child,
        last_output,
        stdout_thread,
        stderr_thread,
    }
}

fn spawn_output_reader<R>(
    pipe: Option<R>,
    redaction: RedactionConfig,
    echo_output: bool,
    last_output: Arc<Mutex<Instant>>,
) -> JoinHandle<String>
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || {
        let mut accumulated = Vec::new();
        if let Some(pipe) = pipe {
            let mut reader = BufReader::new(pipe);
            let mut buf = [0u8; 4096];
            // Buffer for incomplete trailing UTF-8 bytes across read() calls
            let mut utf8_remainder: Vec<u8> = Vec::new();
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if echo_output {
                            // Prepend any leftover bytes from previous chunk
                            let mut full_chunk = std::mem::take(&mut utf8_remainder);
                            full_chunk.extend_from_slice(&buf[..n]);
                            // Find the last valid UTF-8 boundary
                            match std::str::from_utf8(&full_chunk) {
                                Ok(valid) => {
                                    let redacted =
                                        crate::redact::redact_secrets(valid, &redaction);
                                    let _ = std::io::stderr().write_all(redacted.as_bytes());
                                    let _ = std::io::stderr().flush();
                                }
                                Err(e) => {
                                    let valid_up_to = e.valid_up_to();
                                    if valid_up_to > 0 {
                                        // SAFETY: from_utf8 confirmed valid up to this index
                                        let valid =
                                            unsafe { std::str::from_utf8_unchecked(&full_chunk[..valid_up_to]) };
                                        let redacted =
                                            crate::redact::redact_secrets(valid, &redaction);
                                        let _ = std::io::stderr().write_all(redacted.as_bytes());
                                        let _ = std::io::stderr().flush();
                                    }
                                    if e.error_len().is_some() {
                                        // Genuinely invalid byte (not incomplete) — skip it
                                        // and keep the rest for next iteration
                                        let skip = valid_up_to + e.error_len().unwrap();
                                        utf8_remainder = full_chunk[skip..].to_vec();
                                    } else {
                                        // Incomplete trailing bytes — buffer for next read
                                        utf8_remainder = full_chunk[valid_up_to..].to_vec();
                                    }
                                }
                            }
                        }
                        accumulated.extend_from_slice(&buf[..n]);
                        *last_output
                            .lock()
                            .unwrap_or_else(|error| error.into_inner()) = Instant::now();
                    }
                    Err(_) => break,
                }
            }
            // Flush any remaining bytes
            if echo_output && !utf8_remainder.is_empty() {
                let chunk = String::from_utf8_lossy(&utf8_remainder);
                let redacted = crate::redact::redact_secrets(&chunk, &redaction);
                let _ = std::io::stderr().write_all(redacted.as_bytes());
                let _ = std::io::stderr().flush();
            }
        }
        String::from_utf8_lossy(&accumulated).into_owned()
    })
}

#[cfg(test)]
mod tests {
    use super::spawn_output_reader;
    use crate::config::RedactionConfig;
    use std::io::Cursor;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    #[test]
    fn spawn_output_reader_collects_output_and_updates_activity_time() {
        let last_output = Arc::new(Mutex::new(Instant::now() - Duration::from_secs(60)));
        let reader = spawn_output_reader(
            Some(Cursor::new(b"hello world".to_vec())),
            RedactionConfig::default(),
            false,
            Arc::clone(&last_output),
        );

        let output = reader.join().unwrap();

        assert_eq!(output, "hello world");
        assert!(last_output.lock().unwrap().elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn spawn_output_reader_without_pipe_returns_empty_output() {
        let last_output = Arc::new(Mutex::new(Instant::now()));
        let reader = spawn_output_reader::<Cursor<Vec<u8>>>(
            None,
            RedactionConfig::default(),
            false,
            last_output,
        );

        assert_eq!(reader.join().unwrap(), "");
    }
}
