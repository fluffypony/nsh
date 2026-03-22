use serde::{Deserialize, Serialize};

/// ALPN identifier for the nsh remote protocol.
pub const ALPN: &[u8] = b"nsh/remote/0";

/// Messages sent from the mobile app to the daemon over QUIC.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RemoteRequest {
    ListSessions,
    Attach { session_id: String },
    Input { bytes: Vec<u8> },
    Resize { cols: u16, rows: u16 },
    Detach,
    /// Warm reconnect: resume from a known sequence number.
    Resume { session_id: String, last_seq: u64 },
    /// Execute a natural-language query from the mobile app.
    Query {
        session_id: String,
        query: String,
        #[serde(default)]
        think: bool,
        #[serde(default)]
        private: bool,
    },
}

/// Messages sent from the daemon to the mobile app over QUIC.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RemoteResponse {
    SessionList {
        sessions: Vec<RemoteSessionInfo>,
    },
    AttachOk {
        initial_screen: Vec<u8>,
    },
    TerminalData {
        seq: u64,
        bytes: Vec<u8>,
    },
    SessionUpdate {
        event: SessionEvent,
    },
    Detached,
    Error {
        message: String,
    },
    Ok,
    QueryComplete {
        response: String,
    },
    QueryError {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteSessionInfo {
    pub session_id: String,
    pub tty: String,
    pub shell: String,
    pub pid: i64,
    pub label: Option<String>,
    pub last_cwd: Option<String>,
    pub last_command: Option<String>,
    #[serde(default)]
    pub git_branch: Option<String>,
    #[serde(default)]
    pub running_command: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionEvent {
    Added(RemoteSessionInfo),
    Removed { session_id: String },
    Updated(RemoteSessionInfo),
    CommandCompleted {
        session_id: String,
        command: String,
        exit_code: i32,
    },
    AwaitingInput {
        session_id: String,
        prompt: String,
    },
}

/// Length-prefixed binary framing for QUIC streams.
/// Format: 4-byte big-endian length, then JSON payload.
pub mod framing {
    use std::io;

    const MAX_FRAME_SIZE: usize = 1024 * 1024; // 1 MB // 10 MB

    pub async fn write_frame<W: tokio::io::AsyncWriteExt + Unpin>(
        w: &mut W,
        data: &[u8],
    ) -> io::Result<()> {
        let len = (data.len() as u32).to_be_bytes();
        w.write_all(&len).await?;
        w.write_all(data).await?;
        w.flush().await
    }

    pub async fn read_frame<R: tokio::io::AsyncReadExt + Unpin>(
        r: &mut R,
    ) -> io::Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        r.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_FRAME_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame too large: {len} bytes"),
            ));
        }
        let mut buf = vec![0u8; len];
        r.read_exact(&mut buf).await?;
        Ok(buf)
    }

    pub async fn write_message<W: tokio::io::AsyncWriteExt + Unpin>(
        w: &mut W,
        msg: &impl serde::Serialize,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let json = serde_json::to_vec(msg)?;
        write_frame(w, &json).await?;
        Ok(())
    }

    pub async fn read_message<T: serde::de::DeserializeOwned, R: tokio::io::AsyncReadExt + Unpin>(
        r: &mut R,
    ) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
        let data = read_frame(r).await?;
        Ok(serde_json::from_slice(&data)?)
    }
}

/// Synchronous length-prefixed framing for Unix socket IPC.
/// Format: 4-byte big-endian length, then JSON payload.
pub mod sync_framing {
    use std::io::{self, Read, Write};

    const MAX_FRAME_SIZE: usize = 1024 * 1024; // 1 MB

    pub fn write_frame<W: Write>(w: &mut W, data: &[u8]) -> io::Result<()> {
        let len = (data.len() as u32).to_be_bytes();
        w.write_all(&len)?;
        w.write_all(data)?;
        w.flush()
    }

    pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        r.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_FRAME_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame too large: {len} bytes"),
            ));
        }
        let mut buf = vec![0u8; len];
        r.read_exact(&mut buf)?;
        Ok(buf)
    }

    pub fn write_message<W: Write>(w: &mut W, msg: &impl serde::Serialize) -> io::Result<()> {
        let json = serde_json::to_vec(msg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        write_frame(w, &json)
    }

    pub fn read_message<T: serde::de::DeserializeOwned, R: Read>(r: &mut R) -> io::Result<T> {
        let data = read_frame(r)?;
        serde_json::from_slice(&data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

/// Lightweight state updates sent via unreliable datagrams.
/// Best-effort: the receiver must tolerate missing updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StatePush {
    SessionActivity {
        session_id: String,
        last_cwd: Option<String>,
        git_branch: Option<String>,
        running_command: Option<String>,
    },
    CommandStarted {
        session_id: String,
        command: String,
    },
    CommandFinished {
        session_id: String,
        command: String,
        exit_code: i32,
    },
}
