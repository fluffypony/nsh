//! Unified reactive state bus for daemon-wide event broadcasting.
//!
//! Replaces scattered file-based notifications and polling loops with
//! a single publish/subscribe channel. Subscribers (remote endpoint,
//! per-session notification writers, mobile push) receive events
//! immediately without polling.

use tokio::sync::broadcast;

/// Events that flow through the state bus.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(dead_code)]
pub enum BusEvent {
    SessionCreated {
        session_id: String,
        tty: String,
        shell: String,
    },
    SessionEnded {
        session_id: String,
    },
    SessionUpdated {
        session_id: String,
    },
    CommandRecorded {
        session_id: String,
        command: String,
        exit_code: i32,
    },
    HookReloadNeeded {
        session_id: String,
    },
    MemoryIngested {
        ops_count: usize,
    },
    RemotePeerConnected {
        peer_id: String,
    },
    RemotePeerDisconnected {
        peer_id: String,
    },
}

/// A broadcast-based event bus for the daemon.
///
/// Producers call `publish()` to send events; consumers call
/// `subscribe()` to get a receiver that yields all future events.
/// Slow consumers that fall behind will miss events (lossy semantics,
/// consistent with the best-effort StatePush datagram model).
pub struct StateBus {
    tx: broadcast::Sender<BusEvent>,
}

impl StateBus {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(256);
        Self { tx }
    }

    /// Publish an event to all current subscribers.
    /// Returns silently if there are no subscribers.
    pub fn publish(&self, event: BusEvent) {
        let _ = self.tx.send(event);
    }

    /// Create a new subscription. The receiver will see all events
    /// published after this call.
    #[allow(dead_code)]
    pub fn subscribe(&self) -> broadcast::Receiver<BusEvent> {
        self.tx.subscribe()
    }
}

impl Default for StateBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publish_subscribe_round_trip() {
        let bus = StateBus::new();
        let mut rx = bus.subscribe();

        bus.publish(BusEvent::SessionCreated {
            session_id: "s1".into(),
            tty: "/dev/pts/0".into(),
            shell: "zsh".into(),
        });

        let event = rx.recv().await.unwrap();
        match event {
            BusEvent::SessionCreated { session_id, .. } => {
                assert_eq!(session_id, "s1");
            }
            _ => panic!("wrong event type"),
        }
    }

    #[tokio::test]
    async fn no_subscriber_does_not_panic() {
        let bus = StateBus::new();
        // Should not panic even with no subscribers
        bus.publish(BusEvent::SessionEnded {
            session_id: "s1".into(),
        });
    }
}
