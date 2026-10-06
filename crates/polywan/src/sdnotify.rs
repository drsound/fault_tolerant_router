//! systemd notifications (IMPL-10) without libsystemd: datagrams of
//! `KEY=VALUE` lines to the socket named by `NOTIFY_SOCKET`, a path or an
//! abstract name (`@`). Without the variable nothing is sent, so the daemon
//! behaves the same without systemd; a failed send is logged once and is
//! never fatal.

use std::io;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};

use tracing::warn;

pub const VARIABLE: &str = "NOTIFY_SOCKET";

pub struct Notifier {
    socket: UnixDatagram,
    address: SocketAddr,
    warned: bool,
}

/// The outcome of [`Notifier::send`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sent {
    /// Sent, or failed for good (logged).
    Done,
    /// The receiver's queue is full: the message was not sent.
    Again,
}

impl Notifier {
    /// The notifier of `NOTIFY_SOCKET`, read once at startup; `None` without
    /// the variable or when it cannot be used (logged).
    pub fn from_env() -> Option<Notifier> {
        let value = std::env::var_os(VARIABLE)?;
        match Notifier::new(&value.to_string_lossy()) {
            Ok(n) => Some(n),
            Err(e) => {
                warn!("{VARIABLE}={value:?}: {e}; systemd is not notified");
                None
            }
        }
    }

    pub fn new(target: &str) -> io::Result<Notifier> {
        let address = if let Some(name) = target.strip_prefix('@') {
            SocketAddr::from_abstract_name(name)?
        } else if target.starts_with('/') {
            SocketAddr::from_pathname(target)?
        } else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "neither an absolute path nor an abstract name",
            ));
        };
        let socket = UnixDatagram::unbound()?;
        socket.set_nonblocking(true)?;
        Ok(Notifier {
            socket,
            address,
            warned: false,
        })
    }

    /// Sends `message` (newline-separated assignments) without blocking.
    pub fn send(&mut self, message: &str) -> Sent {
        match self.socket.send_to_addr(message.as_bytes(), &self.address) {
            Ok(_) => Sent::Done,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Sent::Again,
            Err(e) => {
                if !std::mem::replace(&mut self.warned, true) {
                    warn!("cannot notify systemd: {e}");
                }
                Sent::Done
            }
        }
    }
}

/// What a running daemon tells systemd: `READY=1` once, `STATUS=` when the
/// summary differs from the one last delivered. A message that found the
/// queue full stays pending; it is rebuilt from the current state, so a
/// summary that returns to the delivered one leaves nothing to send.
pub struct Notifications {
    notifier: Notifier,
    ready_sent: bool,
    status_sent: String,
}

impl Notifications {
    pub fn new(notifier: Notifier) -> Notifications {
        Notifications {
            notifier,
            ready_sent: false,
            status_sent: String::new(),
        }
    }

    /// Sends what changed: readiness when `ready` and not sent yet, the
    /// status line when it changed. Returns whether a message is pending.
    pub fn update(&mut self, ready: bool, status: &str) -> bool {
        let ready = ready && !self.ready_sent;
        let mut message = String::new();
        if ready {
            message += "READY=1\n";
        }
        if status != self.status_sent {
            message += &format!("STATUS={status}\n");
        }
        if message.is_empty() {
            return false;
        }
        match self.notifier.send(&message) {
            Sent::Done => {
                self.ready_sent |= ready;
                status.clone_into(&mut self.status_sent);
                false
            }
            Sent::Again => true,
        }
    }

    pub fn stopping(&mut self) {
        self.notifier.send("STOPPING=1\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receive_blocking(r: &UnixDatagram) -> String {
        r.set_nonblocking(false).unwrap();
        receive(r)
    }

    fn receive(r: &UnixDatagram) -> String {
        let mut buf = [0; 512];
        let n = r.recv(&mut buf).unwrap();
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }

    #[test]
    fn paths_and_abstract_names() {
        let dir = std::env::temp_dir().join(format!("polywan-sdnotify-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("notify");
        let r = UnixDatagram::bind(&path).unwrap();
        let mut n = Notifier::new(&path.to_string_lossy()).unwrap();
        assert_eq!(n.send("READY=1\n"), Sent::Done);
        assert_eq!(receive(&r), "READY=1\n");
        std::fs::remove_dir_all(&dir).unwrap();

        let name = format!("polywan-sdnotify-{}", std::process::id());
        let r = UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(&name).unwrap()).unwrap();
        let mut n = Notifier::new(&format!("@{name}")).unwrap();
        assert_eq!(n.send("STOPPING=1\n"), Sent::Done);
        assert_eq!(receive(&r), "STOPPING=1\n");
    }

    #[test]
    fn a_full_queue_is_retried_and_other_errors_are_dropped() {
        let name = format!("polywan-sdnotify-full-{}", std::process::id());
        let r = UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(&name).unwrap()).unwrap();
        let mut n = Notifier::new(&format!("@{name}")).unwrap();
        // The receiver never reads: its queue fills up.
        let mut sent = 0;
        while n.send("STATUS=x\n") == Sent::Done {
            sent += 1;
            assert!(sent < 100_000, "the queue never filled");
        }
        assert_eq!(receive(&r), "STATUS=x\n");
        assert_eq!(n.send("READY=1\n"), Sent::Done, "room again");
        // No receiver: dropped, not retried.
        drop(r);
        assert_eq!(n.send("READY=1\n"), Sent::Done);
        assert!(Notifier::new("relative").is_err());
    }

    #[test]
    fn notifications_send_changes_and_keep_only_what_is_still_pending() {
        let name = format!("polywan-sdnotify-session-{}", std::process::id());
        let r = UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(&name).unwrap()).unwrap();
        let mut n = Notifications::new(Notifier::new(&format!("@{name}")).unwrap());
        assert!(!n.update(false, "status ok"));
        assert_eq!(receive(&r), "STATUS=status ok\n");
        assert!(!n.update(false, "status ok"), "nothing changed");
        assert!(!n.update(true, "status ok"));
        assert_eq!(receive(&r), "READY=1\n");
        assert!(!n.update(true, "status ok"), "readiness once");
        // A full queue: the change stays pending until it can be sent...
        let mut sent = 0;
        while n.notifier.send("x") == Sent::Done {
            sent += 1;
            assert!(sent < 100_000, "the queue never filled");
        }
        assert!(n.update(true, "status degraded (apply_failed)"));
        // ...and nothing is pending once the summary is back to the one
        // delivered.
        assert!(!n.update(true, "status ok"));
        r.set_nonblocking(true).unwrap();
        while r.recv(&mut [0; 16]).is_ok() {}
        assert!(!n.update(true, "status degraded (apply_failed)"));
        assert_eq!(receive_blocking(&r), "STATUS=status degraded (apply_failed)\n");
    }
}
