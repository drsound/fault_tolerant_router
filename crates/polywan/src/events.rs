//! Events (SPEC.md §8.1, FR-EV-1 to FR-EV-3) and their history for
//! `GET /v1/events` (FR-API-2).
//!
//! The State task owns the [`Bus`]: emitting assigns the sequence number,
//! serialises the event once (an event is small and bounded), stores it in
//! the ring under a short lock and offers it to every notifier's bounded
//! queue without waiting; a full queue drops the event for that notifier
//! and counts it (INV-8). Readers of the ring take copies of the stored
//! JSON under the lock and never serialise or wait under it.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::Value;
use tokio::sync::{mpsc, watch};

/// Bounds of the ring and of one response (FR-API-2).
pub const RING_EVENTS: usize = 1000;
pub const RING_BYTES: usize = 4 << 20;

/// One event (FR-EV-2). Messages and reasons are built from selected
/// operational fields, never from error chains (FR-API-2).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Event {
    pub seq: u64,
    pub instance: String,
    /// RFC 3339, UTC, milliseconds.
    pub timestamp: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uplink: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub message: String,
    /// The synthetic event of a notification test (FR-MAIL-4).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub test: bool,
}

/// What an emitter provides; the bus adds the rest.
#[derive(Clone, Debug, Default)]
pub struct NewEvent {
    pub kind: &'static str,
    pub uplink: Option<String>,
    pub family: Option<&'static str>,
    pub old: Option<Value>,
    pub new: Option<Value>,
    pub reason: Option<String>,
    pub message: String,
}

impl NewEvent {
    pub fn new(kind: &'static str, message: impl Into<String>) -> NewEvent {
        NewEvent {
            kind,
            message: message.into(),
            ..NewEvent::default()
        }
    }

    pub fn path(mut self, uplink: &str, family: &'static str) -> NewEvent {
        self.uplink = Some(uplink.to_owned());
        self.family = Some(family);
        self
    }

    pub fn uplink(mut self, uplink: &str) -> NewEvent {
        self.uplink = Some(uplink.to_owned());
        self
    }

    pub fn family(mut self, family: &'static str) -> NewEvent {
        self.family = Some(family);
        self
    }

    pub fn change(mut self, old: impl Into<Value>, new: impl Into<Value>) -> NewEvent {
        self.old = Some(old.into());
        self.new = Some(new.into());
        self
    }

    pub fn reason(mut self, reason: impl Into<String>) -> NewEvent {
        self.reason = Some(reason.into());
        self
    }
}

/// A notifier's queue (FR-EV-3): at most `capacity` events and
/// `max_bytes` of serialised event data, of the selected types only.
struct Notifier {
    name: &'static str,
    tx: mpsc::Sender<(Arc<Event>, usize)>,
    bytes: Arc<AtomicUsize>,
    max_bytes: usize,
    /// `None`: every type.
    select: Option<Vec<String>>,
    dropped: u64,
}

/// The receiving end of a notifier's queue.
pub struct Queue {
    rx: mpsc::Receiver<(Arc<Event>, usize)>,
    bytes: Arc<AtomicUsize>,
}

impl Queue {
    pub async fn recv(&mut self) -> Option<Arc<Event>> {
        let (e, n) = self.rx.recv().await?;
        self.bytes.fetch_sub(n, Ordering::Relaxed);
        Some(e)
    }

    /// An event already queued, without waiting.
    pub fn try_recv(&mut self) -> Option<Arc<Event>> {
        let (e, n) = self.rx.try_recv().ok()?;
        self.bytes.fetch_sub(n, Ordering::Relaxed);
        Some(e)
    }
}

/// The emitter, owned by the State task.
pub struct Bus {
    instance: String,
    seq: u64,
    ring: Arc<Mutex<Ring>>,
    latest: watch::Sender<u64>,
    notifiers: Vec<Notifier>,
}

impl Bus {
    pub fn new(instance: String) -> Bus {
        Bus {
            ring: Arc::new(Mutex::new(Ring::new(instance.clone()))),
            instance,
            seq: 0,
            latest: watch::channel(0).0,
            notifiers: Vec::new(),
        }
    }

    pub fn instance(&self) -> &str {
        &self.instance
    }

    /// The history, for the API's readers.
    pub fn ring(&self) -> Arc<Mutex<Ring>> {
        Arc::clone(&self.ring)
    }

    /// The latest sequence number, for long polls.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.latest.subscribe()
    }

    /// A notifier's queue, of at most `capacity` events and `max_bytes` of
    /// serialised event data, receiving every type until [`Bus::select`].
    pub fn add_notifier(&mut self, name: &'static str, capacity: usize, max_bytes: usize) -> Queue {
        let (tx, rx) = mpsc::channel(capacity);
        let bytes = Arc::new(AtomicUsize::new(0));
        self.notifiers.push(Notifier {
            name,
            tx,
            bytes: Arc::clone(&bytes),
            max_bytes,
            select: None,
            dropped: 0,
        });
        Queue { rx, bytes }
    }

    /// The event types a notifier receives from now on (FR-MAIL-2:
    /// selection precedes admission); `None` for every type.
    pub fn select(&mut self, name: &str, types: Option<Vec<String>>) {
        for n in self.notifiers.iter_mut().filter(|n| n.name == name) {
            n.select = types.clone();
        }
    }

    /// Events dropped per notifier (`polywan_events_dropped_total`).
    pub fn dropped(&self) -> Vec<(&'static str, u64)> {
        self.notifiers.iter().map(|n| (n.name, n.dropped)).collect()
    }

    pub fn emit(&mut self, new: NewEvent) -> Arc<Event> {
        self.seq += 1;
        let event = Arc::new(Event {
            seq: self.seq,
            instance: self.instance.clone(),
            timestamp: rfc3339(SystemTime::now()),
            kind: new.kind,
            uplink: new.uplink,
            family: new.family,
            old: new.old,
            new: new.new,
            reason: new.reason,
            message: new.message,
            test: false,
        });
        let json: Arc<str> = serde_json::to_string(&*event).unwrap_or_default().into();
        let size = json.len();
        self.ring
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(event.seq, json);
        for n in &mut self.notifiers {
            if n.select.as_ref().is_some_and(|t| !t.iter().any(|k| k == event.kind)) {
                continue;
            }
            // Counted before sending: the receiver subtracts what it takes.
            if n.bytes.fetch_add(size, Ordering::Relaxed) + size > n.max_bytes
                || n.tx.try_send((Arc::clone(&event), size)).is_err()
            {
                n.bytes.fetch_sub(size, Ordering::Relaxed);
                n.dropped += 1;
            }
        }
        self.latest.send_replace(event.seq);
        event
    }
}

/// The in-memory history: at most [`RING_EVENTS`] events and
/// [`RING_BYTES`] of serialised data, the oldest evicted first.
pub struct Ring {
    instance: String,
    events: VecDeque<(u64, Arc<str>)>,
    bytes: usize,
}

/// One response of `GET /v1/events`.
#[derive(Debug, PartialEq)]
pub struct Page {
    pub instance: String,
    pub reset: bool,
    pub truncated: bool,
    /// Serialised events, oldest first.
    pub events: Vec<Arc<str>>,
}

impl Ring {
    fn new(instance: String) -> Ring {
        Ring {
            instance,
            events: VecDeque::new(),
            bytes: 0,
        }
    }

    fn push(&mut self, seq: u64, json: Arc<str>) {
        self.bytes += json.len();
        self.events.push_back((seq, json));
        while self.events.len() > RING_EVENTS || self.bytes > RING_BYTES {
            match self.events.pop_front() {
                Some((_, old)) => self.bytes -= old.len(),
                None => break,
            }
        }
    }

    pub fn latest(&self) -> u64 {
        self.events.back().map_or(0, |(s, _)| *s)
    }

    /// The events after `after` of instance `instance`, at most `limit` and
    /// `max_bytes`. Another instance, or an `after` beyond the latest
    /// event, resets the cursor to the start of the history; history
    /// evicted since `after` is reported as truncated (FR-API-2).
    pub fn page(&self, instance: Option<&str>, after: Option<u64>, limit: usize, max_bytes: usize) -> Page {
        let latest = self.latest();
        let reset = instance.is_some_and(|i| i != self.instance) || after.is_some_and(|a| a > latest);
        let after = if reset { None } else { after };
        let oldest = self.events.front().map_or(latest + 1, |(s, _)| *s);
        let truncated = after.is_some_and(|a| a + 1 < oldest);
        let mut events = Vec::new();
        let mut bytes = 0;
        for (seq, json) in &self.events {
            if after.is_some_and(|a| *seq <= a) {
                continue;
            }
            // At least one event, whatever its size, so that a client
            // always advances.
            if events.len() >= limit.min(RING_EVENTS) || (!events.is_empty() && bytes + json.len() > max_bytes) {
                break;
            }
            bytes += json.len();
            events.push(Arc::clone(json));
        }
        Page {
            instance: self.instance.clone(),
            reset,
            truncated,
            events,
        }
    }
}

/// A random instance identifier (FR-EV-2).
pub fn instance_id() -> String {
    let mut b = [0u8; 16];
    // Without randomness, the start time still separates runs.
    if getrandom::fill(&mut b).is_err() {
        let n = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
        b = n.to_le_bytes();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// RFC 3339 in UTC with milliseconds (`2026-10-05T01:02:03.456Z`).
pub fn rfc3339(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (y, m, day) = civil(days as i64);
    format!(
        "{y:04}-{m:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        d.subsec_millis()
    )
}

/// Year, month and day of a day count since 1970-01-01 (proleptic
/// Gregorian; Howard Hinnant's algorithm).
pub(crate) fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn timestamps_are_rfc3339_utc() {
        let at = |s: u64, ms: u64| rfc3339(UNIX_EPOCH + Duration::from_secs(s) + Duration::from_millis(ms));
        assert_eq!(at(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(at(951_782_400, 5), "2000-02-29T00:00:00.005Z");
        assert_eq!(at(1_791_158_400 + 3723, 999), "2026-10-05T01:02:03.999Z");
        assert_eq!(at(4_107_542_399, 0), "2100-02-28T23:59:59.000Z");
    }

    #[test]
    fn events_carry_sequence_instance_and_fields() {
        let mut bus = Bus::new("abc".into());
        let mut rx = bus.add_notifier("email", 1, usize::MAX);
        let e = bus.emit(
            NewEvent::new("path_state_changed", "uplink a ipv4: up -> down (carrier_lost)")
                .path("a", "ipv4")
                .change("up", "down")
                .reason("carrier_lost"),
        );
        assert_eq!((e.seq, e.instance.as_str()), (1, "abc"));
        let json: Value =
            serde_json::from_str(&bus.ring().lock().unwrap().page(None, None, 10, RING_BYTES).events[0]).unwrap();
        assert_eq!(json["type"], "path_state_changed");
        assert_eq!(json["old"], "up");
        assert_eq!(json["family"], "ipv4");
        assert!(json.get("test").is_none());
        // The notifier's queue holds one event: the second is dropped and
        // counted, routing never waits.
        bus.emit(NewEvent::new("daemon_stopping", "stopping"));
        assert_eq!(bus.dropped(), [("email", 1)]);
        assert_eq!(rx.try_recv().unwrap().seq, 1);
        assert_eq!(*bus.subscribe().borrow(), 2);
    }

    #[test]
    fn notifiers_receive_selected_types_within_their_byte_bound() {
        let mut bus = Bus::new("abc".into());
        let mut rx = bus.add_notifier("email", 10, 400);
        bus.select("email", Some(vec!["daemon_started".into()]));
        bus.emit(NewEvent::new("config_reloaded", "not selected"));
        bus.emit(NewEvent::new("daemon_started", "x".repeat(100)));
        // Selected, but beyond the 400 bytes with the first one: dropped.
        bus.emit(NewEvent::new("daemon_started", "x".repeat(200)));
        assert_eq!(bus.dropped(), [("email", 1)]);
        assert_eq!(rx.try_recv().unwrap().seq, 2);
        assert!(rx.try_recv().is_none());
        // Taken events free their bytes.
        bus.emit(NewEvent::new("daemon_started", "x".repeat(200)));
        assert_eq!(rx.try_recv().unwrap().seq, 4);
        bus.select("email", None);
        bus.emit(NewEvent::new("config_reloaded", "every type"));
        assert_eq!(rx.try_recv().unwrap().seq, 5);
    }

    fn ring_of(n: u64, size: usize) -> Ring {
        let mut r = Ring::new("i1".into());
        for seq in 1..=n {
            r.push(seq, "x".repeat(size).into());
        }
        r
    }

    #[test]
    fn the_ring_keeps_its_bounds() {
        let r = ring_of(1500, 10);
        assert_eq!((r.events.len(), r.latest()), (1000, 1500));
        // Two events of 3 MiB do not fit in 4 MiB.
        let r = ring_of(3, 3 << 20);
        assert_eq!(r.events.len(), 1);
        assert_eq!(r.bytes, 3 << 20);
    }

    #[test]
    fn pages_follow_the_cursor() {
        let r = ring_of(1500, 10);
        let p = r.page(Some("i1"), Some(1400), 1000, RING_BYTES);
        assert_eq!((p.reset, p.truncated, p.events.len()), (false, false, 100));
        // History evicted since the cursor.
        let p = r.page(Some("i1"), Some(10), 50, RING_BYTES);
        assert_eq!((p.reset, p.truncated, p.events.len()), (false, true, 50));
        // Another instance, or a cursor beyond the latest event: from the
        // start of the history.
        for p in [
            r.page(Some("other"), Some(1400), 5, RING_BYTES),
            r.page(Some("i1"), Some(9999), 5, RING_BYTES),
        ] {
            assert_eq!((p.reset, p.truncated, p.events.len()), (true, false, 5));
        }
        // Nothing new: an empty page.
        assert!(r.page(Some("i1"), Some(1500), 10, RING_BYTES).events.is_empty());
        // The byte bound, at least one event.
        assert_eq!(r.page(None, None, 1000, 25).events.len(), 2);
        assert_eq!(r.page(None, None, 1000, 1).events.len(), 1);
    }
}
