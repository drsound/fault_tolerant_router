//! Email notifications (SPEC.md §8.2, FR-MAIL-1 to FR-MAIL-3): selected
//! events are coalesced over `notify.coalesce` into one message, admitted
//! by a rolling-hour limit with one suppression notice, and submitted one
//! at a time through the trusted sendmail interface
//! (`sendmail -i -f FROM RECIPIENT...`, the message on standard input), with
//! retries 1, 5 and 15 min after a failure.
//!
//! The parts that decide (batches, admission, the waiting messages and their
//! retries, message construction) are pure and take the time as an
//! argument; [`notifier`] drives them on the I/O runtime from its own
//! bounded queue of the event bus, so routing never waits (INV-8).
//!
//! Bounds (FR-MAIL-2): the event queue holds 256 events and 1 MiB (the bus
//! enforces both); a batch retains 200 changes and 64 KiB of rendered text,
//! counting the rest; a body holds 128 KiB, an encoded message 512 KiB; at
//! most eight messages wait, with 4 MiB of retained bodies (a waiting
//! message retains only its body; headers are built at each submission).

use std::borrow::Cow;
use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot, watch};
use tokio::time::Instant;
use tracing::{info, warn};

use crate::config::{Email, Notify};
use crate::events::{Event, Queue};
use crate::metrics::Failures;
use crate::subprocess::{self, Spec};

/// The email event queue (FR-MAIL-2).
pub const QUEUE: usize = 256;
pub const QUEUE_BYTES: usize = 1 << 20;
/// Retained changes of a batch and their rendered text (FR-MAIL-2).
pub const BATCH_CHANGES: usize = 200;
pub const BATCH_BYTES: usize = 64 << 10;
/// A body before transfer encoding, and a complete encoded message.
pub const BODY_BYTES: usize = 128 << 10;
pub const MESSAGE_BYTES: usize = 512 << 10;
/// Messages awaiting submission or retry, and their retained bodies.
pub const WAITING: usize = 8;
pub const WAITING_BYTES: usize = 4 << 20;
/// Minutes after the preceding failure (FR-MAIL-3).
const RETRY_MINUTES: [u32; 3] = [1, 5, 15];
/// The submission deadline (FR-MAIL-1).
const DEADLINE: Duration = Duration::from_secs(60);
/// What a stopping daemon spends on the email still waiting.
pub const SHUTDOWN: Duration = Duration::from_secs(10);

/// The durations of email: a minute (of the retries and of the rolling
/// hour) and the submission deadline; shorter under the scenarios' test
/// hook.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Times {
    pub minute: Duration,
    pub deadline: Duration,
}

impl Default for Times {
    fn default() -> Times {
        Times {
            minute: Duration::from_secs(60),
            deadline: DEADLINE,
        }
    }
}

impl Times {
    pub fn hour(&self) -> Duration {
        self.minute * 60
    }

    /// The delay before retry `n` (0-based), if there is one.
    pub fn retry(&self, n: usize) -> Option<Duration> {
        RETRY_MINUTES.get(n).map(|m| self.minute * *m)
    }
}

/// What a message is (its Subject, FR-MAIL-1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Notification,
    Suppressed,
    Test,
}

impl Kind {
    fn subject(self) -> &'static str {
        match self {
            Kind::Notification => "PolyWAN notification",
            Kind::Suppressed => "PolyWAN notifications suppressed",
            Kind::Test => "PolyWAN notification test",
        }
    }
}

/// One line of a batch: time, type, uplink and family, message; control
/// characters escaped (a message never adds lines).
pub fn change_line(e: &Event) -> String {
    let mut s = format!("{} {}", e.timestamp, e.kind);
    for part in [e.uplink.as_deref(), e.family].into_iter().flatten() {
        s.push(' ');
        s.push_str(part);
    }
    s.push_str(": ");
    for c in e.message.chars() {
        if c.is_control() {
            let _ = write!(s, "{}", c.escape_unicode());
        } else {
            s.push(c);
        }
    }
    s.push('\n');
    s
}

/// The changes coalesced into the next message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    pub deadline: Instant,
    text: String,
    changes: usize,
    omitted: usize,
}

impl Batch {
    pub fn new(deadline: Instant) -> Batch {
        Batch {
            deadline,
            text: String::new(),
            changes: 0,
            omitted: 0,
        }
    }

    /// Retains the change within the batch's bounds, or counts it.
    pub fn add(&mut self, e: &Event) {
        let line = change_line(e);
        if self.changes < BATCH_CHANGES && self.text.len() + line.len() <= BATCH_BYTES {
            self.text += &line;
            self.changes += 1;
        } else {
            self.omitted += 1;
        }
    }

    /// The body of the batch's message; `suppressed` messages were
    /// suppressed by the rate limit since the previous admitted one.
    pub fn body(&self, host: Option<&str>, suppressed: u64) -> String {
        let total = self.changes + self.omitted;
        let mut s = format!(
            "PolyWAN{} reports {total} change{}:\n\n",
            host.map(|h| format!(" on {h}")).unwrap_or_default(),
            if total == 1 { "" } else { "s" }
        );
        s += &self.text;
        if self.omitted > 0 {
            let _ = writeln!(
                s,
                "\n{} further change{} omitted (a message lists at most {BATCH_CHANGES} changes and {} KiB).",
                self.omitted,
                if self.omitted == 1 { " was" } else { "s were" },
                BATCH_BYTES >> 10
            );
        }
        if suppressed > 0 {
            let _ = writeln!(
                s,
                "\n{suppressed} notification{} suppressed by notify.email.max_per_hour before this one.",
                if suppressed == 1 { " was" } else { "s were" }
            );
        }
        s
    }
}

/// The body of a suppression notice.
pub fn suppression_body(host: Option<&str>, max_per_hour: u32) -> String {
    format!(
        "PolyWAN{} reached its limit of {max_per_hour} notification{} per hour (notify.email.max_per_hour).\n\nFurther notifications are suppressed until the rolling hour leaves room; the next notification reports how many were suppressed. At most one such notice is sent per hour.\n",
        host.map(|h| format!(" on {h}")).unwrap_or_default(),
        if max_per_hour == 1 { "" } else { "s" }
    )
}

/// The rolling-hour limit of FR-MAIL-2.
#[derive(Clone, Debug, Default)]
pub struct Admission {
    /// Admission times within the last hour (at most `max_per_hour`).
    admitted: VecDeque<Instant>,
    notice: Option<Instant>,
    /// Messages suppressed since the last admitted one.
    suppressed: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admit {
    /// Admitted; `suppressed` messages were suppressed before it.
    Yes { suppressed: u64 },
    /// Suppressed; `notice`: the suppression notice is due.
    No { notice: bool },
}

impl Admission {
    pub fn admit(&mut self, now: Instant, max_per_hour: u32, hour: Duration) -> Admit {
        while self.admitted.front().is_some_and(|t| now.duration_since(*t) >= hour) {
            self.admitted.pop_front();
        }
        if self.admitted.len() < max_per_hour as usize {
            self.admitted.push_back(now);
            return Admit::Yes {
                suppressed: std::mem::take(&mut self.suppressed),
            };
        }
        self.suppressed += 1;
        let notice = self.notice.is_none_or(|t| now.duration_since(t) >= hour);
        if notice {
            self.notice = Some(now);
        }
        Admit::No { notice }
    }
}

/// A message awaiting submission or retry: what it says, not how it is
/// addressed, which follows the configuration of each attempt (FR-MAIL-1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub kind: Kind,
    pub id: String,
    pub date: SystemTime,
    pub body: String,
    /// Failed submissions so far.
    pub failures: usize,
    pub due: Instant,
}

/// A Message-ID: unique by instance and counter, its right side the
/// sender's domain.
pub fn message_id(instance: &str, n: u64, from: &str) -> String {
    let domain = from.rsplit_once('@').map_or("localhost", |(_, d)| d);
    format!("<{n}.{instance}@{domain}>")
}

/// The kernel host name for the Subject, when it qualifies (FR-MAIL-1):
/// at most 63 octets of dot-separated labels of letters, digits and inner
/// hyphens.
pub fn host_suffix(raw: &str) -> Option<&str> {
    let h = raw.trim_end_matches('\n');
    (!h.is_empty() && h.len() <= 63 && h.split('.').all(dns_label)).then_some(h)
}

/// A DNS label of letters, digits and inner hyphens, of 1 to 63 octets (of
/// host names and of mailbox domains, FR-MAIL-1).
pub fn dns_label(l: &str) -> bool {
    (1..=63).contains(&l.len())
        && !l.starts_with('-')
        && !l.ends_with('-')
        && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// The kernel host name, if it qualifies for the Subject.
pub fn hostname() -> Option<String> {
    let raw = std::fs::read_to_string("/proc/sys/kernel/hostname").ok()?;
    host_suffix(&raw).map(str::to_owned)
}

/// RFC 5322 date in UTC (`Mon, 05 Oct 2026 01:02:03 +0000`).
pub fn rfc5322_date(t: SystemTime) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let secs = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (y, m, d) = crate::events::civil(days as i64);
    format!(
        "{}, {d:02} {} {y:04} {:02}:{:02}:{:02} +0000",
        DAYS[(days % 7) as usize],
        MONTHS[m as usize - 1],
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Standard base64 in lines of 76 characters (RFC 2045).
pub fn base64_lines(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len() * 4 / 3 + data.len() / 57 + 4);
    // 57 input bytes make one line of 76 characters.
    for line in data.chunks(57) {
        for c in line.chunks(3) {
            let n = (u32::from(c[0]) << 16)
                | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
                | u32::from(*c.get(2).unwrap_or(&0));
            for i in 0..4 {
                if i <= c.len() {
                    out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out.push('\n');
    }
    out
}

/// `body` cut to at most `max` bytes at a character boundary.
fn truncate_utf8(body: &mut String, max: usize) {
    if body.len() > max {
        let mut end = max;
        while !body.is_char_boundary(end) {
            end -= 1;
        }
        body.truncate(end);
    }
}

/// The complete message for sendmail's standard input, with Unix line
/// ends (the sendmail interface's convention). No event text enters a
/// header (FR-MAIL-1).
pub fn render(m: &Message, email: &Email, host: Option<&str>) -> Result<Vec<u8>, String> {
    let body: Cow<str> = if m.body.len() > BODY_BYTES {
        const CUT: &str = "\n[truncated]\n";
        let mut body = m.body.clone();
        truncate_utf8(&mut body, BODY_BYTES - CUT.len());
        body += CUT;
        body.into()
    } else {
        m.body.as_str().into()
    };
    let mut s = format!(
        "Date: {}\nMessage-ID: {}\nFrom: {}\nTo: {}\nSubject: {}{}\nMIME-Version: 1.0\nContent-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: base64\nAuto-Submitted: auto-generated\n\n",
        rfc5322_date(m.date),
        m.id,
        email.from,
        // One recipient per line: every header line stays short.
        email.to.join(",\n "),
        m.kind.subject(),
        host.map(|h| format!(" ({h})")).unwrap_or_default(),
    );
    s += &base64_lines(body.as_bytes());
    if s.len() > MESSAGE_BYTES {
        return Err(format!(
            "the message would have {} bytes, more than {MESSAGE_BYTES}",
            s.len()
        ));
    }
    Ok(s.into_bytes())
}

/// The sendmail run of a message (FR-MAIL-1): as root with group 0, the
/// message on standard input, standard output discarded.
pub fn spec(email: &Email, input: Vec<u8>, deadline: Duration) -> Spec {
    let mut args = vec!["-i".to_owned(), "-f".to_owned(), email.from.clone()];
    args.extend(email.to.iter().cloned());
    Spec {
        program: email.sendmail.clone(),
        args,
        env: Vec::new(),
        uid: 0,
        gid: 0,
        input,
        capture_stdout: false,
        supervise_descendants: false,
        input_may_go_unread: false,
        timeout: deadline,
    }
}

/// What the email notifier shares with notification tests: one sendmail
/// submission at a time, tests included (FR-MAIL-3), and the numbers of
/// the instance's Message-IDs.
#[derive(Clone, Debug)]
pub struct Sendmail {
    /// One permit. The semaphore is fair: a test waiting for a running
    /// submission goes before the next due message. Closed once the
    /// notifier ends.
    pub turn: Arc<Semaphore>,
    ids: Arc<AtomicU64>,
}

impl Default for Sendmail {
    fn default() -> Sendmail {
        Sendmail {
            turn: Arc::new(Semaphore::new(1)),
            ids: Arc::default(),
        }
    }
}

impl Sendmail {
    /// The number of the next Message-ID.
    pub fn next_id(&self) -> u64 {
        self.ids.fetch_add(1, Ordering::Relaxed) + 1
    }
}

/// The decisions of the email notifier.
pub struct Mail {
    pub times: Times,
    /// `polywan_notifications_failed_total{channel="email"}`.
    pub failures: Arc<Failures>,
    instance: String,
    pub sendmail: Sendmail,
    pub batch: Option<Batch>,
    pub admission: Admission,
    /// Oldest first.
    pub waiting: VecDeque<Message>,
}

impl Mail {
    pub fn new(instance: String, times: Times, failures: Arc<Failures>, sendmail: Sendmail) -> Mail {
        Mail {
            times,
            failures,
            instance,
            sendmail,
            batch: None,
            admission: Admission::default(),
            waiting: VecDeque::new(),
        }
    }

    /// A selected event: into the open batch, or a new one closing
    /// `coalesce` from now.
    pub fn add(&mut self, now: Instant, coalesce: Duration, e: &Event) {
        self.batch.get_or_insert_with(|| Batch::new(now + coalesce)).add(e);
    }

    pub fn message(&mut self, kind: Kind, body: String, email: &Email, now: Instant) -> Message {
        let n = self.sendmail.next_id();
        Message {
            kind,
            id: message_id(&self.instance, n, &email.from),
            date: SystemTime::now(),
            body,
            failures: 0,
            due: now,
        }
    }

    /// Closes the open batch: an admitted message, or a suppression
    /// (with its notice once an hour).
    pub fn close_batch(&mut self, now: Instant, email: &Email, host: Option<&str>) {
        let Some(batch) = self.batch.take() else { return };
        match self.admission.admit(now, email.max_per_hour, self.times.hour()) {
            Admit::Yes { suppressed } => {
                let m = self.message(Kind::Notification, batch.body(host, suppressed), email, now);
                self.wait(m);
            }
            Admit::No { notice } => {
                info!("email notification suppressed by notify.email.max_per_hour");
                if notice {
                    let m = self.message(Kind::Suppressed, suppression_body(host, email.max_per_hour), email, now);
                    self.wait(m);
                }
            }
        }
    }

    /// Queues a message, evicting the oldest beyond the bounds.
    pub fn wait(&mut self, m: Message) {
        self.waiting.push_back(m);
        while self.waiting.len() > WAITING || self.waiting.iter().map(|m| m.body.len()).sum::<usize>() > WAITING_BYTES {
            if let Some(old) = self.waiting.pop_front() {
                warn!(message_id = %old.id, "email discarded: too many messages waiting");
            }
        }
    }

    /// When the next waiting message is due.
    pub fn next_due(&self) -> Option<Instant> {
        self.waiting.iter().map(|m| m.due).min()
    }

    /// The first waiting message due at `now`.
    pub fn take_due(&mut self, now: Instant) -> Option<Message> {
        let i = (0..self.waiting.len())
            .filter(|i| self.waiting[*i].due <= now)
            .min_by_key(|i| self.waiting[*i].due)?;
        self.waiting.remove(i)
    }

    /// A failed submission: retried after its delay, or dropped after the
    /// last retry (FR-MAIL-3).
    pub fn failed(&mut self, mut m: Message, now: Instant) {
        match self.times.retry(m.failures) {
            Some(delay) => {
                m.failures += 1;
                m.due = now + delay;
                info!(message_id = %m.id, retry_in = ?delay, "email submission will be retried");
                self.wait(m);
            }
            None => warn!(message_id = %m.id, "email dropped after its last retry"),
        }
    }

    /// `[notify.email]` removed: pending email and retries are discarded
    /// (FR-MAIL-1); the rate-limit accounting stays.
    pub fn discard(&mut self) -> usize {
        let n = self.waiting.len() + usize::from(self.batch.is_some());
        self.waiting.clear();
        self.batch = None;
        n
    }
}

/// How a submission ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Submitted {
    Accepted,
    /// Retried (FR-MAIL-3).
    Failed(String),
    /// No conforming message could be built: reported, not retried.
    Unbuildable(String),
}

/// Submits a message with the configuration it starts with; the
/// executable's trust is checked first (FR-CFG-5).
pub async fn submit(m: &Message, email: &Email, deadline: Duration) -> Submitted {
    match attempt(m, email, deadline).await {
        Err(Before::Unbuildable(e)) => Submitted::Unbuildable(e),
        Err(Before::Untrusted(e)) => Submitted::Failed(e),
        Ok(o) if o.end.success() => Submitted::Accepted,
        Ok(o) => Submitted::Failed(format!("{}, stderr: {}", o.end, o.stderr.escaped())),
    }
}

/// Why an attempt ran no process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Before {
    Unbuildable(String),
    Untrusted(String),
}

impl std::fmt::Display for Before {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Before::Unbuildable(e) | Before::Untrusted(e) => f.write_str(e),
        }
    }
}

/// One run of sendmail for a message, its executable's trust checked first
/// (FR-CFG-5).
pub async fn attempt(m: &Message, email: &Email, deadline: Duration) -> Result<subprocess::Outcome, Before> {
    let input = render(m, email, hostname().as_deref()).map_err(Before::Unbuildable)?;
    let trust = crate::checks::executable(&email.sendmail, "notify.email.sendmail");
    if !trust.errors.is_empty() {
        return Err(Before::Untrusted(trust.errors.join("; ")));
    }
    Ok(subprocess::run(&spec(email, input, deadline)).await)
}

/// A notification test's message (FR-MAIL-4), outside the rate limit.
pub fn test_message(instance: &str, n: u64, email: &Email) -> Message {
    Message {
        kind: Kind::Test,
        id: message_id(instance, n, &email.from),
        date: SystemTime::now(),
        body: crate::notifytest::body(hostname().as_deref()),
        failures: 0,
        due: Instant::now(),
    }
}

/// Logs a submission's end, counts a failure and applies FR-MAIL-3.
fn finished(mail: &mut Mail, m: Message, result: Submitted, now: Instant, retry: bool) {
    if result != Submitted::Accepted {
        Failures::add(&mail.failures.email);
    }
    match result {
        Submitted::Accepted => info!(message_id = %m.id, "email submitted"),
        Submitted::Unbuildable(e) => warn!(message_id = %m.id, error = %e, "email not submitted"),
        Submitted::Failed(e) => {
            warn!(message_id = %m.id, attempt = m.failures + 1, error = %e, "email submission failed");
            if retry {
                mail.failed(m, now);
            }
        }
    }
}

/// The running submission: it gives its message back with how it ended.
type Running = std::pin::Pin<Box<dyn Future<Output = (Message, Submitted)> + Send>>;

/// Submits `m` with the configuration it starts with, holding the sendmail
/// turn until it ends.
fn submission(m: Message, email: Email, deadline: Duration, turn: OwnedSemaphorePermit) -> Running {
    Box::pin(async move {
        let result = submit(&m, &email, deadline).await;
        drop(turn);
        (m, result)
    })
}

async fn at(t: Option<Instant>) {
    match t {
        Some(t) => tokio::time::sleep_until(t).await,
        None => std::future::pending().await,
    }
}

/// The email notifier: `events` from the bus (selected by
/// `notify.email.events`), the notification settings from `config`. A
/// stopping daemon sends `stop` the sender of its answer: the batch is
/// closed and what waits is tried once, within [`SHUTDOWN`].
pub async fn notifier(
    events: Queue,
    config: watch::Receiver<Arc<Notify>>,
    stop: oneshot::Receiver<oneshot::Sender<()>>,
    mut mail: Mail,
) {
    let turn = Arc::clone(&mail.sendmail.turn);
    drive(events, config, stop, &mut mail).await;
    // Tests waiting for the turn end; later ones are refused (FR-MAIL-4).
    turn.close();
}

async fn drive(
    mut events: Queue,
    mut config: watch::Receiver<Arc<Notify>>,
    mut stop: oneshot::Receiver<oneshot::Sender<()>>,
    mail: &mut Mail,
) {
    let mut notify = Arc::clone(&config.borrow_and_update());
    let mut running: Option<Running> = None;
    loop {
        let close = mail.batch.as_ref().map(|b| b.deadline);
        let due = if running.is_some() { None } else { mail.next_due() };
        let turn = Arc::clone(&mail.sendmail.turn);
        // In this order: an accepted reload applies before any submission
        // that is ready at the same time (FR-MAIL-1), and the stop before
        // anything else.
        tokio::select! {
            biased;
            changed = config.changed() => {
                if changed.is_err() {
                    return;
                }
                let next = Arc::clone(&config.borrow_and_update());
                if notify.email.is_some() && next.email.is_none() {
                    let n = mail.discard();
                    if n > 0 {
                        info!(discarded = n, "email removed from the configuration: pending email discarded");
                    }
                }
                notify = next;
            }
            done = &mut stop => {
                let Ok(done) = done else { return };
                while let Some(e) = events.try_recv() {
                    if notify.email.is_some() {
                        mail.add(Instant::now(), notify.coalesce, &e);
                    }
                }
                flush(mail, &notify, running.take()).await;
                let _ = done.send(());
                return;
            }
            (m, result) = async { running.as_mut().expect("polled while running").await }, if running.is_some() => {
                running = None;
                // A retry needs email still configured (FR-MAIL-1).
                let retry = notify.email.is_some();
                finished(mail, m, result, Instant::now(), retry);
            }
            // The message is taken once the turn is held: one that a reload
            // discards meanwhile is not submitted.
            permit = async { at(due).await; turn.acquire_owned().await }, if due.is_some() => {
                let Ok(permit) = permit else { return };
                match &notify.email {
                    Some(email) => {
                        if let Some(m) = mail.take_due(Instant::now()) {
                            running = Some(submission(m, email.clone(), mail.times.deadline, permit));
                        }
                    }
                    None => {
                        mail.discard();
                    }
                }
            }
            () = at(close) => match &notify.email {
                Some(email) => mail.close_batch(Instant::now(), email, hostname().as_deref()),
                None => {
                    mail.discard();
                }
            },
            e = events.recv() => {
                let Some(e) = e else { return };
                if notify.email.is_some() {
                    mail.add(Instant::now(), notify.coalesce, &e);
                }
            }
        }
    }
}

/// The last submissions of a stopping daemon, within [`SHUTDOWN`]: the
/// running one, then each waiting message that is due, once. A retry not
/// due yet keeps its delay (FR-MAIL-3) and is discarded. Each submission
/// takes its turn: a running notification test ends first.
async fn flush(mail: &mut Mail, notify: &Notify, running: Option<Running>) {
    let Some(email) = &notify.email else { return };
    let now = Instant::now();
    mail.close_batch(now, email, hostname().as_deref());
    let deadline = mail.times.deadline;
    let (pending, later): (Vec<Message>, Vec<Message>) = std::mem::take(&mut mail.waiting)
        .into_iter()
        .partition(|m| m.due <= now);
    if !later.is_empty() {
        warn!(
            discarded = later.len(),
            "email retries not due yet at shutdown were discarded"
        );
    }
    let turn = Arc::clone(&mail.sendmail.turn);
    let work = async {
        if let Some(f) = running {
            let (m, r) = f.await;
            finished(mail, m, r, Instant::now(), false);
        }
        for m in pending {
            let Ok(_turn) = turn.acquire().await else { return };
            let r = submit(&m, email, deadline).await;
            finished(mail, m, r, Instant::now(), false);
        }
    };
    if tokio::time::timeout(SHUTDOWN, work).await.is_err() {
        warn!("email still waiting at shutdown was discarded");
    }
}

#[cfg(test)]
mod tests;
