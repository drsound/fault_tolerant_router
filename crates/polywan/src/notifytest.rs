//! Notification tests (SPEC.md FR-MAIL-4): one attempt through every
//! configured channel, bypassing coalescing, the email rate limit and the
//! event filters, without retries and without touching ordinary work.
//!
//! The email test takes the sendmail turn of the daemon's email notifier,
//! so that it shares the limit of one sendmail submission at a time; hooks
//! get the synthetic `notify_test` event (never in the ring) and share the
//! hooks' concurrency limit. The whole test has a budget of the sendmail deadline
//! plus every hook's timeout; at its expiry the processes still running are
//! killed with their groups and the channels not started are reported as
//! such. `notify-test --offline` runs the same channels in the CLI.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{Semaphore, watch};

use crate::config::Notify;
use crate::events::Event;
use crate::mail::{self, Sendmail, Times};
use crate::subprocess::{self, End};

/// How a channel's test ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Succeeded,
    Failed,
    TimedOut,
    NotStarted,
}

/// One channel's report (FR-MAIL-4): control socket only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// `email` or `hook`.
    pub channel: String,
    /// A hook's program.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    pub outcome: Outcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_status: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
    /// Why it failed before or around the process (trust, spawn, input).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Standard error, at most 64 KiB, as text.
    #[serde(default)]
    pub stderr: String,
    #[serde(default)]
    pub stderr_truncated: bool,
}

impl Report {
    fn new(channel: &str, program: Option<String>, outcome: Outcome) -> Report {
        Report {
            channel: channel.to_owned(),
            program,
            outcome,
            exit_status: None,
            signal: None,
            error: None,
            stderr: String::new(),
            stderr_truncated: false,
        }
    }

    /// The report of a run, or of a failure before it.
    pub fn of(channel: &str, program: Option<String>, run: Result<subprocess::Outcome, String>) -> Report {
        let o = match run {
            Ok(o) => o,
            Err(e) => {
                let mut r = Report::new(channel, program, Outcome::Failed);
                r.error = Some(e);
                return r;
            }
        };
        let outcome = match o.end {
            End::Exited(0) => Outcome::Succeeded,
            End::TimedOut => Outcome::TimedOut,
            _ => Outcome::Failed,
        };
        let mut r = Report::new(channel, program, outcome);
        match o.end {
            End::Exited(c) => r.exit_status = Some(c),
            End::Signaled(s) => r.signal = Some(s),
            End::SpawnFailed(e) | End::InputFailed(e) => r.error = Some(e),
            End::TimedOut => {}
        }
        r.stderr = String::from_utf8_lossy(&o.stderr.data).into_owned();
        r.stderr_truncated = o.stderr.truncated;
        r
    }
}

/// The synthetic event of a hook test, never in the ring (FR-MAIL-4).
pub fn event(instance: &str) -> Event {
    Event {
        seq: 0,
        instance: instance.to_owned(),
        timestamp: crate::events::rfc3339(std::time::SystemTime::now()),
        kind: "notify_test",
        uplink: None,
        family: None,
        old: None,
        new: None,
        reason: None,
        message: "notification test".into(),
        test: true,
    }
}

/// The test message's body: its last lines check that the transport keeps
/// non-ASCII text and a line holding a single dot (sendmail `-i`).
pub fn body(host: Option<&str>) -> String {
    format!(
        "This is a test of PolyWAN's email notifications{}, requested with `polywan notify-test`; no routing change caused it.\n\nThe next line has non-ASCII text, the one after it a single dot:\nPolyWAN — prova ✓\n.\nEnd of the test.\n",
        host.map(|h| format!(" on {h}")).unwrap_or_default()
    )
}

/// The overall budget: the sendmail deadline plus every hook's timeout.
pub fn budget(notify: &Notify, times: Times) -> Duration {
    notify.hooks.iter().map(|h| h.timeout).sum::<Duration>() + times.deadline
}

/// Why a test did not start.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Another test runs (429).
    Busy,
    /// The email notifier stopped (503).
    Unavailable,
}

/// What the channels of a test share with the notifiers.
pub struct Channels {
    /// The email notifier's sendmail turn and Message-ID numbers.
    pub sendmail: Sendmail,
    /// The hooks' concurrency limit (FR-HOOK-3).
    pub slots: Arc<Semaphore>,
    pub instance: String,
    pub times: Times,
}

/// A channel's report, filled when it ends, and whether it started.
#[derive(Default)]
struct Slot {
    started: AtomicBool,
    report: Mutex<Option<Report>>,
}

impl Slot {
    fn set(&self, r: Report) {
        *self.report.lock().unwrap_or_else(|e| e.into_inner()) = Some(r);
    }
}

/// Runs a test through every configured channel within the budget.
pub async fn run(notify: &Notify, c: &Channels) -> Result<Vec<Report>, Refusal> {
    // FR-MAIL-4: admission first; a refusal starts nothing.
    if notify.email.is_some() && c.sendmail.turn.is_closed() {
        return Err(Refusal::Unavailable);
    }
    let mut tasks = tokio::task::JoinSet::new();
    let mut slots: Vec<(String, Option<String>, Arc<Slot>)> = Vec::new();
    if let Some(email) = &notify.email {
        let slot = Arc::new(Slot::default());
        slots.push(("email".into(), None, Arc::clone(&slot)));
        let (email, deadline, turn) = (email.clone(), c.times.deadline, Arc::clone(&c.sendmail.turn));
        let m = mail::test_message(&c.instance, c.sendmail.next_id(), &email);
        tasks.spawn(async move {
            // After a running submission, before the next due message.
            let Ok(_turn) = turn.acquire_owned().await else {
                return slot.set(Report::of("email", None, Err("the email notifier stopped".into())));
            };
            slot.started.store(true, Ordering::Relaxed);
            let run = mail::attempt(&m, &email, deadline).await.map_err(|e| e.to_string());
            slot.set(Report::of("email", None, run));
        });
    }
    if !notify.hooks.is_empty() {
        let user = crate::hooks::resolve_user(&notify.hook_user).await;
        let e = event(&c.instance);
        for hook in &notify.hooks {
            let program = hook.command.first().cloned();
            let slot = Arc::new(Slot::default());
            slots.push(("hook".into(), program.clone(), Arc::clone(&slot)));
            let spec = match &user {
                Ok(ids) => crate::hooks::spec(hook, &e, *ids).ok_or_else(|| "empty command".to_owned()),
                Err(e) => Err(e.clone()),
            };
            let permits = Arc::clone(&c.slots);
            tasks.spawn(async move {
                let spec = match spec {
                    Ok(s) => s,
                    Err(e) => return slot.set(Report::of("hook", program, Err(e))),
                };
                let Ok(_permit) = permits.acquire_owned().await else {
                    return;
                };
                slot.started.store(true, Ordering::Relaxed);
                slot.set(Report::of("hook", program, Ok(subprocess::run(&spec).await)));
            });
        }
    }
    let budget = budget(notify, c.times);
    let _ = tokio::time::timeout(budget, async { while tasks.join_next().await.is_some() {} }).await;
    // At the budget's end: what still runs is killed with its group.
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(slots
        .into_iter()
        .map(|(channel, program, slot)| {
            slot.report
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
                .unwrap_or_else(|| {
                    let outcome = if slot.started.load(Ordering::Relaxed) {
                        Outcome::TimedOut
                    } else {
                        Outcome::NotStarted
                    };
                    Report::new(&channel, program, outcome)
                })
        })
        .collect())
}

/// The daemon's tests: one at a time.
pub struct Tester {
    busy: AtomicBool,
    pub notify: watch::Receiver<Arc<Notify>>,
    pub channels: Channels,
}

/// Marks the end of a test.
pub struct Running(Arc<Tester>);

impl Drop for Running {
    fn drop(&mut self) {
        self.0.busy.store(false, Ordering::Release);
    }
}

impl Tester {
    pub fn new(notify: watch::Receiver<Arc<Notify>>, channels: Channels) -> Tester {
        Tester {
            busy: AtomicBool::new(false),
            notify,
            channels,
        }
    }

    /// Starts a test, unless one runs.
    pub fn begin(self: &Arc<Self>) -> Result<Running, Refusal> {
        self.busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Refusal::Busy)?;
        Ok(Running(Arc::clone(self)))
    }

    /// The budget of a test with the current configuration.
    pub fn budget(&self) -> Duration {
        budget(&self.notify.borrow(), self.channels.times)
    }

    /// Runs a test with the accepted configuration of this moment.
    pub async fn run(&self) -> Result<Vec<Report>, Refusal> {
        let notify = Arc::clone(&self.notify.borrow());
        run(&notify, &self.channels).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Hook;
    use crate::subprocess::Captured;

    fn notify(hooks: Vec<Hook>) -> Notify {
        Notify {
            coalesce: Duration::from_secs(30),
            email: None,
            hooks,
            hook_user: "nobody".into(),
        }
    }

    fn hook(command: &[&str], timeout_ms: u64) -> Hook {
        Hook {
            command: command.iter().map(|s| (*s).to_owned()).collect(),
            events: Some(vec!["daemon_started".into()]),
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    #[test]
    fn reports_carry_how_a_channel_ended() {
        let run = |end: End| {
            Report::of(
                "hook",
                Some("/x".into()),
                Ok(subprocess::Outcome {
                    end,
                    stdout: Captured::default(),
                    stderr: Captured {
                        data: b"oops".to_vec(),
                        truncated: true,
                    },
                }),
            )
        };
        let r = run(End::Exited(0));
        assert_eq!((r.outcome, r.exit_status), (Outcome::Succeeded, Some(0)));
        let r = run(End::Exited(3));
        assert_eq!(
            (r.outcome, r.exit_status, r.stderr.as_str(), r.stderr_truncated),
            (Outcome::Failed, Some(3), "oops", true)
        );
        let r = run(End::Signaled(9));
        assert_eq!((r.outcome, r.signal), (Outcome::Failed, Some(9)));
        assert_eq!(run(End::TimedOut).outcome, Outcome::TimedOut);
        let r = Report::of("email", None, Err("untrusted".into()));
        assert_eq!((r.outcome, r.error.as_deref()), (Outcome::Failed, Some("untrusted")));
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["outcome"], "failed");
        assert!(json.get("program").is_none());
    }

    #[test]
    fn the_budget_and_the_message() {
        let n = notify(vec![hook(&["/bin/true"], 2000), hook(&["/bin/true"], 3000)]);
        assert_eq!(budget(&n, Times::default()), Duration::from_secs(65));
        let body = body(Some("gw"));
        assert!(body.contains(" on gw,"), "{body}");
        assert!(body.lines().any(|l| l == "."), "a lone dot");
        assert!(!body.is_ascii(), "non-ASCII text");
        let e = event("abc");
        assert_eq!((e.kind, e.test, e.seq), ("notify_test", true, 0));
        assert_eq!(serde_json::to_value(&e).unwrap()["test"], true);
    }

    #[tokio::test]
    async fn channels_not_started_within_the_budget_are_reported() {
        let times = Times {
            minute: Duration::from_secs(60),
            deadline: Duration::from_millis(100),
        };
        // No permit: the hook waits beyond the budget (0.2 s).
        let channels = |permits: usize| Channels {
            sendmail: Sendmail::default(),
            slots: Arc::new(Semaphore::new(permits)),
            instance: "abc".into(),
            times,
        };
        let r = run(&notify(vec![hook(&["/bin/true"], 100)]), &channels(0))
            .await
            .unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(
            (r[0].outcome, r[0].program.as_deref()),
            (Outcome::NotStarted, Some("/bin/true"))
        );
        let none = run(&notify(Vec::new()), &channels(1)).await.unwrap();
        assert!(none.is_empty());
    }
}
