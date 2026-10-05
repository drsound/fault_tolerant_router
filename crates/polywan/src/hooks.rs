//! Hooks (SPEC.md §8.3, FR-HOOK-1 to FR-HOOK-4): every configured command
//! whose filter selects an event runs with the event as JSON on standard
//! input and as `POLYWAN_*` variables, as `hook_user` with its primary group,
//! in a new process group killed at the timeout, at most four at a time.
//!
//! The notifier runs on the I/O runtime and reads its own bounded queue of
//! the event bus: when every slot is busy the queue fills and the bus drops
//! and counts further events (FR-EV-3); routing never waits (FR-HOOK-4).

use std::sync::Arc;

use serde_json::Value;
use tokio::sync::{Semaphore, watch};
use tracing::{info, warn};

use crate::config::{Hook, Notify};
use crate::events::{Event, Queue};
use crate::subprocess::{self, End, Spec};

/// Hooks running at the same time (FR-HOOK-3).
pub const CONCURRENCY: usize = 4;
/// Events waiting for the hooks (FR-EV-3).
pub const QUEUE: usize = 256;

/// The environment of a hook run (FR-HOOK-2): strings as they are, other
/// values as JSON, absent fields empty.
pub fn environment(e: &Event) -> Vec<(String, String)> {
    let text = |v: &Option<Value>| match v {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    };
    vec![
        ("POLYWAN_EVENT".into(), e.kind.to_owned()),
        ("POLYWAN_UPLINK".into(), e.uplink.clone().unwrap_or_default()),
        ("POLYWAN_FAMILY".into(), e.family.unwrap_or_default().to_owned()),
        ("POLYWAN_OLD".into(), text(&e.old)),
        ("POLYWAN_NEW".into(), text(&e.new)),
        ("POLYWAN_REASON".into(), e.reason.clone().unwrap_or_default()),
    ]
}

/// Whether a hook's filter selects an event type.
pub fn selects(hook: &Hook, kind: &str) -> bool {
    hook.events.as_ref().is_none_or(|list| list.iter().any(|k| k == kind))
}

/// The run of one hook for one event.
pub fn spec(hook: &Hook, event: &Event, user: (u32, u32)) -> Option<Spec> {
    let (program, args) = hook.command.split_first()?;
    Some(Spec {
        program: program.into(),
        args: args.to_vec(),
        env: environment(event),
        uid: user.0,
        gid: user.1,
        input: serde_json::to_vec(event).unwrap_or_default(),
        capture_stdout: true,
        timeout: hook.timeout,
    })
}

/// Runs a hook and logs how it ended, with its output (FR-HOOK-3).
pub async fn run_logged(spec: Spec, kind: &str) -> End {
    let program = spec.program.display().to_string();
    let o = subprocess::run(&spec).await;
    if o.end.success() {
        info!(hook = %program, event = kind, stdout = %o.stdout.escaped(), stderr = %o.stderr.escaped(), "hook finished");
    } else {
        warn!(hook = %program, event = kind, end = %o.end, stdout = %o.stdout.escaped(), stderr = %o.stderr.escaped(), "hook failed");
    }
    o.end
}

/// The hooks notifier: `events` from the bus, the notification settings
/// from `config` (changed by reloads).
/// `slots` is the concurrency limit, shared with notification tests.
pub async fn notifier(mut events: Queue, mut config: watch::Receiver<Arc<Notify>>, slots: Arc<Semaphore>) {
    let mut user: Option<(String, (u32, u32))> = None;
    while let Some(event) = events.recv().await {
        let notify = Arc::clone(&config.borrow_and_update());
        let wanted: Vec<&Hook> = notify.hooks.iter().filter(|h| selects(h, event.kind)).collect();
        if wanted.is_empty() {
            continue;
        }
        // The hook user, resolved again when it changes (a reload).
        if user.as_ref().is_none_or(|(name, _)| *name != notify.hook_user) {
            let name = notify.hook_user.clone();
            let found = tokio::task::spawn_blocking(move || crate::identity::user(&name))
                .await
                .ok()
                .and_then(Result::ok)
                .flatten();
            match found {
                Some(u) => user = Some((notify.hook_user.clone(), (u.uid, u.gid))),
                None => {
                    warn!(user = %notify.hook_user, "hook user not found: hooks not run");
                    user = None;
                    continue;
                }
            }
        }
        let Some((_, ids)) = user else { continue };
        for hook in wanted {
            let Some(spec) = spec(hook, &event, ids) else { continue };
            // FR-HOOK-3: at most four at a time; waiting here lets the
            // queue fill, never the State task.
            let Ok(permit) = Arc::clone(&slots).acquire_owned().await else {
                return;
            };
            let kind = event.kind;
            tokio::spawn(async move {
                run_logged(spec, kind).await;
                drop(permit);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn event() -> Event {
        Event {
            seq: 3,
            instance: "i".into(),
            timestamp: "t".into(),
            kind: "active_set_changed",
            uplink: None,
            family: Some("ipv4"),
            old: Some(serde_json::json!(["a", "b"])),
            new: Some(serde_json::json!(["a"])),
            reason: None,
            message: "m".into(),
            test: false,
        }
    }

    #[test]
    fn the_environment_carries_the_event() {
        let env = environment(&event());
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("POLYWAN_EVENT"), Some("active_set_changed"));
        assert_eq!(get("POLYWAN_UPLINK"), Some(""));
        assert_eq!(get("POLYWAN_FAMILY"), Some("ipv4"));
        assert_eq!(get("POLYWAN_OLD"), Some(r#"["a","b"]"#));
        assert_eq!(get("POLYWAN_NEW"), Some(r#"["a"]"#));
    }

    #[test]
    fn filters_select_event_types() {
        let mut h = Hook {
            command: vec!["/bin/true".into()],
            events: None,
            timeout: Duration::from_secs(1),
        };
        assert!(selects(&h, "daemon_started"));
        h.events = Some(vec!["path_state_changed".into()]);
        assert!(selects(&h, "path_state_changed"));
        assert!(!selects(&h, "daemon_started"));
        let s = spec(&h, &event(), (65534, 65534)).unwrap();
        assert_eq!((s.uid, s.gid, s.timeout), (65534, 65534, Duration::from_secs(1)));
        let input: Value = serde_json::from_slice(&s.input).unwrap();
        assert_eq!(input["type"], "active_set_changed");
    }
}
