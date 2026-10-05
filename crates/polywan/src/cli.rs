//! The CLI commands that use the API (§9): they read only the socket, never
//! the configuration, so that they need no access to the root-owned file.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use hyper::{Method, StatusCode};
use serde_json::Value;

use crate::api::{self, client};

/// `println!` for the CLI's output: a closed standard output (`polywan
/// status | head -1`) ends the process quietly with the status of a
/// SIGPIPE death, where `println!` would panic (resetting SIGPIPE needs
/// unsafe code).
#[macro_export]
macro_rules! say {
    ($($arg:tt)*) => {
        $crate::cli::write_stdout(format_args!($($arg)*), true)
    };
}

/// See [`say!`]; `newline: false` writes the text as it is.
pub fn write_stdout(args: std::fmt::Arguments<'_>, newline: bool) {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    let written = out
        .write_fmt(args)
        .and_then(|()| if newline { out.write_all(b"\n") } else { Ok(()) })
        .and_then(|()| out.flush());
    if let Err(e) = written {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            std::process::exit(141);
        }
        eprintln!("polywan: writing the output: {e}");
        std::process::exit(1);
    }
}

/// Reads and validates a configuration file, for the commands that need it.
pub fn load(path: &Path) -> Result<crate::config::Config> {
    crate::config::load(path).map_err(|e| anyhow::anyhow!("{e}"))
}

/// The server's message in an error response.
fn error_text(v: &Value) -> &str {
    v.get("error").and_then(Value::as_str).unwrap_or("request failed")
}

/// `GET` on a socket, as JSON; any status but 200 is an error with the
/// server's message.
async fn get(socket: &Path, path: &str, timeout: Duration) -> Result<Value> {
    let (status, body) = client::request(socket, Method::GET, path, None, timeout)
        .await
        .with_context(|| socket.display().to_string())?;
    let v: Value = serde_json::from_slice(&body).context("the response is not JSON")?;
    if !status.is_success() {
        bail!("{}: {}", status, error_text(&v));
    }
    Ok(v)
}

/// `POST` on the control socket: the status and the JSON body (`null` if
/// the body is not JSON).
async fn post(
    socket: &Path,
    path: &str,
    body: Option<String>,
    timeout: Duration,
) -> Result<(StatusCode, Value), client::Error> {
    let (status, body) = client::request(socket, Method::POST, path, body, timeout).await?;
    Ok((status, serde_json::from_slice(&body).unwrap_or_default()))
}

pub async fn status(socket: &Path, json: bool) -> Result<()> {
    let s = get(socket, "/v1/status", api::DEADLINE).await?;
    if json {
        crate::say!("{s}");
        return Ok(());
    }
    let text = |v: &Value| v.as_str().unwrap_or("").to_owned();
    let uptime = s["uptime_seconds"].as_u64().unwrap_or(0);
    crate::say!(
        "polywan {}, up {}h {:02}m, status {}{}",
        text(&s["version"]),
        uptime / 3600,
        uptime % 3600 / 60,
        text(&s["status"]),
        match s["reasons"].as_array() {
            Some(r) if !r.is_empty() => format!(" ({})", r.iter().map(text).collect::<Vec<_>>().join(", ")),
            _ => String::new(),
        }
    );
    crate::say!(
        "generation: desired {}, applied {}",
        s["generation"]["desired"],
        s["generation"]["applied"]
    );
    if let Some(active) = s["active"].as_object() {
        for (family, set) in active {
            let names: Vec<String> = set.as_array().into_iter().flatten().map(text).collect();
            crate::say!(
                "active {family}: {}",
                if names.is_empty() {
                    "none".into()
                } else {
                    names.join(", ")
                }
            );
        }
    }
    for u in s["uplinks"].as_array().into_iter().flatten() {
        let drained = if u["drained"].as_bool() == Some(true) {
            ", drained"
        } else {
            ""
        };
        crate::say!(
            "uplink {} (id {}, {}){drained}",
            text(&u["name"]),
            u["id"],
            text(&u["interface"])
        );
        for p in s["paths"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|p| p["uplink"] == u["name"])
        {
            let family = text(&p["family"]);
            let active = s["active"][&family]
                .as_array()
                .is_some_and(|set| set.iter().any(|n| *n == u["name"]));
            let mut line = format!(
                "  {family}: {} ({}) since {}, {}, {}",
                text(&p["state"]),
                text(&p["reason"]),
                text(&p["since"]),
                if p["ready"].as_bool() == Some(true) {
                    "ready"
                } else {
                    "not ready"
                },
                if active { "active" } else { "not active" }
            );
            if let Some(src) = p["source"].as_str() {
                line += &format!(", source {src}");
            }
            if let Some(gw) = p["gateway"].as_str() {
                line += &format!(" via {gw}");
            }
            let st = &p["statistics"];
            if let Some(rtt) = st["rtt_seconds"].as_f64() {
                line += &format!(", rtt {:.1} ms", rtt * 1000.0);
            }
            if let Some(j) = st["jitter_seconds"].as_f64() {
                line += &format!(", jitter {:.1} ms", j * 1000.0);
            }
            if let Some(l) = st["loss"].as_f64() {
                line += &format!(", loss {:.0}%", l * 100.0);
            }
            crate::say!("{line}");
        }
    }
    Ok(())
}

fn print_event(e: &Value) {
    let text = |k: &str| e[k].as_str().unwrap_or("");
    crate::say!(
        "{} #{} {} {}",
        text("timestamp"),
        e["seq"],
        text("type"),
        text("message")
    );
}

/// `events`: the history, then with `follow` each new event; with `json`,
/// one JSON object per line: the events as the API returns them, and a
/// `notice` record for a restart (`reset`) or evicted events (`truncated`).
pub async fn events(socket: &Path, follow: bool, json: bool) -> Result<()> {
    let mut instance: Option<String> = None;
    let mut after: Option<u64> = None;
    loop {
        let mut query = Vec::new();
        if let Some(i) = &instance {
            query.push(format!("instance={i}"));
        }
        if let Some(a) = after {
            query.push(format!("after={a}"));
        }
        let wait = if follow && instance.is_some() {
            api::MAX_WAIT
        } else {
            Duration::ZERO
        };
        if !wait.is_zero() {
            query.push(format!("wait={}", wait.as_secs()));
        }
        let path = format!("/v1/events?{}", query.join("&"));
        let page = get(socket, &path, api::DEADLINE + wait).await?;
        let notice = |kind: &str, text: &str| {
            if json {
                crate::say!("{}", serde_json::json!({"notice": kind, "instance": page["instance"]}));
            } else {
                crate::say!("({text})");
            }
        };
        if instance.is_some() && page["reset"].as_bool() == Some(true) {
            notice("reset", "the daemon restarted: events from the start of its history");
        }
        if page["truncated"].as_bool() == Some(true) {
            notice("truncated", "older events were evicted from the history");
        }
        instance = page["instance"].as_str().map(str::to_owned);
        let events = page["events"].as_array().cloned().unwrap_or_default();
        for e in &events {
            if json {
                crate::say!("{e}");
            } else {
                print_event(e);
            }
            after = e["seq"].as_u64().or(after);
        }
        // A full page may have more behind it.
        if !follow && events.len() < crate::events::RING_EVENTS {
            return Ok(());
        }
    }
}

/// `drain` and `undrain` (FR-API-3): complete only once applied.
pub async fn drain(socket: &Path, name: &str, drain: bool, force: bool) -> Result<()> {
    if !crate::config::valid_uplink_name(name) {
        bail!("{name:?} is not an uplink name");
    }
    let action = if drain { "drain" } else { "undrain" };
    let body = (drain && force).then(|| r#"{"force": true}"#.to_owned());
    let (status, v) = post(socket, &format!("/v1/uplinks/{name}/{action}"), body, api::DEADLINE)
        .await
        .with_context(|| socket.display().to_string())?;
    if status != StatusCode::OK {
        let steps = v
            .get("failed_steps")
            .map(|s| format!(" (failed steps: {s})"))
            .unwrap_or_default();
        bail!("{action} {name}: {status}: {}{steps}", error_text(&v));
    }
    crate::say!(
        "uplink {name} {}, applied in generation {}",
        if drain { "drained" } else { "undrained" },
        v["generation"]
    );
    Ok(())
}

/// `reload` (FR-API-3): the validation errors, or the applied generation.
pub async fn reload(socket: &Path) -> Result<()> {
    let (status, v) = match post(socket, "/v1/reload", None, api::DEADLINE).await {
        Ok(answer) => answer,
        // A reload that changes the control socket's path or access closes
        // this connection when it commits, before the answer (IMPL-10).
        Err(client::Error::Exchange(e)) => bail!(
            "{}: no answer ({e}): the outcome of the reload is unknown; a change of the control socket's path or access closes the connection that requested it, and `polywan events` shows config_reloaded or reload_failed",
            socket.display()
        ),
        Err(e) => return Err(e).with_context(|| socket.display().to_string()),
    };
    if status != StatusCode::OK {
        let mut message = format!("reload: {status}: {}", error_text(&v));
        for e in v.get("errors").and_then(Value::as_array).into_iter().flatten() {
            message += &format!("\n{}", e.as_str().unwrap_or_default());
        }
        if let Some(steps) = v.get("failed_steps") {
            message += &format!("\nfailed steps: {steps}");
        }
        bail!("{message}");
    }
    crate::say!("configuration reloaded, applied in generation {}", v["generation"]);
    Ok(())
}

/// `forget-uplink` (FR-MARK-4, §9): through the control socket while the
/// daemon runs; offline only when no daemon listens, never after a
/// permission or protocol failure.
pub async fn forget(socket: &Path, name: &str, config: &Path, lock: &Path) -> Result<()> {
    if !crate::config::valid_uplink_name(name) {
        bail!("{name:?} is not an uplink name");
    }
    match post(socket, &format!("/v1/uplinks/{name}/forget"), None, api::DEADLINE).await {
        Ok((status, v)) => {
            if status != StatusCode::OK {
                bail!("forget {name}: {status}: {}", error_text(&v));
            }
            crate::say!("uplink {name:?} forgotten; id {} can be reused", v["id"]);
            Ok(())
        }
        Err(client::Error::Connect(e))
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            forget_offline(config, name, lock)
        }
        Err(e) => Err(anyhow::anyhow!("{}: {e} (not retried offline)", socket.display())),
    }
}

/// Offline: root, the configuration and the instance lock (FR-MARK-4).
fn forget_offline(path: &Path, name: &str, lock: &Path) -> Result<()> {
    let cfg = load(path)?;
    let _lock = crate::state::InstanceLock::acquire(lock).map_err(|e| anyhow::anyhow!("{e}; stop the daemon first"))?;
    let dir = crate::state::StateDir {
        path: cfg.state_dir.clone(),
    };
    let mut m = dir
        .manifest()?
        .ok_or_else(|| anyhow::anyhow!("no manifest in {}", cfg.state_dir.display()))?;
    if cfg.uplinks.iter().any(|u| u.name == name) {
        bail!("uplink {name:?} is still in the configuration; remove it first");
    }
    let id = m.forget(name).map_err(|e| anyhow::anyhow!(e))?;
    dir.write_manifest(&m)?;
    crate::say!("uplink {name:?} forgotten; id {id} can be reused");
    Ok(())
}

/// Prints a test's reports; an error if a channel did not succeed or none
/// is configured (FR-MAIL-4).
pub fn print_reports(reports: &[crate::notifytest::Report]) -> Result<()> {
    use crate::notifytest::Outcome;
    if reports.is_empty() {
        bail!("no notification channel is configured");
    }
    let mut failed = 0;
    for r in reports {
        let name = match &r.program {
            Some(p) => format!("{} {p}", r.channel),
            None => r.channel.clone(),
        };
        let mut line = format!(
            "{name}: {}",
            match r.outcome {
                Outcome::Succeeded => "succeeded",
                Outcome::Failed => "failed",
                Outcome::TimedOut => "timed out",
                Outcome::NotStarted => "not started",
            }
        );
        if let Some(c) = r.exit_status.filter(|c| *c != 0) {
            line += &format!(", exit status {c}");
        }
        if let Some(s) = r.signal {
            line += &format!(", killed by signal {s}");
        }
        if let Some(e) = &r.error {
            line += &format!(": {e}");
        }
        crate::say!("{line}");
        for l in r.stderr.lines() {
            crate::say!("  stderr: {l}");
        }
        if r.stderr_truncated {
            crate::say!("  stderr: [truncated]");
        }
        if r.outcome != Outcome::Succeeded {
            failed += 1;
        }
    }
    if failed > 0 {
        bail!("{failed} of {} channels failed", reports.len());
    }
    Ok(())
}

/// How long `notify-test` waits: the daemon bounds the test by its budget
/// (60 s plus the hooks' timeouts), which the client cannot know without
/// reading the configuration.
const NOTIFY_TEST_WAIT: Duration = Duration::from_secs(3600);

/// `notify-test` (FR-MAIL-4), through the control socket.
pub async fn notify_test(socket: &Path) -> Result<()> {
    let (status, v) = post(socket, "/v1/notify-test", None, NOTIFY_TEST_WAIT)
        .await
        .with_context(|| socket.display().to_string())?;
    if status != StatusCode::OK {
        bail!("notify-test: {status}: {}", error_text(&v));
    }
    let reports: Vec<crate::notifytest::Report> =
        serde_json::from_value(v["channels"].clone()).context("the response has no channel reports")?;
    print_reports(&reports)
}

/// `notify-test --offline` (FR-MAIL-4): as root, with trusted executables
/// and the instance lock, outside the service's sandbox.
pub async fn notify_test_offline(path: &Path, lock: &Path) -> Result<()> {
    if !nix::unistd::geteuid().is_root() {
        bail!("notify-test --offline needs root");
    }
    let cfg = load(path)?;
    let errors = crate::checks::runnable(path, &cfg, &crate::subprocess::inherited_descriptors()).errors();
    if let Some(e) = errors.first() {
        bail!("{e}");
    }
    let _lock = crate::state::InstanceLock::acquire(lock)
        .map_err(|e| anyhow::anyhow!("{e}; while the daemon runs, use notify-test without --offline"))?;
    eprintln!(
        "WARNING: offline test: the service's sandbox was not exercised; only `polywan notify-test` through the daemon tests it"
    );
    let channels = crate::notifytest::Channels {
        sendmail: crate::mail::Sendmail::default(),
        slots: std::sync::Arc::new(tokio::sync::Semaphore::new(crate::hooks::CONCURRENCY)),
        instance: crate::events::instance_id(),
        times: crate::test_hooks::mail_times(crate::mail::Times::default()),
    };
    let reports = crate::notifytest::run(&cfg.notify, &channels)
        .await
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    print_reports(&reports)
}
