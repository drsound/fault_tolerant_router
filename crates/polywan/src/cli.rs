//! The CLI commands that use the API (§9): they read only the socket, never
//! the configuration, so that they need no access to the root-owned file.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use hyper::Method;
use serde_json::Value;

use crate::api::{self, client};

/// `GET` on a socket, as JSON; any status but 200 is an error with the
/// server's message.
async fn get(socket: &Path, path: &str, timeout: Duration) -> Result<Value> {
    let (status, body) = client::request(socket, Method::GET, path, None, timeout)
        .await
        .with_context(|| socket.display().to_string())?;
    let v: Value = serde_json::from_slice(&body).context("the response is not JSON")?;
    if !status.is_success() {
        bail!(
            "{}: {}",
            status,
            v.get("error").and_then(Value::as_str).unwrap_or("request failed")
        );
    }
    Ok(v)
}

pub async fn status(socket: &Path, json: bool) -> Result<()> {
    let s = get(socket, "/v1/status", api::DEADLINE).await?;
    if json {
        println!("{s}");
        return Ok(());
    }
    let text = |v: &Value| v.as_str().unwrap_or("").to_owned();
    let uptime = s["uptime_seconds"].as_u64().unwrap_or(0);
    println!(
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
    println!(
        "generation: desired {}, applied {}",
        s["generation"]["desired"], s["generation"]["applied"]
    );
    if let Some(active) = s["active"].as_object() {
        for (family, set) in active {
            let names: Vec<String> = set.as_array().into_iter().flatten().map(text).collect();
            println!(
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
        println!(
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
            let mut line = format!(
                "  {}: {} ({}) since {}",
                text(&p["family"]),
                text(&p["state"]),
                text(&p["reason"]),
                text(&p["since"])
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
            println!("{line}");
        }
    }
    Ok(())
}

fn print_event(e: &Value) {
    let text = |k: &str| e[k].as_str().unwrap_or("");
    println!(
        "{} #{} {} {}",
        text("timestamp"),
        e["seq"],
        text("type"),
        text("message")
    );
}

pub async fn events(socket: &Path, follow: bool) -> Result<()> {
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
        if instance.is_some() && page["reset"].as_bool() == Some(true) {
            println!("(the daemon restarted: events from the start of its history)");
        }
        if page["truncated"].as_bool() == Some(true) {
            println!("(older events were evicted from the history)");
        }
        instance = page["instance"].as_str().map(str::to_owned);
        let events = page["events"].as_array().cloned().unwrap_or_default();
        for e in &events {
            print_event(e);
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
    let (status, body) = client::request(
        socket,
        Method::POST,
        &format!("/v1/uplinks/{name}/{action}"),
        body,
        api::DEADLINE,
    )
    .await
    .with_context(|| socket.display().to_string())?;
    let v: Value = serde_json::from_slice(&body).unwrap_or_default();
    let message = v.get("error").and_then(Value::as_str).unwrap_or("request failed");
    if status != hyper::StatusCode::OK {
        let steps = v
            .get("failed_steps")
            .map(|s| format!(" (failed steps: {s})"))
            .unwrap_or_default();
        bail!("{action} {name}: {status}: {message}{steps}");
    }
    println!(
        "uplink {name} {}, applied in generation {}",
        if drain { "drained" } else { "undrained" },
        v["generation"]
    );
    Ok(())
}

/// `reload` (FR-API-3): the validation errors, or the applied generation.
pub async fn reload(socket: &Path) -> Result<()> {
    let (status, body) = client::request(socket, Method::POST, "/v1/reload", None, api::DEADLINE)
        .await
        .with_context(|| socket.display().to_string())?;
    let v: Value = serde_json::from_slice(&body).unwrap_or_default();
    if status != hyper::StatusCode::OK {
        let mut message = format!(
            "reload: {status}: {}",
            v.get("error").and_then(Value::as_str).unwrap_or("request failed")
        );
        for e in v.get("errors").and_then(Value::as_array).into_iter().flatten() {
            message += &format!("\n{}", e.as_str().unwrap_or_default());
        }
        if let Some(steps) = v.get("failed_steps") {
            message += &format!("\nfailed steps: {steps}");
        }
        bail!("{message}");
    }
    println!("configuration reloaded, applied in generation {}", v["generation"]);
    Ok(())
}

/// `forget-uplink` (FR-MARK-4, §9): through the control socket while the
/// daemon runs; offline only when no daemon listens, never after a
/// permission or protocol failure.
pub async fn forget(socket: &Path, name: &str, config: &Path, lock: &Path) -> Result<()> {
    if !crate::config::valid_uplink_name(name) {
        bail!("{name:?} is not an uplink name");
    }
    let r = client::request(
        socket,
        Method::POST,
        &format!("/v1/uplinks/{name}/forget"),
        None,
        api::DEADLINE,
    )
    .await;
    match r {
        Ok((status, body)) => {
            let v: Value = serde_json::from_slice(&body).unwrap_or_default();
            if status != hyper::StatusCode::OK {
                bail!(
                    "forget {name}: {status}: {}",
                    v.get("error").and_then(Value::as_str).unwrap_or("request failed")
                );
            }
            println!("uplink {name:?} forgotten; id {} can be reused", v["id"]);
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
    let cfg = crate::config::load(path).map_err(|e| anyhow::anyhow!("{e}"))?;
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
    println!("uplink {name:?} forgotten; id {id} can be reused");
    Ok(())
}
