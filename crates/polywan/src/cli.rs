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
