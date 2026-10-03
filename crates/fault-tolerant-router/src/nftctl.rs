//! Running `nft` (IMPL-3): atomic application with a deadline and bounded
//! stderr capture, JSON listings and their normalisation (FR-REC-6).

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use crate::nft::TABLE;

pub const DEADLINE: Duration = Duration::from_secs(10);
const CAPTURE: usize = 64 * 1024;

/// Runs `nft` with arguments and optional standard input; returns stdout.
pub async fn run(nft: &Path, args: &[&str], input: Option<&str>) -> Result<String, String> {
    let mut child = Command::new(nft)
        .args(args)
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("cannot run {}: {e}", nft.display()))?;
    let mut stdin = child.stdin.take();
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let work = async {
        if let (Some(mut i), Some(text)) = (stdin.take(), input) {
            i.write_all(text.as_bytes())
                .await
                .map_err(|e| format!("writing to nft: {e}"))?;
        }
        let mut out = Vec::new();
        let mut err = Vec::new();
        let read_out = async {
            if let Some(o) = stdout.as_mut() {
                let _ = o.read_to_end(&mut out).await;
            }
        };
        let read_err = async {
            if let Some(e) = stderr.as_mut() {
                let _ = e.take(CAPTURE as u64).read_to_end(&mut err).await;
            }
        };
        tokio::join!(read_out, read_err);
        let status = child.wait().await.map_err(|e| format!("waiting for nft: {e}"))?;
        Ok::<_, String>((status, out, err))
    };
    match tokio::time::timeout(DEADLINE, work).await {
        Err(_) => Err(format!("nft did not finish within {} s", DEADLINE.as_secs())),
        Ok(Err(e)) => Err(e),
        Ok(Ok((status, out, err))) if status.success() => {
            let _ = err;
            Ok(String::from_utf8_lossy(&out).into_owned())
        }
        Ok(Ok((status, _, err))) => Err(format!(
            "nft failed ({status}): {}",
            String::from_utf8_lossy(&err).trim()
        )),
    }
}

/// Applies a transaction (`nft -f -`).
pub async fn apply(nft: &Path, transaction: &str) -> Result<(), String> {
    run(nft, &["-f", "-"], Some(transaction)).await.map(|_| ())
}

/// The normalised JSON listing of FTR's table, `None` if it does not exist.
pub async fn table(nft: &Path) -> Result<Option<Value>, String> {
    match run(nft, &["-j", "list", "table", "inet", TABLE], None).await {
        Ok(text) => {
            let v: Value = serde_json::from_str(&text).map_err(|e| format!("nft JSON: {e}"))?;
            Ok(Some(normalize(v)))
        }
        Err(e) if e.contains("No such file or directory") || e.contains("does not exist") => Ok(None),
        Err(e) => Err(e),
    }
}

/// The JSON listing of the flowtables only (FR-CT-2 runtime inspection): the
/// same objects as in the ruleset, without dumping large sets.
pub async fn flowtables(nft: &Path) -> Result<Value, String> {
    let text = run(nft, &["-j", "list", "flowtables"], None).await?;
    serde_json::from_str(&text).map_err(|e| format!("nft JSON: {e}"))
}

/// The JSON listing of the whole ruleset (read-only checks).
pub async fn ruleset(nft: &Path) -> Result<Value, String> {
    let text = run(nft, &["-j", "list", "ruleset"], None).await?;
    serde_json::from_str(&text).map_err(|e| format!("nft JSON: {e}"))
}

/// Removes the `metainfo` object and every `handle` (S2 F9): the listing of
/// an identical table then compares equal across replacements.
pub fn normalize(mut v: Value) -> Value {
    fn strip(v: &mut Value) {
        match v {
            Value::Object(m) => {
                m.remove("handle");
                for x in m.values_mut() {
                    strip(x);
                }
            }
            Value::Array(a) => {
                a.retain(|x| x.get("metainfo").is_none());
                for x in a {
                    strip(x);
                }
            }
            _ => {}
        }
    }
    strip(&mut v);
    v
}

/// Interfaces listed by flowtables, by table (FR-CT-2). A single device is
/// a string in the JSON listing, several are an array (S2 F14).
pub fn flowtable_devices(ruleset: &Value) -> Vec<(String, String)> {
    let mut v = Vec::new();
    for o in ruleset.get("nftables").and_then(Value::as_array).into_iter().flatten() {
        let Some(ft) = o.get("flowtable") else { continue };
        let name = format!(
            "{} {} {}",
            ft.get("family").and_then(Value::as_str).unwrap_or("?"),
            ft.get("table").and_then(Value::as_str).unwrap_or("?"),
            ft.get("name").and_then(Value::as_str).unwrap_or("?")
        );
        match ft.get("dev") {
            Some(Value::String(d)) => v.push((name, d.clone())),
            Some(Value::Array(a)) => v.extend(a.iter().filter_map(Value::as_str).map(|d| (name.clone(), d.to_owned()))),
            _ => {}
        }
    }
    v
}

/// Statements of other tables, as (family table chain, statement key).
fn statements(ruleset: &Value) -> Vec<(String, &Value)> {
    let mut v = Vec::new();
    for o in ruleset.get("nftables").and_then(Value::as_array).into_iter().flatten() {
        let Some(rule) = o.get("rule") else { continue };
        if rule.get("table").and_then(Value::as_str) == Some(TABLE) {
            continue;
        }
        let place = format!(
            "{} {} {}",
            rule.get("family").and_then(Value::as_str).unwrap_or("?"),
            rule.get("table").and_then(Value::as_str).unwrap_or("?"),
            rule.get("chain").and_then(Value::as_str).unwrap_or("?")
        );
        for s in rule.get("expr").and_then(Value::as_array).into_iter().flatten() {
            v.push((place.clone(), s));
        }
    }
    v
}

/// Chains of other tables with `notrack` (FR-CT-1, best effort).
pub fn notrack_chains(ruleset: &Value) -> Vec<String> {
    let mut v: Vec<String> = statements(ruleset)
        .into_iter()
        .filter(|(_, s)| s.get("notrack").is_some())
        .map(|(p, _)| p)
        .collect();
    v.dedup();
    v
}

/// Chains of other tables with source NAT (FR-NAT-4, best effort; the check
/// does not evaluate which interfaces the rules match).
pub fn source_nat_chains(ruleset: &Value) -> Vec<String> {
    let mut v: Vec<String> = statements(ruleset)
        .into_iter()
        .filter(|(_, s)| s.get("masquerade").is_some() || s.get("snat").is_some())
        .map(|(p, _)| p)
        .collect();
    v.dedup();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalisation_removes_handles_and_metainfo() {
        let a: Value = serde_json::from_str(
            r#"{"nftables":[{"metainfo":{"version":"1.1.3"}},{"table":{"family":"inet","name":"t","handle":7}},{"rule":{"chain":"c","handle":3,"expr":[{"return":null}]}}]}"#,
        )
        .unwrap();
        let b: Value = serde_json::from_str(
            r#"{"nftables":[{"metainfo":{"version":"1.0.6","json_schema_version":1}},{"table":{"family":"inet","name":"t","handle":9}},{"rule":{"chain":"c","handle":4,"expr":[{"return":null}]}}]}"#,
        )
        .unwrap();
        assert_eq!(normalize(a), normalize(b));
    }

    #[test]
    fn flowtable_devices_in_both_json_forms() {
        let r: Value = serde_json::from_str(
            r#"{"nftables":[{"flowtable":{"family":"inet","table":"f","name":"ft","dev":"wan0"}},{"flowtable":{"family":"inet","table":"f","name":"ft2","dev":["lan","wan1"]}}]}"#,
        )
        .unwrap();
        let d = flowtable_devices(&r);
        assert_eq!(
            d.iter().map(|(_, x)| x.as_str()).collect::<Vec<_>>(),
            ["wan0", "lan", "wan1"]
        );
        assert_eq!(d[0].0, "inet f ft");
    }

    #[test]
    fn notrack_and_nat_of_other_tables_are_found() {
        let r: Value = serde_json::from_str(
            r#"{"nftables":[{"rule":{"family":"inet","table":"raw","chain":"pre","expr":[{"notrack":null}]}},{"rule":{"family":"ip","table":"nat","chain":"post","expr":[{"masquerade":null}]}},{"rule":{"family":"inet","table":"fault_tolerant_router","chain":"nat","expr":[{"masquerade":null}]}}]}"#,
        )
        .unwrap();
        assert_eq!(notrack_chains(&r), ["inet raw pre"]);
        assert_eq!(source_nat_chains(&r), ["ip nat post"]);
    }
}
