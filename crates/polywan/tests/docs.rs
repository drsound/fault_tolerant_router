//! The configurations shown in the documentation (`docs/`) are validated as
//! `check-config --offline` validates a file, and every key the parser
//! accepts is described in the configuration reference (DIST-3).
//!
//! A TOML block with both `[[downlink]]` and `[[uplink]]` is a complete
//! configuration; any other is a fragment, laid over the packaged example
//! (its tables merged, its other values, arrays of tables included,
//! replacing the example's) before validation.

use std::path::{Path, PathBuf};

use toml::{Table, Value};

/// The documentation of the source tree; the published crate has none.
fn docs() -> Option<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    root.join("SPEC.md").is_file().then(|| root.join("docs"))
}

fn pages(dir: &Path) -> Vec<PathBuf> {
    let mut v = Vec::new();
    for e in std::fs::read_dir(dir).expect("docs/ is readable").flatten() {
        let p = e.path();
        if p.is_dir() {
            v.extend(pages(&p));
        } else if p.extension().is_some_and(|x| x == "md") {
            v.push(p);
        }
    }
    v.sort();
    v
}

/// The TOML blocks of a page, with the line of each opening fence; blocks
/// indented in lists lose the fence's indentation.
fn blocks(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut open: Option<(usize, usize, String)> = None;
    for (i, line) in text.lines().enumerate() {
        let indent = line.len() - line.trim_start().len();
        let fence = line.trim_start().starts_with("```");
        match &mut open {
            None if line.trim_start().starts_with("```toml") => open = Some((i + 1, indent, String::new())),
            Some(_) if fence => {
                let (start, _, block) = open.take().expect("open");
                out.push((start, block));
            }
            Some((_, indent, block)) => {
                block.push_str(line.get(*indent..).unwrap_or("").trim_end_matches(' '));
                block.push('\n');
            }
            None => {}
        }
    }
    out
}

fn merge(base: &mut Table, over: Table) {
    for (k, v) in over {
        match (base.get_mut(&k), v) {
            (Some(Value::Table(b)), Value::Table(o)) => merge(b, o),
            (_, v) => {
                base.insert(k, v);
            }
        }
    }
}

fn example() -> Table {
    polywan::config::EXAMPLE.parse().expect("the example is TOML")
}

#[test]
fn configurations_in_the_documentation_are_valid() {
    let Some(dir) = docs() else { return };
    let mut failures = Vec::new();
    let mut checked = 0;
    for page in pages(&dir) {
        let text = std::fs::read_to_string(&page).expect("a page is readable");
        for (line, block) in blocks(&text) {
            let at = format!("{}:{line}", page.display());
            let table: Table = match block.parse() {
                Ok(t) => t,
                Err(e) => {
                    failures.push(format!("{at}: not TOML: {e}"));
                    continue;
                }
            };
            let complete = table.contains_key("downlink") && table.contains_key("uplink");
            let config = if complete {
                block
            } else {
                let mut base = example();
                merge(&mut base, table);
                base.to_string()
            };
            if let Err(diags) = polywan::config::parse(&config) {
                for d in diags {
                    failures.push(format!("{at}: {}: {}", d.key, d.message));
                }
            }
            checked += 1;
        }
    }
    assert!(checked > 0, "no TOML block found in {}", dir.display());
    assert!(failures.is_empty(), "invalid configurations:\n{}", failures.join("\n"));
}

const PROBE: &str = "__probe";

/// The fields of the table at `path` (inside the first element of every
/// array of tables on the way), from the parser's rejection of an unknown
/// key there; `None` if `path` is not a table, or an array of tables with
/// `array`.
fn fields(path: &[&str], array: bool) -> Option<Vec<String>> {
    let mut root = example();
    let mut t = &mut root;
    for (i, key) in path.iter().enumerate() {
        let last = i + 1 == path.len();
        let fresh = || {
            if last && array {
                Value::Array(vec![Value::Table(Table::new())])
            } else {
                Value::Table(Table::new())
            }
        };
        if last {
            t.insert((*key).to_owned(), fresh());
        } else if !t.contains_key(*key) {
            t.insert((*key).to_owned(), Value::Table(Table::new()));
        }
        t = match t.get_mut(*key)? {
            Value::Table(t) => t,
            Value::Array(a) => match a.first_mut()? {
                Value::Table(t) => t,
                _ => return None,
            },
            _ => return None,
        };
    }
    t.insert(PROBE.to_owned(), Value::Integer(1));
    let message = match polywan::config::parse(&root.to_string()) {
        Ok(_) => return None,
        Err(diags) => diags.into_iter().map(|d| d.message).collect::<Vec<_>>().join("\n"),
    };
    let expected = message.strip_prefix(&format!("unknown field `{PROBE}`, expected "))?;
    Some(expected.split('`').skip(1).step_by(2).map(str::to_owned).collect())
}

/// Every key the parser accepts, as dotted paths, found by probing.
fn keys(path: &mut Vec<&'static str>, out: &mut Vec<String>) {
    let here = fields(path, false).or_else(|| fields(path, true));
    let Some(fields) = here else {
        out.push(path.join("."));
        return;
    };
    for f in fields {
        let f: &'static str = Box::leak(f.into_boxed_str());
        path.push(f);
        keys(path, out);
        path.pop();
    }
}

#[test]
fn every_key_is_in_the_configuration_reference() {
    let Some(dir) = docs() else { return };
    let reference = std::fs::read_to_string(dir.join("configuration.md")).expect("docs/configuration.md");
    let mut all = Vec::new();
    keys(&mut Vec::new(), &mut all);
    assert!(all.contains(&"routing.table_base".to_owned()), "probing found {all:?}");
    assert!(all.contains(&"notify.hook.command".to_owned()), "probing found {all:?}");
    // `[uplink.health]` overrides the keys of `[health]`, described once.
    let missing: std::collections::BTreeSet<_> = all
        .iter()
        .map(|k| {
            k.strip_prefix("uplink.")
                .filter(|r| r.starts_with("health."))
                .unwrap_or(k)
        })
        .filter(|k| !reference.contains(&format!("`{k}`")))
        .collect();
    assert!(
        missing.is_empty(),
        "keys missing from docs/configuration.md: {missing:?}"
    );
}
