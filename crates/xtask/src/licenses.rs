//! The third-party notices of the release binaries (P8 of M4): every crate
//! of `Cargo.lock` linked into `polywan` for a PLAT-3 target, with the
//! license files it ships, musl's notice, and the Rust standard library's
//! notices from the toolchain. Offline: crate sources come from Cargo's
//! registry, never from a license service.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use serde_json::Value;

/// The release targets (SPEC.md PLAT-3). The notices cover the crates
/// linked for any of them, so every package carries the same file.
const TARGETS: &[&str] = &[
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "armv7-unknown-linux-musleabihf",
];

/// The notice of musl 1.2.5, the C library that the toolchain links
/// statically into the musl targets (its self-contained `libc.a`).
const MUSL: &str = include_str!("../../../packaging/licenses/musl-COPYRIGHT");

/// The file names under which crates ship license texts and notices.
const PREFIXES: &[&str] = &["LICENSE", "LICENCE", "COPYING", "NOTICE", "COPYRIGHT"];

/// Writes `THIRD-PARTY-LICENSES` and `rust-std-copyright.html` into `dir`.
pub fn write(dir: &Path) -> anyhow::Result<()> {
    let mut crates = BTreeMap::new();
    for target in TARGETS {
        for c in linked(target)? {
            crates.insert((c.name.clone(), c.version.clone()), c);
        }
    }
    // One copy of every distinct text, with the crates that ship it.
    let mut texts: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for c in crates.values() {
        let files = license_files(&c.dir)?;
        if files.is_empty() {
            bail!("{} {} ships no license file in {}", c.name, c.version, c.dir.display());
        }
        for f in files {
            let text = fs::read_to_string(c.dir.join(&f)).with_context(|| format!("{}/{f}", c.dir.display()))?;
            texts
                .entry(text)
                .or_default()
                .push(format!("{} {} ({f})", c.name, c.version));
        }
    }

    let mut out = String::from(HEADER);
    for c in crates.values() {
        out += &format!("  {} {}: {}\n", c.name, c.version, c.license);
    }
    out += &format!("\n{RULE}\nmusl libc\n{RULE}\n\n{MUSL}");
    let mut texts: Vec<_> = texts.into_iter().collect();
    texts.sort_by(|a, b| a.1.cmp(&b.1));
    for (text, users) in texts {
        out += &format!("\n{RULE}\n{}\n{RULE}\n\n{}", users.join(",\n"), text.trim_end());
        out.push('\n');
    }
    fs::create_dir_all(dir).with_context(|| format!("{}", dir.display()))?;
    fs::write(dir.join("THIRD-PARTY-LICENSES"), out)?;

    let std = sysroot()?.join("share/doc/rust/COPYRIGHT-library.html");
    fs::copy(&std, dir.join("rust-std-copyright.html")).with_context(|| format!("{}", std.display()))?;
    Ok(())
}

const RULE: &str = "------------------------------------------------------------------------";

const HEADER: &str = "Third-party software in the PolyWAN release binaries

The polywan binaries and packages are statically linked. Besides PolyWAN
itself (MIT OR Apache-2.0), they contain:

- the Rust standard library (MIT OR Apache-2.0) and the crates compiled
  into it, whose notices are in rust-std-copyright.html, as distributed
  with the Rust toolchain that built the binaries;
- musl libc (MIT), whose notice follows the list of crates;
- LLVM's libunwind (Apache-2.0 WITH LLVM-exception, which requires no
  notice for object code);
- the following crates, whose license texts follow musl's notice, each
  text once with the crates that ship it:

";

struct Crate {
    name: String,
    version: String,
    license: String,
    dir: PathBuf,
}

/// The crates linked into `polywan` for `target`: its normal dependencies,
/// transitively, without procedural macros (they run in the compiler) and
/// what only they depend on.
fn linked(target: &str) -> anyhow::Result<Vec<Crate>> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let output = Command::new(cargo)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--filter-platform",
            target,
        ])
        .arg("--manifest-path")
        .arg(&manifest)
        .output()
        .context("cargo metadata")?;
    if !output.status.success() {
        bail!("cargo metadata: {}", String::from_utf8_lossy(&output.stderr));
    }
    let meta: Value = serde_json::from_slice(&output.stdout)?;
    let packages: BTreeMap<&str, &Value> = meta["packages"]
        .as_array()
        .context("packages")?
        .iter()
        .filter_map(|p| Some((p["id"].as_str()?, p)))
        .collect();
    let nodes: BTreeMap<&str, &Value> = meta["resolve"]["nodes"]
        .as_array()
        .context("resolve")?
        .iter()
        .filter_map(|n| Some((n["id"].as_str()?, n)))
        .collect();
    let root = packages
        .values()
        .find(|p| p["name"] == "polywan" && p["source"].is_null())
        .and_then(|p| p["id"].as_str())
        .context("the polywan package")?;

    let proc_macro = |id: &str| {
        packages[id]["targets"].as_array().is_some_and(|t| {
            t.iter().any(|t| {
                t["kind"]
                    .as_array()
                    .is_some_and(|k| k.iter().any(|k| k == "proc-macro"))
            })
        })
    };
    let mut seen = BTreeSet::new();
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        for dep in nodes[id]["deps"].as_array().into_iter().flatten() {
            let normal = dep["dep_kinds"]
                .as_array()
                .is_some_and(|k| k.iter().any(|k| k["kind"].is_null()));
            let pkg = dep["pkg"].as_str().context("dependency id")?;
            if normal && !proc_macro(pkg) {
                stack.push(pkg);
            }
        }
    }
    seen.remove(root);
    seen.into_iter()
        .map(|id| {
            let p = packages[id];
            let field = |k: &str| p[k].as_str().map(str::to_owned);
            let name = field("name").context("name")?;
            let manifest = field("manifest_path").context("manifest_path")?;
            Ok(Crate {
                license: field("license").with_context(|| format!("{name} declares no license expression"))?,
                version: field("version").context("version")?,
                dir: Path::new(&manifest).parent().context("crate directory")?.to_owned(),
                name,
            })
        })
        .collect()
}

/// The license and notice files at the top of a crate's source, sorted.
fn license_files(dir: &Path) -> anyhow::Result<Vec<String>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("{}", dir.display()))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let upper = name.to_uppercase();
        if entry.file_type()?.is_file() && PREFIXES.iter().any(|p| upper.starts_with(p)) {
            files.push(name);
        }
    }
    files.sort();
    Ok(files)
}

fn sysroot() -> anyhow::Result<PathBuf> {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let output = Command::new(rustc)
        .args(["--print", "sysroot"])
        .output()
        .context("rustc --print sysroot")?;
    if !output.status.success() {
        bail!("rustc --print sysroot: {}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(PathBuf::from(String::from_utf8(output.stdout)?.trim()))
}
