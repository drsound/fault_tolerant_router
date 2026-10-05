//! A recording sendmail stub for the email scenarios (AS-07, AS-25): a
//! root-owned shell script in the run's executable directory (trusted
//! under FR-CFG-5) that records each call's time, process ids, arguments
//! and input, and behaves as its control file says.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use crate::topology::Topology;

/// What the stub does with a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Reads the message and exits 0.
    Accept,
    /// Reads the message and exits with this status.
    Exit(u8),
    /// Reads the message, writes 1 MiB to standard error, exits 1.
    Flood,
    /// Reads the message, then kills itself with SIGKILL.
    Signal,
    /// Never reads its input and sleeps 60 s.
    NoRead,
    /// Reads the message, then sleeps 60 s with a background child whose
    /// process id it records.
    Hang,
}

impl Mode {
    fn word(self) -> String {
        match self {
            Mode::Accept => "accept".into(),
            Mode::Exit(n) => format!("exit {n}"),
            Mode::Flood => "flood".into(),
            Mode::Signal => "signal".into(),
            Mode::NoRead => "noread".into(),
            Mode::Hang => "hang".into(),
        }
    }
}

/// One call of the stub.
#[derive(Clone, Debug)]
pub struct Call {
    pub at: SystemTime,
    pub pid: u32,
    pub pgid: u32,
    /// Whether its mode reads the message.
    pub reads: bool,
    pub args: Vec<String>,
    /// The message, if it was read.
    pub message: Option<Mail>,
}

/// A recorded message: its headers (unfolded) and decoded body.
#[derive(Clone, Debug)]
pub struct Mail {
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub raw: String,
}

impl Mail {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Parses a message with a base64 `text/plain` body.
    pub fn parse(raw: &str) -> Result<Mail> {
        let (head, body) = raw.split_once("\n\n").context("no end of headers")?;
        let mut headers: Vec<(String, String)> = Vec::new();
        for line in head.lines() {
            if line.starts_with([' ', '\t']) {
                let last = headers.last_mut().context("continuation first")?;
                last.1 += &format!("\n{line}");
            } else {
                let (n, v) = line.split_once(": ").context("header without a colon")?;
                headers.push((n.to_owned(), v.to_owned()));
            }
        }
        let encoding = headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("Content-Transfer-Encoding"))
            .map(|(_, v)| v.as_str());
        anyhow::ensure!(encoding == Some("base64"), "unexpected encoding {encoding:?}");
        Ok(Mail {
            body: String::from_utf8(base64_decode(body)?)?,
            headers,
            raw: raw.to_owned(),
        })
    }
}

/// Decodes base64 text, ignoring line breaks.
pub fn base64_decode(text: &str) -> Result<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bits = 0u32;
    let mut n = 0;
    let mut out = Vec::new();
    for c in text.bytes().filter(|c| !c.is_ascii_whitespace() && *c != b'=') {
        let v = ALPHABET.iter().position(|a| *a == c).context("not base64")?;
        bits = bits << 6 | v as u32;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
        }
    }
    Ok(out)
}

/// The stub of one run.
pub struct Stub {
    /// The executable to configure as `notify.email.sendmail`.
    pub path: PathBuf,
    dir: PathBuf,
}

impl Stub {
    /// A stub named `name` in the run's executable directory, accepting.
    pub fn new(t: &Topology, name: &str) -> Result<Stub> {
        let dir = t.exec_dir()?.join(format!("{name}.d"));
        fs::create_dir_all(&dir)?;
        let path = t.exec_dir()?.join(name);
        let d = dir.display();
        fs::write(
            &path,
            format!(
                r#"#!/bin/sh
d={d}
# The mode first: a recorded call has its mode, and whether it reads.
mode=$(cat $d/mode 2>/dev/null)
reads=1
[ "$mode" = noread ] && reads=0
n=$(date +%s%N)
echo "$n $$ $(cut -d' ' -f5 /proc/$$/stat) $reads $*" >> $d/calls
# Complete messages only: written aside, then renamed.
read_message() {{ cat > $d/$n.tmp && mv $d/$n.tmp $d/$n.msg; }}
case $mode in
  "exit "*) read_message; exit ${{mode#exit }} ;;
  flood) read_message; head -c 1048576 /dev/zero | tr '\0' x >&2; exit 1 ;;
  signal) read_message; kill -KILL $$ ;;
  noread) sleep 60 ;;
  hang) read_message; sleep 60 & echo $! > $d/child; sleep 60 ;;
  *) read_message ;;
esac
"#
            ),
        )?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        let stub = Stub { path, dir };
        stub.set(Mode::Accept)?;
        Ok(stub)
    }

    pub fn set(&self, mode: Mode) -> Result<()> {
        Ok(fs::write(self.dir.join("mode"), mode.word())?)
    }

    /// The background child of the last [`Mode::Hang`] call.
    pub fn child(&self) -> Option<u32> {
        fs::read_to_string(self.dir.join("child")).ok()?.trim().parse().ok()
    }

    /// The calls so far, oldest first.
    pub fn calls(&self) -> Result<Vec<Call>> {
        let text = fs::read_to_string(self.dir.join("calls")).unwrap_or_default();
        let mut v = Vec::new();
        for line in text.lines() {
            let mut w = line.split(' ');
            let n = w.next().context("time")?;
            let ns: u64 = n.parse()?;
            let pid = w.next().context("pid")?.parse()?;
            let pgid = w.next().context("pgid")?.parse()?;
            let reads = w.next() == Some("1");
            // None while the message is still being read.
            let message = fs::read_to_string(self.dir.join(format!("{n}.msg")))
                .ok()
                .map(|m| Mail::parse(&m))
                .transpose()?;
            v.push(Call {
                at: UNIX_EPOCH + Duration::from_nanos(ns),
                pid,
                pgid,
                reads,
                args: w.map(str::to_owned).collect(),
                message,
            });
        }
        Ok(v)
    }

    /// The calls whose message has this Message-ID.
    pub fn attempts(&self, id: &str) -> Result<Vec<Call>> {
        Ok(self
            .calls()?
            .into_iter()
            .filter(|c| c.message.as_ref().and_then(|m| m.header("Message-ID")) == Some(id))
            .collect())
    }

    /// Waits until the stub has been called `count` times or more, and
    /// every call that reads its message has read it.
    pub fn wait_calls(&self, t: &Topology, count: usize, timeout: Duration) -> Result<Vec<Call>> {
        t.wait_for(&format!("{count} sendmail calls"), timeout, || {
            let calls = self.calls()?;
            Ok(calls.len() >= count && calls.iter().all(|c| !c.reads || c.message.is_some()))
        })?;
        self.calls()
    }
}
