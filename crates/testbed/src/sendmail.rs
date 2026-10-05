//! A recording sendmail stub for the email scenarios (AS-07, AS-25): a
//! root-owned shell script in the run's executable directory (trusted
//! under FR-CFG-5) that records each call's time, process ids, arguments
//! and input, and behaves as the next mode of its script says.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Mutex;
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
    /// The script's word; a call records it with `-` for spaces.
    pub fn word(self) -> String {
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
    /// Its mode ([`Mode::word`] with `-` for spaces).
    pub mode: String,
    /// Whether its mode reads the message.
    pub reads: bool,
    pub args: Vec<String>,
    /// The message, if it was read.
    pub message: Option<Mail>,
    /// The name of its message file.
    stamp: String,
}

impl Call {
    /// A header of its message, once read.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.message.as_ref()?.header(name)
    }

    /// Parses a line of the calls file.
    fn parse(line: &str) -> Result<Call> {
        let mut w = line.split(' ');
        let stamp = w.next().context("time")?.to_owned();
        let ns: u64 = stamp.parse()?;
        let pid = w.next().context("pid")?.parse()?;
        let pgid = w.next().context("pgid")?.parse()?;
        let mode = w.next().context("mode")?.to_owned();
        Ok(Call {
            at: UNIX_EPOCH + Duration::from_nanos(ns),
            pid,
            pgid,
            reads: mode != "noread",
            mode,
            args: w.map(str::to_owned).collect(),
            message: None,
            stamp,
        })
    }
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
        let mut mail = Mail {
            headers,
            body: String::new(),
            raw: raw.to_owned(),
        };
        let encoding = mail.header("Content-Transfer-Encoding");
        anyhow::ensure!(encoding == Some("base64"), "unexpected encoding {encoding:?}");
        mail.body = String::from_utf8(base64_decode(body)?)?;
        Ok(mail)
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
    /// The calls parsed so far ([`Stub::calls`]).
    parsed: Mutex<Vec<Call>>,
}

impl Stub {
    /// A stub named `name` in the run's executable directory, accepting
    /// every call until a [`Stub::script`].
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
# The mode first, so that a recorded call has its mode: the script's next
# line, taken under a lock, or accept once the script is used up.
exec 9>>$d/lock
flock 9
mode=$(head -n 1 $d/script 2>/dev/null)
sed -i 1d $d/script 2>/dev/null
exec 9>&-
mode=${{mode:-accept}}
n=$(date +%s%N)
echo "$n $$ $(cut -d' ' -f5 /proc/$$/stat) $(echo $mode | tr ' ' -) $*" >> $d/calls
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
        Ok(Stub {
            path,
            dir,
            parsed: Mutex::default(),
        })
    }

    /// The next calls behave as `modes`, one each in order, and the calls
    /// after them accept; replaces the modes not used yet. A phase sets its
    /// sequence before its trigger, so that no call races a change of mode.
    pub fn script(&self, modes: &[Mode]) -> Result<()> {
        let text: String = modes.iter().map(|m| m.word() + "\n").collect();
        // Under the calls' lock: a call takes its mode from one script,
        // never the first line of the next.
        let lock = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("lock"))?;
        lock.lock()?;
        Ok(fs::write(self.dir.join("script"), text)?)
    }

    /// The background child of the last [`Mode::Hang`] call.
    pub fn child(&self) -> Option<u32> {
        fs::read_to_string(self.dir.join("child")).ok()?.trim().parse().ok()
    }

    /// The calls so far, oldest first. Each call and message is parsed
    /// once: polling reads only what is new.
    pub fn calls(&self) -> Result<Vec<Call>> {
        let text = fs::read_to_string(self.dir.join("calls")).unwrap_or_default();
        let mut parsed = self.parsed.lock().unwrap_or_else(|e| e.into_inner());
        for line in text.split_inclusive('\n').skip(parsed.len()) {
            // A line still being written comes complete at the next poll.
            let Some(line) = line.strip_suffix('\n') else {
                break;
            };
            parsed.push(Call::parse(line)?);
        }
        // A message appears once read (written aside, then renamed).
        for c in parsed.iter_mut().filter(|c| c.reads && c.message.is_none()) {
            c.message = fs::read_to_string(self.dir.join(format!("{}.msg", c.stamp)))
                .ok()
                .map(|m| Mail::parse(&m))
                .transpose()?;
        }
        Ok(parsed.clone())
    }

    /// The calls whose message has this Message-ID.
    pub fn attempts(&self, id: &str) -> Result<Vec<Call>> {
        Ok(self
            .calls()?
            .into_iter()
            .filter(|c| c.header("Message-ID") == Some(id))
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
