//! The runner of sendmail and hooks (SPEC.md FR-MAIL-1, FR-HOOK-3, IMPL-4):
//! an absolute program with an argument vector and no shell, an empty
//! environment but `PATH` and the given variables, `/` as working
//! directory, the given user and primary group without supplementary
//! groups, a new process group, standard input written then closed,
//! standard error drained to its end with at most 64 KiB retained, and a
//! deadline after which the whole process group is killed and the child
//! reaped.
//!
//! Descriptors other than 0–2 are never passed on: PolyWAN's own are
//! close-on-exec, and descriptors the daemon inherited without that flag
//! are found by [`inherited_descriptors`], which refuses the configurations
//! that would run subprocesses alongside them.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

/// The only environment variable besides the given ones (FR-HOOK-2).
pub const PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
/// Retained output per stream (FR-MAIL-1, FR-HOOK-3).
pub const CAPTURE: usize = 64 * 1024;

/// What to run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub uid: u32,
    pub gid: u32,
    pub input: Vec<u8>,
    /// Standard output is captured (hooks) or discarded (sendmail).
    pub capture_stdout: bool,
    pub timeout: Duration,
}

/// Output retained from a stream.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Captured {
    pub data: Vec<u8>,
    pub truncated: bool,
}

impl Captured {
    /// The output as one escaped line, for logs (diagnostics never enter
    /// status or event responses).
    pub fn escaped(&self) -> String {
        let mut s: String = self.data.escape_ascii().to_string();
        if self.truncated {
            s += " [truncated]";
        }
        s
    }
}

/// How a run ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum End {
    /// Exited with this status.
    Exited(i32),
    /// Killed by this signal (not by PolyWAN).
    Signaled(i32),
    /// The deadline passed: the process group was killed.
    TimedOut,
    /// It could not start.
    SpawnFailed(String),
    /// Its input could not be written.
    InputFailed(String),
}

impl End {
    pub fn success(&self) -> bool {
        *self == End::Exited(0)
    }
}

impl std::fmt::Display for End {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            End::Exited(c) => write!(f, "exit status {c}"),
            End::Signaled(s) => write!(f, "killed by signal {s}"),
            End::TimedOut => f.write_str("timed out"),
            End::SpawnFailed(e) => write!(f, "could not start: {e}"),
            End::InputFailed(e) => write!(f, "input not written: {e}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub end: End,
    pub stdout: Captured,
    pub stderr: Captured,
}

/// Runs `spec` to its end or deadline. Cancelling the returned future (a
/// reload, a stopping daemon) kills the process group too.
pub async fn run(spec: &Spec) -> Outcome {
    let mut cmd = Command::new(&spec.program);
    cmd.args(&spec.args)
        .env_clear()
        .env("PATH", PATH)
        .envs(spec.env.iter().map(|(k, v)| (k, v)))
        .current_dir("/")
        .uid(spec.uid)
        .gid(spec.gid)
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(if spec.capture_stdout {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return Outcome {
                end: End::SpawnFailed(e.to_string()),
                stdout: Captured::default(),
                stderr: Captured::default(),
            };
        }
    };
    // Armed until the child exits by itself: a deadline or a cancellation
    // kills the whole group. Descendants of a child that exited normally
    // are left alone (a mail system may deliver in the background).
    let mut group = Group(child.id().map(|pid| pid as i32));
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let input = spec.input.clone();
    let work = async {
        let write = async {
            match stdin {
                Some(mut i) => {
                    let r = i.write_all(&input).await;
                    // Closed: the end of the input.
                    drop(i);
                    r.map_err(|e| e.to_string())
                }
                None => Ok(()),
            }
        };
        let (written, out, err) = tokio::join!(write, drain(stdout), drain(stderr));
        let status = child.wait().await;
        (written, out, err, status)
    };
    match tokio::time::timeout(spec.timeout, work).await {
        Ok((written, stdout, stderr, status)) => {
            group.disarm();
            // How the child ended comes first; a failed input write matters
            // only for a child that exited with 0 (a dead child's pipe
            // breaks).
            let end = match status {
                Err(e) => End::SpawnFailed(e.to_string()),
                Ok(s) => match (s.code(), std::os::unix::process::ExitStatusExt::signal(&s), written) {
                    (_, Some(sig), _) => End::Signaled(sig),
                    (Some(0), _, Err(e)) => End::InputFailed(e),
                    (Some(c), _, _) => End::Exited(c),
                    (None, None, _) => End::SpawnFailed("no exit status".into()),
                },
            };
            Outcome { end, stdout, stderr }
        }
        Err(_) => {
            // The group first, while the child is not reaped (its process
            // group id stays valid), then the child itself.
            drop(group);
            let _ = child.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
            Outcome {
                end: End::TimedOut,
                stdout: Captured::default(),
                stderr: Captured::default(),
            }
        }
    }
}

/// Kills a process group when dropped, unless disarmed.
struct Group(Option<i32>);

impl Group {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        if let Some(g) = self.0.take() {
            let _ = nix::sys::signal::killpg(nix::unistd::Pid::from_raw(g), nix::sys::signal::Signal::SIGKILL);
        }
    }
}

/// Reads a stream to its end, keeping the first [`CAPTURE`] bytes: a
/// verbose child never blocks on a full pipe.
pub(crate) async fn drain<R: tokio::io::AsyncRead + Unpin>(stream: Option<R>) -> Captured {
    let mut c = Captured::default();
    let Some(mut s) = stream else { return c };
    let mut buf = [0u8; 8192];
    loop {
        match s.read(&mut buf).await {
            Ok(0) | Err(_) => return c,
            Ok(n) => {
                let room = CAPTURE.saturating_sub(c.data.len());
                c.data.extend_from_slice(&buf[..n.min(room)]);
                if n > room {
                    c.truncated = true;
                }
            }
        }
    }
}

/// Descriptors above 2 that this process inherited without close-on-exec:
/// a subprocess would inherit them (FR-HOOK-3, FR-MAIL-1).
pub fn inherited_descriptors() -> Vec<i32> {
    let cloexec = nix::fcntl::OFlag::O_CLOEXEC.bits();
    let Ok(dir) = std::fs::read_dir("/proc/self/fdinfo") else {
        return Vec::new();
    };
    let mut v: Vec<i32> = dir
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
        .filter(|fd| *fd > 2)
        .filter(|fd| {
            std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}"))
                .ok()
                .and_then(|t| {
                    t.lines()
                        .find_map(|l| l.strip_prefix("flags:"))
                        .and_then(|f| i32::from_str_radix(f.trim(), 8).ok())
                })
                .is_some_and(|flags| flags & cloexec == 0)
        })
        .collect();
    v.sort_unstable();
    v
}

/// The refusal of FR-HOOK-3 and FR-MAIL-1: a configuration that runs hooks
/// or sendmail while the daemon holds inherited descriptors that they would
/// inherit.
pub fn descriptor_errors(config: &crate::config::Config, inherited: &[i32]) -> Vec<String> {
    if inherited.is_empty() || (config.notify.hooks.is_empty() && config.notify.email.is_none()) {
        return Vec::new();
    }
    vec![format!(
        "the daemon inherited descriptors {inherited:?} without close-on-exec; hooks and sendmail would inherit them (FR-HOOK-3): start it without them (a systemd unit passes none)"
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str, timeout_ms: u64) -> Spec {
        Spec {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            env: vec![("POLYWAN_EVENT".into(), "path_state_changed".into())],
            uid: nix::unistd::geteuid().as_raw(),
            gid: nix::unistd::getegid().as_raw(),
            input: b"hello".to_vec(),
            capture_stdout: true,
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    #[tokio::test]
    async fn input_environment_and_status() {
        let o = run(&sh(
            "cat; echo; echo \"$POLYWAN_EVENT $PATH $(pwd)\"; env | wc -l; exit 3",
            5000,
        ))
        .await;
        assert_eq!(o.end, End::Exited(3));
        let out = String::from_utf8_lossy(&o.stdout.data).into_owned();
        assert!(
            out.starts_with("hello\npath_state_changed /usr/sbin:/usr/bin:/sbin:/bin /\n"),
            "{out}"
        );
        // PATH, POLYWAN_EVENT, and the shell's own PWD/SHLVL at most.
        let vars: usize = out.lines().last().unwrap().trim().parse().unwrap();
        assert!(vars <= 5, "{out}");
    }

    #[tokio::test]
    async fn a_flood_is_drained_and_truncated() {
        let o = run(&sh("head -c 1000000 /dev/zero >&2; echo done", 10_000)).await;
        assert_eq!(o.end, End::Exited(0));
        assert_eq!((o.stderr.data.len(), o.stderr.truncated), (CAPTURE, true));
        assert_eq!(o.stdout.data, b"done\n");
    }

    #[tokio::test]
    async fn the_group_is_killed_at_the_deadline() {
        let dir = std::env::temp_dir().join(format!("polywan-subprocess-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mark = dir.join("grandchild");
        let script = format!("(sleep 3; touch {}) & sleep 30", mark.display());
        let o = run(&sh(&script, 300)).await;
        assert_eq!(o.end, End::TimedOut);
        std::thread::sleep(Duration::from_secs(4));
        assert!(!mark.exists(), "the grandchild died with the group");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn signals_spawn_failures_and_blocked_input() {
        assert_eq!(run(&sh("kill -TERM $$", 5000)).await.end, End::Signaled(15));
        let mut missing = sh("", 1000);
        missing.program = "/nonexistent/polywan-test".into();
        assert!(matches!(run(&missing).await.end, End::SpawnFailed(_)));
        // A child that never reads a large input: the deadline ends it.
        let mut blocked = sh("sleep 30", 300);
        blocked.input = vec![b'x'; 1 << 20];
        assert_eq!(run(&blocked).await.end, End::TimedOut);
    }

    #[tokio::test]
    async fn another_user_without_groups_or_capabilities() {
        // Changing user needs root (the build host and the test hosts run
        // the unit tests as root; CI does not).
        if !nix::unistd::geteuid().is_root() {
            return;
        }
        let mut spec = sh("id -u; id -G; grep -E '^Cap(Eff|Prm):' /proc/self/status", 5000);
        (spec.uid, spec.gid) = (65534, 65534);
        let o = run(&spec).await;
        assert_eq!(o.end, End::Exited(0), "{}", o.stderr.escaped());
        let out = String::from_utf8_lossy(&o.stdout.data).into_owned();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[..2], ["65534", "65534"], "no supplementary groups: {out}");
        assert!(lines[2..].iter().all(|l| l.ends_with("0000000000000000")), "{out}");
    }

    #[test]
    fn our_descriptors_are_close_on_exec() {
        // The test harness may pass descriptors of its own; a fresh socket
        // of ours is never listed.
        let before = inherited_descriptors();
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(inherited_descriptors(), before);
        drop(s);
    }
}
