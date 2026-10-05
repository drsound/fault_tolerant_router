//! The API (SPEC.md §9, FR-API-1 to FR-API-5): HTTP/1.1 and JSON on the
//! control socket and the read-only status socket, served on the I/O
//! runtime (IMPL-4).
//!
//! Each listener admits at most 16 connections, refusing more before any
//! task is created; a connection serves one request (no keep-alive), with
//! heads of at most 8 KiB and 64 fields, and a deadline that covers reading
//! the request, handling it and writing the response (10 s, plus the wait
//! of a long poll). Authorisation is the listener's role and nothing else;
//! every path outside the role's allowlist is 404, every other method on an
//! exposed path 405, without side effects (IMPL-11). Readers use the
//! published status and the event ring only (FR-API-4).

pub mod client;
pub mod socket;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::Serialize;
use tokio::sync::{Semaphore, mpsc, oneshot, watch};
use tokio::time::Instant;
use tracing::{info, warn};

use crate::events::{self, Ring};
use crate::status::Status;
use socket::{Access, Published, Record};

/// Connections each listener admits (FR-API-4).
pub const CONNECTIONS: usize = 16;
/// The deadline of an ordinary request (FR-API-4).
pub const DEADLINE: Duration = Duration::from_secs(10);
/// The longest wait of an events request (FR-API-2).
pub const MAX_WAIT: Duration = Duration::from_secs(60);
/// Request heads (FR-API-4); hyper's smallest read buffer.
const HEAD_BYTES: usize = 8192;
const HEAD_FIELDS: usize = 64;

/// What a listener exposes (IMPL-11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Control,
    Status,
}

/// One configured socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub role: Role,
    pub path: PathBuf,
    pub access: Access,
}

/// The endpoints of a configuration, with the groups resolved.
pub fn endpoints(api: &crate::config::Api) -> Result<Vec<Endpoint>, String> {
    let gid = |name: &str| -> Result<u32, String> {
        crate::identity::group(name)
            .map_err(|e| format!("group {name:?}: {e}"))?
            .ok_or_else(|| format!("group {name:?} does not exist"))
    };
    let mut v = vec![Endpoint {
        role: Role::Control,
        path: api.socket.clone(),
        access: Access {
            gid: Some(gid(&api.group)?),
        },
    }];
    if let Some(path) = &api.status_socket {
        v.push(Endpoint {
            role: Role::Status,
            path: path.clone(),
            access: Access {
                gid: api.status_group.as_deref().map(gid).transpose()?,
            },
        });
    }
    Ok(v)
}

/// What the handlers read.
#[derive(Clone)]
pub struct Shared {
    pub status: watch::Receiver<Arc<Status>>,
    pub ring: Arc<Mutex<Ring>>,
    pub latest: watch::Receiver<u64>,
    pub started: std::time::Instant,
}

/// Commands of the listener manager, which runs on the I/O runtime.
pub enum Command {
    /// Binds the sockets of new paths (a reload, FR-API-1); nothing changes
    /// for clients until the commit.
    Prepare {
        endpoints: Vec<Endpoint>,
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Serves the prepared configuration: new sockets start, removed ones
    /// close, changed access applies and closes the existing connections.
    Commit,
    /// Removes what the last preparation bound.
    Rollback,
    /// Closes every listener and removes the published sockets.
    Shutdown(oneshot::Sender<()>),
}

/// The handle the State task keeps.
#[derive(Clone)]
pub struct Api {
    commands: mpsc::Sender<Command>,
}

impl Api {
    /// Binds the configured sockets and starts serving them. Called at
    /// startup, before the event loop.
    pub async fn start(
        handle: &tokio::runtime::Handle,
        endpoints: Vec<Endpoint>,
        runtime_dir: PathBuf,
        shared: Shared,
    ) -> Result<Api, String> {
        let (commands, rx) = mpsc::channel(8);
        let (ready, started) = oneshot::channel();
        handle.spawn(manager(rx, endpoints, Record::new(&runtime_dir), shared, ready));
        started.await.map_err(|_| "the API manager stopped".to_owned())??;
        Ok(Api { commands })
    }

    pub async fn prepare(&self, endpoints: Vec<Endpoint>) -> Result<(), String> {
        let (reply, rx) = oneshot::channel();
        self.commands
            .send(Command::Prepare { endpoints, reply })
            .await
            .map_err(|_| "the API manager stopped".to_owned())?;
        rx.await.map_err(|_| "the API manager stopped".to_owned())?
    }

    pub fn send(&self, c: Command) -> bool {
        self.commands.try_send(c).is_ok()
    }

    pub async fn shutdown(&self) {
        let (tx, rx) = oneshot::channel();
        if self.commands.send(Command::Shutdown(tx)).await.is_ok() {
            let _ = rx.await;
        }
    }
}

/// A serving listener.
struct Listener {
    endpoint: Endpoint,
    published: Published,
    /// Stops the listener and its connections.
    stop: watch::Sender<bool>,
    /// Advanced when the access policy changes: the connections admitted
    /// under the old one close (FR-API-1).
    cut: watch::Sender<u64>,
}

async fn manager(
    mut rx: mpsc::Receiver<Command>,
    initial: Vec<Endpoint>,
    record: Record,
    shared: Shared,
    ready: oneshot::Sender<Result<(), String>>,
) {
    let mut serving: Vec<Listener> = Vec::new();
    let mut prepared: Vec<(Endpoint, std::os::unix::net::UnixListener, Published)> = Vec::new();
    let mut next: Option<Vec<Endpoint>> = None;
    // At startup the record identifies the sockets of an earlier instance.
    let known = record.read();
    let mut started = Ok(());
    for e in initial {
        match bind(&e, &known).await {
            Ok((l, p)) => serving.push(serve(e, l, p, &shared)),
            Err(err) => {
                started = Err(err);
                break;
            }
        }
    }
    let save = |serving: &[Listener], prepared: &[(Endpoint, std::os::unix::net::UnixListener, Published)]| {
        let list: Vec<Published> = serving
            .iter()
            .map(|l| l.published.clone())
            .chain(prepared.iter().map(|(_, _, p)| p.clone()))
            .collect();
        if let Err(e) = record.write(&list) {
            warn!("recording the API sockets: {e}");
        }
    };
    if started.is_err() {
        for l in serving.drain(..) {
            close(l);
        }
    }
    save(&serving, &prepared);
    let failed = started.is_err();
    let _ = ready.send(started);
    if failed {
        return;
    }
    while let Some(c) = rx.recv().await {
        match c {
            Command::Prepare { endpoints, reply } => {
                for (_, _, p) in prepared.drain(..) {
                    socket::unpublish(&p);
                }
                let mut result = Ok(());
                for e in &endpoints {
                    match serving.iter().find(|l| l.endpoint.path == e.path) {
                        // FR-API-1: an existing path never changes role.
                        Some(l) if l.endpoint.role != e.role => {
                            result = Err(format!(
                                "{} cannot change from the {:?} to the {:?} socket on reload",
                                e.path.display(),
                                l.endpoint.role,
                                e.role
                            ));
                            break;
                        }
                        Some(_) => {}
                        None => match bind(e, &[]).await {
                            Ok((l, p)) => prepared.push((e.clone(), l, p)),
                            Err(err) => {
                                result = Err(err);
                                break;
                            }
                        },
                    }
                }
                if result.is_err() {
                    for (_, _, p) in prepared.drain(..) {
                        socket::unpublish(&p);
                    }
                    next = None;
                } else {
                    next = Some(endpoints);
                }
                save(&serving, &prepared);
                let _ = reply.send(result);
            }
            Command::Commit => {
                let Some(wanted) = next.take() else { continue };
                let mut kept = Vec::new();
                for l in serving.drain(..) {
                    match wanted.iter().find(|e| e.path == l.endpoint.path) {
                        Some(e) if e.access == l.endpoint.access => kept.push(l),
                        // A changed access applies to the socket file;
                        // connections admitted under the old policy close.
                        Some(e) => {
                            let e = e.clone();
                            let p = e.path.clone();
                            let access = e.access;
                            let applied = tokio::task::spawn_blocking(move || {
                                use std::os::unix::fs::PermissionsExt;
                                std::os::unix::fs::chown(&p, Some(0), Some(access.gid.unwrap_or(0)))?;
                                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(access.mode()))
                            })
                            .await;
                            if !matches!(applied, Ok(Ok(()))) {
                                warn!(path = %e.path.display(), "changing the access of an API socket failed");
                            }
                            // The listening socket stays; its connections
                            // are cut.
                            l.cut.send_modify(|g| *g += 1);
                            kept.push(Listener { endpoint: e, ..l });
                        }
                        None => close(l),
                    }
                }
                serving = kept;
                for (e, l, p) in prepared.drain(..) {
                    serving.push(serve(e, l, p, &shared));
                }
                save(&serving, &prepared);
            }
            Command::Rollback => {
                next = None;
                for (_, _, p) in prepared.drain(..) {
                    socket::unpublish(&p);
                }
                save(&serving, &prepared);
            }
            Command::Shutdown(done) => {
                for l in serving.drain(..) {
                    close(l);
                }
                for (_, _, p) in prepared.drain(..) {
                    socket::unpublish(&p);
                }
                save(&serving, &prepared);
                let _ = done.send(());
                return;
            }
        }
    }
}

fn close(l: Listener) {
    let _ = l.stop.send(true);
    socket::unpublish(&l.published);
}

async fn bind(e: &Endpoint, known: &[Published]) -> Result<(std::os::unix::net::UnixListener, Published), String> {
    let e = e.clone();
    let known = known.to_vec();
    tokio::task::spawn_blocking(move || socket::bind(&e.path, e.access, &known))
        .await
        .map_err(|err| err.to_string())?
        .map_err(|err| err.to_string())
}

fn serve(
    endpoint: Endpoint,
    listener: std::os::unix::net::UnixListener,
    published: Published,
    shared: &Shared,
) -> Listener {
    let (stop, stopped) = watch::channel(false);
    let (cut, cuts) = watch::channel(0);
    let role = endpoint.role;
    let shared = shared.clone();
    tokio::spawn(async move {
        if let Err(e) = accept_loop(listener, role, shared, stopped, cuts).await {
            warn!("API listener stopped: {e}");
        }
    });
    info!(path = %endpoint.path.display(), role = ?role, "API socket listening");
    Listener {
        endpoint,
        published,
        stop,
        cut,
    }
}

async fn accept_loop(
    listener: std::os::unix::net::UnixListener,
    role: Role,
    shared: Shared,
    mut stopped: watch::Receiver<bool>,
    cuts: watch::Receiver<u64>,
) -> std::io::Result<()> {
    listener.set_nonblocking(true)?;
    let listener = tokio::net::UnixListener::from_std(listener)?;
    let admitted = Arc::new(Semaphore::new(CONNECTIONS));
    let mut refused = Diagnostics::default();
    loop {
        tokio::select! {
            _ = stopped.changed() => return Ok(()),
            r = listener.accept() => {
                let Ok((stream, _)) = r else { continue };
                // FR-API-4: beyond the limit, closed at once; no task, no
                // queue.
                let Ok(permit) = Arc::clone(&admitted).try_acquire_owned() else {
                    refused.note(role);
                    continue;
                };
                let shared = shared.clone();
                let (stopped, cuts) = (stopped.clone(), cuts.clone());
                tokio::spawn(async move {
                    connection(stream, role, shared, stopped, cuts).await;
                    drop(permit);
                });
            }
        }
    }
}

/// Rate-limited diagnostics about clients (FR-API-4).
#[derive(Default)]
struct Diagnostics {
    last: Option<Instant>,
    suppressed: u64,
}

impl Diagnostics {
    fn note(&mut self, role: Role) {
        let now = Instant::now();
        if self
            .last
            .is_some_and(|t| now.duration_since(t) < Duration::from_secs(60))
        {
            self.suppressed += 1;
            return;
        }
        warn!(role = ?role, suppressed = self.suppressed, "API connection limit reached: connection closed");
        self.last = Some(now);
        self.suppressed = 0;
    }
}

async fn connection(
    stream: tokio::net::UnixStream,
    role: Role,
    shared: Shared,
    mut stopped: watch::Receiver<bool>,
    mut cuts: watch::Receiver<u64>,
) {
    let generation = *cuts.borrow();
    let (deadline_tx, mut deadline) = watch::channel(Instant::now() + DEADLINE);
    let deadline_tx = Arc::new(deadline_tx);
    let service = hyper::service::service_fn(move |req| {
        let shared = shared.clone();
        let deadline = Arc::clone(&deadline_tx);
        async move { Ok::<_, std::convert::Infallible>(handle(req, role, &shared, &deadline).await) }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .keep_alive(false)
        .max_headers(HEAD_FIELDS)
        .max_buf_size(HEAD_BYTES)
        .timer(TokioTimer::new())
        .header_read_timeout(DEADLINE);
    let conn = builder.serve_connection(TokioIo::new(stream), service);
    tokio::pin!(conn);
    loop {
        let until = *deadline.borrow();
        tokio::select! {
            _ = &mut conn => return,
            _ = tokio::time::sleep_until(until) => return,
            r = deadline.changed() => if r.is_err() { return },
            _ = stopped.changed() => return,
            _ = cuts.wait_for(|g| *g != generation) => return,
        }
    }
}

type Reply = Response<Full<Bytes>>;

fn reply(code: StatusCode, body: impl Into<Bytes>) -> Reply {
    let mut r = Response::new(Full::new(body.into()));
    *r.status_mut() = code;
    r.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    r
}

fn error(code: StatusCode, message: &str) -> Reply {
    reply(code, serde_json::json!({ "error": message }).to_string())
}

/// The paths of the control socket's write endpoints (FR-API-3).
fn control_only(path: &str) -> bool {
    matches!(path, "/v1/reload" | "/v1/notify-test")
        || path
            .strip_prefix("/v1/uplinks/")
            .and_then(|r| r.split_once('/'))
            .is_some_and(|(name, action)| !name.is_empty() && matches!(action, "drain" | "undrain" | "forget"))
}

async fn handle(req: Request<Incoming>, role: Role, shared: &Shared, deadline: &watch::Sender<Instant>) -> Reply {
    let path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or("").to_owned();
    match path.as_str() {
        "/v1/status" if req.method() == Method::GET => status(shared),
        "/v1/events" if req.method() == Method::GET => events(&query, shared, deadline).await,
        "/v1/status" | "/v1/events" => error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
        p if role == Role::Control && control_only(p) => {
            if req.method() != Method::POST {
                return error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
            }
            error(StatusCode::NOT_IMPLEMENTED, "not implemented by this development build")
        }
        _ => error(StatusCode::NOT_FOUND, "not found"),
    }
}

#[derive(Serialize)]
struct StatusReply<'a> {
    #[serde(flatten)]
    status: &'a Status,
    uptime_seconds: u64,
}

fn status(shared: &Shared) -> Reply {
    let s = Arc::clone(&shared.status.borrow());
    let body = serde_json::to_vec(&StatusReply {
        status: &s,
        uptime_seconds: shared.started.elapsed().as_secs(),
    });
    match body {
        Ok(b) => reply(StatusCode::OK, b),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "status unavailable"),
    }
}

/// Query parameters of `GET /v1/events`.
#[derive(Debug, Default, PartialEq)]
struct EventsQuery {
    instance: Option<String>,
    after: Option<u64>,
    limit: usize,
    wait: Duration,
}

fn parse_events_query(query: &str) -> Result<EventsQuery, String> {
    let mut q = EventsQuery {
        limit: events::RING_EVENTS,
        ..EventsQuery::default()
    };
    let fields: BTreeMap<&str, &str> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| p.split_once('=').unwrap_or((p, "")))
        .collect();
    for (k, v) in fields {
        let number = || v.parse::<u64>().map_err(|_| format!("{k}: not a number"));
        match k {
            "instance" if v.bytes().all(|b| b.is_ascii_hexdigit()) && v.len() <= 64 => q.instance = Some(v.to_owned()),
            "instance" => return Err("instance: not an instance identifier".into()),
            "after" => q.after = Some(number()?),
            "limit" => q.limit = (number()? as usize).clamp(1, events::RING_EVENTS),
            "wait" => q.wait = Duration::from_secs(number()?).min(MAX_WAIT),
            _ => return Err(format!("unknown parameter {k:?}")),
        }
    }
    Ok(q)
}

async fn events(query: &str, shared: &Shared, deadline: &watch::Sender<Instant>) -> Reply {
    let q = match parse_events_query(query) {
        Ok(q) => q,
        Err(e) => return error(StatusCode::BAD_REQUEST, &e),
    };
    let page = |q: &EventsQuery| {
        shared.ring.lock().unwrap_or_else(|e| e.into_inner()).page(
            q.instance.as_deref(),
            q.after,
            q.limit,
            events::RING_BYTES,
        )
    };
    let mut p = page(&q);
    if p.events.is_empty() && !p.reset && !q.wait.is_zero() {
        // FR-API-4: the wait extends the deadline, never the routing state.
        let _ = deadline.send(Instant::now() + q.wait + DEADLINE);
        let after = q.after.unwrap_or(0);
        let mut latest = shared.latest.clone();
        let _ = tokio::time::timeout(q.wait, latest.wait_for(|s| *s > after)).await;
        p = page(&q);
    }
    let mut body = String::with_capacity(64 + p.events.iter().map(|e| e.len() + 1).sum::<usize>());
    body += &format!(
        "{{\"instance\":\"{}\",\"reset\":{},\"truncated\":{},\"events\":[",
        p.instance, p.reset, p.truncated
    );
    for (i, e) in p.events.iter().enumerate() {
        if i > 0 {
            body.push(',');
        }
        body += e;
    }
    body += "]}";
    reply(StatusCode::OK, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_paths_are_recognised() {
        assert!(control_only("/v1/reload"));
        assert!(control_only("/v1/notify-test"));
        assert!(control_only("/v1/uplinks/a/drain"));
        assert!(control_only("/v1/uplinks/fiber/forget"));
        assert!(!control_only("/v1/uplinks//drain"));
        assert!(!control_only("/v1/uplinks/a/delete"));
        assert!(!control_only("/v1/status"));
    }

    #[test]
    fn events_queries_are_parsed_and_bounded() {
        let q = parse_events_query("instance=ab12&after=7&limit=5000&wait=600").unwrap();
        assert_eq!(
            q,
            EventsQuery {
                instance: Some("ab12".into()),
                after: Some(7),
                limit: 1000,
                wait: MAX_WAIT
            }
        );
        assert_eq!(parse_events_query("").unwrap().limit, 1000);
        assert!(parse_events_query("after=x").is_err());
        assert!(parse_events_query("instance=zz").is_err());
        assert!(parse_events_query("verbose=1").is_err());
    }
}
