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
use std::net::SocketAddr;
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
use tracing::{error, info, warn};

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
    /// `GET /metrics` on `metrics.listen` (FR-MET-1).
    Metrics,
}

/// Where a listener listens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address {
    /// A socket of the API (FR-API-1).
    Unix { path: PathBuf, access: Access },
    /// `metrics.listen` (FR-MET-1).
    Tcp(SocketAddr),
}

impl Address {
    /// The same socket path or the same address, whatever the access.
    fn same_place(&self, other: &Address) -> bool {
        match (self, other) {
            (Address::Unix { path: a, .. }, Address::Unix { path: b, .. }) => a == b,
            (Address::Tcp(a), Address::Tcp(b)) => a == b,
            _ => false,
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::Unix { path, .. } => write!(f, "{}", path.display()),
            Address::Tcp(addr) => write!(f, "{addr}"),
        }
    }
}

/// One configured listener.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub role: Role,
    pub address: Address,
}

/// The endpoints of a configuration, with the groups resolved; the metrics
/// listener, if any, comes last.
pub fn endpoints(cfg: &crate::config::Config) -> Result<Vec<Endpoint>, String> {
    let api = &cfg.api;
    let gid = |name: &str| -> Result<u32, String> {
        crate::identity::group(name)
            .map_err(|e| format!("group {name:?}: {e}"))?
            .ok_or_else(|| format!("group {name:?} does not exist"))
    };
    let mut v = vec![Endpoint {
        role: Role::Control,
        address: Address::Unix {
            path: api.socket.clone(),
            access: Access {
                gid: Some(gid(&api.group)?),
            },
        },
    }];
    if let Some(path) = &api.status_socket {
        v.push(Endpoint {
            role: Role::Status,
            address: Address::Unix {
                path: path.clone(),
                access: Access {
                    gid: api.status_group.as_deref().map(gid).transpose()?,
                },
            },
        });
    }
    if let Some(addr) = cfg.metrics_listen {
        v.push(Endpoint {
            role: Role::Metrics,
            address: Address::Tcp(addr),
        });
    }
    Ok(v)
}

/// What the handlers read, and the queue of the State task's commands.
#[derive(Clone)]
pub struct Shared {
    pub status: watch::Receiver<Arc<Status>>,
    pub ring: Arc<Mutex<Ring>>,
    pub latest: watch::Receiver<u64>,
    pub started: std::time::Instant,
    pub orders: mpsc::Sender<Order>,
    /// Notification tests (FR-MAIL-4), outside the State task.
    pub tester: Arc<crate::notifytest::Tester>,
    /// The notifiers' failures, for the metrics (FR-MET-2).
    pub failures: Arc<crate::metrics::Failures>,
    /// The State task's totals, for the metrics (FR-MET-2).
    pub totals: Arc<std::sync::Mutex<crate::metrics::Totals>>,
}

/// A command of the control socket (FR-API-3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Drain { uplink: String, force: bool },
    Undrain { uplink: String },
    Forget { uplink: String },
    Reload,
}

/// The State task's answer to a command.
#[derive(Clone, Debug, PartialEq)]
pub struct Answer {
    pub code: StatusCode,
    pub body: serde_json::Value,
}

impl Answer {
    pub fn new(code: StatusCode, body: serde_json::Value) -> Answer {
        Answer { code, body }
    }

    pub fn error(code: StatusCode, message: impl Into<String>) -> Answer {
        Answer::new(code, serde_json::json!({ "error": message.into() }))
    }
}

/// A command and where its answer goes.
pub struct Order {
    pub action: Action,
    pub reply: oneshot::Sender<Answer>,
}

/// Commands waiting for the State task (FR-API-4: bounded, a full queue is
/// refused).
pub const ORDER_QUEUE: usize = 8;
/// Request bodies (FR-API-4).
const BODY_BYTES: usize = 64 * 1024;

/// Commands of the listener manager, which runs on the I/O runtime.
pub enum Command {
    /// Binds the sockets of new paths and addresses (a reload, FR-API-1,
    /// FR-MET-1); nothing changes for clients until the commit.
    Prepare {
        endpoints: Vec<Endpoint>,
        reply: oneshot::Sender<Result<(), String>>,
    },
    /// Serves the prepared configuration: new sockets start, removed ones
    /// close with their connections, changed access applies and closes the
    /// existing connections.
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

/// A bound listener, not served yet.
struct Bound {
    endpoint: Endpoint,
    listener: Accepting,
    /// The socket file of a Unix endpoint.
    published: Option<Published>,
}

/// A serving listener.
struct Listener {
    endpoint: Endpoint,
    published: Option<Published>,
    /// Stops the listener and its connections.
    stop: watch::Sender<bool>,
    /// Advanced when the access policy changes: the connections admitted
    /// under the old one close (FR-API-1). Never advanced for the metrics,
    /// which have no access policy.
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
    let mut prepared: Vec<Bound> = Vec::new();
    let mut next: Option<Vec<Endpoint>> = None;
    // At startup the record identifies the sockets of an earlier instance.
    let known = record.read();
    let mut started = Ok(());
    for e in initial {
        match bind(e, &known).await {
            Ok(b) => serving.push(serve(b, &shared)),
            Err(err) => {
                started = Err(err);
                break;
            }
        }
    }
    let save = |serving: &[Listener], prepared: &[Bound]| {
        let list: Vec<Published> = serving
            .iter()
            .filter_map(|l| l.published.clone())
            .chain(prepared.iter().filter_map(|b| b.published.clone()))
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
                discard(&mut prepared);
                let mut result = Ok(());
                for e in &endpoints {
                    match serving.iter().find(|l| l.endpoint.address.same_place(&e.address)) {
                        // FR-API-1: an existing path never changes role.
                        Some(l) if l.endpoint.role != e.role => {
                            result = Err(format!(
                                "{} cannot change from the {:?} to the {:?} socket on reload",
                                e.address, l.endpoint.role, e.role
                            ));
                            break;
                        }
                        Some(_) => {}
                        // FR-MET-1: a new metrics address too is bound
                        // before the commit; a bind failure rejects the
                        // reload.
                        None => match bind(e.clone(), &[]).await {
                            Ok(b) => prepared.push(b),
                            Err(err) => {
                                result = Err(err);
                                break;
                            }
                        },
                    }
                }
                if result.is_err() {
                    discard(&mut prepared);
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
                    match wanted.iter().find(|e| e.address.same_place(&l.endpoint.address)) {
                        Some(e) if *e == l.endpoint => kept.push(l),
                        // A changed access applies to the socket file;
                        // connections admitted under the old policy close.
                        Some(e) => {
                            if let Address::Unix { path, access } = e.address.clone() {
                                let applied =
                                    tokio::task::spawn_blocking(move || socket::apply_access(&path, access)).await;
                                if !matches!(applied, Ok(Ok(()))) {
                                    // Never served under the old access:
                                    // closed, and bound again by the next
                                    // reload (FR-API-1).
                                    error!(path = %e.address, "changing the access of an API socket failed: the socket is closed");
                                    close(l);
                                    continue;
                                }
                            }
                            // The listening socket stays; its connections
                            // are cut.
                            l.cut.send_modify(|g| *g += 1);
                            kept.push(Listener {
                                endpoint: e.clone(),
                                ..l
                            });
                        }
                        // The old metrics address and its connections
                        // close too.
                        None => close(l),
                    }
                }
                serving = kept;
                for b in prepared.drain(..) {
                    serving.push(serve(b, &shared));
                }
                save(&serving, &prepared);
            }
            Command::Rollback => {
                next = None;
                discard(&mut prepared);
                save(&serving, &prepared);
            }
            Command::Shutdown(done) => {
                for l in serving.drain(..) {
                    close(l);
                }
                discard(&mut prepared);
                save(&serving, &prepared);
                let _ = done.send(());
                return;
            }
        }
    }
}

fn close(l: Listener) {
    let _ = l.stop.send(true);
    if let Some(p) = &l.published {
        socket::unpublish(p);
    }
}

/// Removes what a preparation bound.
fn discard(prepared: &mut Vec<Bound>) {
    for b in prepared.drain(..) {
        if let Some(p) = &b.published {
            socket::unpublish(p);
        }
    }
}

async fn bind(endpoint: Endpoint, known: &[Published]) -> Result<Bound, String> {
    let address = endpoint.address.clone();
    let known = known.to_vec();
    let (listener, published) = tokio::task::spawn_blocking(move || match address {
        Address::Unix { path, access } => socket::bind(&path, access, &known)
            .map(|(l, p)| (Accepting::Unix(l), Some(p)))
            .map_err(|err| err.to_string()),
        Address::Tcp(addr) => std::net::TcpListener::bind(addr)
            .map(|l| (Accepting::Tcp(l), None))
            .map_err(|e| format!("metrics.listen {addr}: {e}")),
    })
    .await
    .map_err(|err| err.to_string())??;
    Ok(Bound {
        endpoint,
        listener,
        published,
    })
}

fn serve(b: Bound, shared: &Shared) -> Listener {
    let Bound {
        endpoint,
        listener,
        published,
    } = b;
    let (stop, stopped) = watch::channel(false);
    let (cut, cuts) = watch::channel(0);
    let role = endpoint.role;
    let shared = shared.clone();
    tokio::spawn(async move {
        if let Err(e) = accept_loop(listener, role, shared, stopped, cuts).await {
            match role {
                Role::Metrics => warn!("metrics listener stopped: {e}"),
                Role::Control | Role::Status => warn!("API listener stopped: {e}"),
            }
        }
    });
    match &endpoint.address {
        Address::Unix { path, .. } => info!(path = %path.display(), role = ?role, "API socket listening"),
        Address::Tcp(addr) => info!(%addr, "metrics listening"),
    }
    Listener {
        endpoint,
        published,
        stop,
        cut,
    }
}

/// A listening socket of the API or of the metrics.
enum Accepting {
    Unix(std::os::unix::net::UnixListener),
    Tcp(std::net::TcpListener),
}

/// A connection's stream.
trait Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Stream for T {}

enum Listening {
    Unix(tokio::net::UnixListener),
    Tcp(tokio::net::TcpListener),
}

impl Listening {
    async fn accept(&self) -> std::io::Result<Box<dyn Stream>> {
        Ok(match self {
            Listening::Unix(l) => Box::new(l.accept().await?.0),
            Listening::Tcp(l) => Box::new(l.accept().await?.0),
        })
    }
}

async fn accept_loop(
    listener: Accepting,
    role: Role,
    shared: Shared,
    mut stopped: watch::Receiver<bool>,
    cuts: watch::Receiver<u64>,
) -> std::io::Result<()> {
    let listener = match listener {
        Accepting::Unix(l) => {
            l.set_nonblocking(true)?;
            Listening::Unix(tokio::net::UnixListener::from_std(l)?)
        }
        Accepting::Tcp(l) => {
            l.set_nonblocking(true)?;
            Listening::Tcp(tokio::net::TcpListener::from_std(l)?)
        }
    };
    let admitted = Arc::new(Semaphore::new(CONNECTIONS));
    let mut refused = Diagnostics::default();
    loop {
        tokio::select! {
            _ = stopped.changed() => return Ok(()),
            r = listener.accept() => {
                let Ok(stream) = r else { continue };
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
    stream: Box<dyn Stream>,
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

/// A command on an uplink (FR-API-3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Drain,
    Undrain,
    Forget,
}

/// The endpoints of the API and of the metrics.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Route {
    Status,
    Events,
    Metrics,
    Reload,
    NotifyTest,
    Uplink { name: String, op: Op },
}

impl Route {
    fn parse(path: &str) -> Option<Route> {
        Some(match path {
            "/v1/status" => Route::Status,
            "/v1/events" => Route::Events,
            "/metrics" => Route::Metrics,
            "/v1/reload" => Route::Reload,
            "/v1/notify-test" => Route::NotifyTest,
            _ => {
                let (name, op) = path.strip_prefix("/v1/uplinks/")?.split_once('/')?;
                let op = match op {
                    "drain" => Op::Drain,
                    "undrain" => Op::Undrain,
                    "forget" => Op::Forget,
                    _ => return None,
                };
                if name.is_empty() {
                    return None;
                }
                Route::Uplink {
                    name: name.to_owned(),
                    op,
                }
            }
        })
    }

    /// The listeners that expose the route, and its method (IMPL-11,
    /// FR-API-3, FR-MET-1).
    fn rule(&self) -> (&'static [Role], Method) {
        match self {
            Route::Status | Route::Events => (&[Role::Control, Role::Status], Method::GET),
            Route::Metrics => (&[Role::Metrics], Method::GET),
            Route::Reload | Route::NotifyTest | Route::Uplink { .. } => (&[Role::Control], Method::POST),
        }
    }
}

async fn handle(req: Request<Incoming>, role: Role, shared: &Shared, deadline: &watch::Sender<Instant>) -> Reply {
    let Some(route) = Route::parse(req.uri().path()) else {
        return error(StatusCode::NOT_FOUND, "not found");
    };
    let (roles, method) = route.rule();
    if !roles.contains(&role) {
        return error(StatusCode::NOT_FOUND, "not found");
    }
    if req.method() != method {
        return error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
    }
    let query = req.uri().query().unwrap_or("").to_owned();
    // A write endpoint's body is read within its bound.
    let force = if method == Method::POST {
        match read_body(req, &route).await {
            Ok(force) => force,
            Err((code, e)) => return error(code, &e),
        }
    } else {
        false
    };
    match route {
        Route::Status => status(shared),
        Route::Events => events(&query, shared, deadline).await,
        Route::Metrics => metrics(shared),
        Route::NotifyTest => notify_test(shared, deadline).await,
        Route::Reload => command(Action::Reload, shared).await,
        Route::Uplink { name: uplink, op } => {
            let action = match op {
                Op::Drain => Action::Drain { uplink, force },
                Op::Undrain => Action::Undrain { uplink },
                Op::Forget => Action::Forget { uplink },
            };
            command(action, shared).await
        }
    }
}

/// The body of a write endpoint, within its bound; `force` for a drain.
async fn read_body(req: Request<Incoming>, route: &Route) -> Result<bool, (StatusCode, String)> {
    use http_body_util::{BodyExt, Limited};

    let body = match Limited::new(req.into_body(), BODY_BYTES).collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => return Err((StatusCode::PAYLOAD_TOO_LARGE, "request body too large".to_owned())),
    };
    parse_body(route, &body).map_err(|e| (StatusCode::BAD_REQUEST, e))
}

/// A command goes to the State task, the answer comes back before the
/// deadline.
async fn command(action: Action, shared: &Shared) -> Reply {
    let (reply, answer) = oneshot::channel();
    if shared.orders.try_send(Order { action, reply }).is_err() {
        return error(StatusCode::SERVICE_UNAVAILABLE, "too many commands in progress");
    }
    // The State task answers within the deadline; the margin leaves time
    // for the response write.
    match tokio::time::timeout(DEADLINE - Duration::from_secs(1), answer).await {
        Ok(Ok(a)) => reply_json(a.code, &a.body),
        Ok(Err(_)) => error(StatusCode::SERVICE_UNAVAILABLE, "the daemon is stopping"),
        Err(_) => error(
            StatusCode::GATEWAY_TIMEOUT,
            "no answer in time; the command may still complete",
        ),
    }
}

/// `POST /v1/notify-test` (FR-MAIL-4): one test at a time (429), refused
/// before any channel starts when the email notifier cannot take it (503);
/// its budget extends the deadline, the response write keeps its own. A
/// disconnected client cancels nothing: the test runs to its end once.
async fn notify_test(shared: &Shared, deadline: &watch::Sender<Instant>) -> Reply {
    use crate::notifytest::Refusal;

    let tester = Arc::clone(&shared.tester);
    let Ok(running) = tester.begin() else {
        return error(StatusCode::TOO_MANY_REQUESTS, "a notification test is running");
    };
    let _ = deadline.send(Instant::now() + tester.budget() + DEADLINE);
    let task = tokio::spawn(async move {
        let r = tester.run().await;
        drop(running);
        r
    });
    let r = task.await;
    let _ = deadline.send(Instant::now() + DEADLINE);
    match r {
        Ok(Ok(reports)) => reply_json(StatusCode::OK, &serde_json::json!({ "channels": reports })),
        Ok(Err(Refusal::Busy)) => error(StatusCode::TOO_MANY_REQUESTS, "a notification test is running"),
        Ok(Err(Refusal::Unavailable)) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "the email notifier cannot take a test now",
        ),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "the test did not complete"),
    }
}

fn reply_json(code: StatusCode, body: &serde_json::Value) -> Reply {
    reply(code, body.to_string())
}

/// The body of a write endpoint: only a drain takes one, `{"force": bool}`;
/// whitespace is no body.
fn parse_body(route: &Route, body: &[u8]) -> Result<bool, String> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DrainBody {
        #[serde(default)]
        force: bool,
    }
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(false);
    }
    if !matches!(route, Route::Uplink { op: Op::Drain, .. }) {
        return Err("this endpoint takes no body".to_owned());
    }
    let b: DrainBody = serde_json::from_slice(body).map_err(|e| format!("body: {e}"))?;
    Ok(b.force)
}

/// `GET /metrics` (FR-MET-2), in the Prometheus text format.
fn metrics(shared: &Shared) -> Reply {
    let s = Arc::clone(&shared.status.borrow());
    let mut r = reply(
        StatusCode::OK,
        crate::metrics::render(&s, &shared.totals, &shared.failures),
    );
    r.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    r
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
    fn routes_are_recognised() {
        let control = |path: &str| Route::parse(path).is_some_and(|r| r.rule().0 == [Role::Control]);
        assert!(control("/v1/reload"));
        assert!(control("/v1/notify-test"));
        assert!(control("/v1/uplinks/a/drain"));
        assert!(control("/v1/uplinks/fiber/forget"));
        assert!(!control("/v1/uplinks//drain"));
        assert!(!control("/v1/uplinks/a/delete"));
        assert!(!control("/v1/uplinks/a/b/drain"));
        assert!(!control("/v1/status"));
        assert_eq!(
            Route::parse("/v1/uplinks/fiber/undrain"),
            Some(Route::Uplink {
                name: "fiber".into(),
                op: Op::Undrain
            })
        );
        assert_eq!(
            Route::parse("/v1/status").unwrap().rule(),
            (&[Role::Control, Role::Status][..], Method::GET)
        );
        assert_eq!(
            Route::parse("/metrics").unwrap().rule(),
            (&[Role::Metrics][..], Method::GET)
        );
        assert_eq!(Route::parse("/v1/nothing"), None);
    }

    #[test]
    fn bodies_are_parsed() {
        let drain = Route::Uplink {
            name: "a".into(),
            op: Op::Drain,
        };
        assert_eq!(parse_body(&drain, br#"{"force": true}"#), Ok(true));
        assert_eq!(parse_body(&drain, b""), Ok(false));
        assert!(parse_body(&drain, br#"{"force": 1}"#).is_err());
        assert!(parse_body(&drain, br#"{"other": true}"#).is_err());
        assert!(parse_body(&Route::Reload, b"x").is_err());
        assert_eq!(parse_body(&Route::Reload, b" \n"), Ok(false));
        assert!(parse_body(&Route::NotifyTest, br#"{"force": true}"#).is_err());
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
