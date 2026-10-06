//! A test SMTP server for AS-34 and the msmtp system configuration that
//! submits to it from the router.
//!
//! The server (`polywan-testbed agent smtp DIR`, on the internet node)
//! offers STARTTLS with a certificate for [`HOST`] issued by a test
//! certificate authority, and AUTH PLAIN only over TLS; it accepts a
//! message only after a successful authentication. It reads its
//! certificate, key and password from `DIR` at each connection (a scenario
//! swaps them between submissions) and appends one JSON line per step of
//! every session to `DIR/events`: connection, TLS, authentication,
//! message (envelope and content), end. It needs no mail server package.
//!
//! [`Topology::msmtp_system`] writes the router's `/etc/netns` entries that
//! the daemon's unit mounts as `ip netns exec` does: the system
//! configuration `/etc/msmtprc` (TLS with certificate checking, the
//! password in the root-only `/etc/netrc`), the test authority as the
//! system's trusted certificates, and [`HOST`] in `/etc/hosts`.

use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::plan::{self, Family, Node};
use crate::topology::Topology;

/// The host name of the server: the certificate's name.
pub const HOST: &str = "smtp.polywan.test";
/// The submission port.
pub const PORT: u16 = 587;
/// The account of the router.
pub const USER: &str = "polywan-router";
/// The server's address (a test server address of the internet node).
pub fn address() -> IpAddr {
    plan::server(Family::V4, 25)
}

/// The largest message the server takes.
const MAX_MESSAGE: usize = 1 << 20;

/// One step of a session in `DIR/events`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Event {
    /// The session's number, from 1.
    pub session: u64,
    /// `connect`, `tls`, `tls_failed`, `auth`, `auth_failed`, `data`
    /// (the end of a message arrived), `message`, `end`.
    pub event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// A message: the envelope and the content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rcpt: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

/// Runs the server forever (`agent smtp DIR`).
pub fn serve(dir: &Path) -> Result<()> {
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), PORT))
        .with_context(|| format!("binding TCP {PORT}"))?;
    let events = Arc::new(Mutex::new(
        fs::File::options().create(true).append(true).open(dir.join("events"))?,
    ));
    eprintln!("polywan-testbed agent: SMTP on {PORT}");
    for (n, stream) in listener.incoming().flatten().enumerate() {
        let (dir, events) = (dir.to_owned(), events.clone());
        thread::spawn(move || {
            let log = |mut e: Event| {
                e.session = n as u64 + 1;
                if let (Ok(mut f), Ok(line)) = (events.lock(), serde_json::to_string(&e)) {
                    let _ = writeln!(f, "{line}");
                }
            };
            log(Event {
                event: "connect".into(),
                detail: stream.peer_addr().ok().map(|a| a.to_string()),
                ..Event::default()
            });
            let end = session(&dir, stream, &log);
            log(Event {
                event: "end".into(),
                detail: end.err().map(|e| format!("{e:#}")),
                ..Event::default()
            });
        });
    }
    Ok(())
}

/// The plain or encrypted connection of a session.
enum Conn {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ServerConnection, TcpStream>>),
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Conn::Plain(s) => s.read(buf),
            Conn::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Conn::Plain(s) => s.write(buf),
            Conn::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Conn::Plain(s) => s.flush(),
            Conn::Tls(s) => s.flush(),
        }
    }
}

/// The TLS configuration of a connection: `DIR/cert.pem` and `DIR/key.pem`.
fn tls_config(dir: &Path) -> Result<Arc<rustls::ServerConfig>> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let certs = CertificateDer::pem_file_iter(dir.join("cert.pem"))?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(dir.join("key.pem"))?;
    Ok(Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(certs, key)?,
    ))
}

/// One SMTP session (RFC 5321, RFC 3207, RFC 4954): EHLO, STARTTLS, AUTH
/// PLAIN, then transactions.
fn session(dir: &Path, stream: TcpStream, log: &dyn Fn(Event)) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut r = BufReader::new(Conn::Plain(stream));
    let reply = |r: &mut BufReader<Conn>, text: &str| -> Result<()> {
        r.get_mut().write_all(format!("{text}\r\n").as_bytes())?;
        Ok(r.get_mut().flush()?)
    };
    reply(&mut r, &format!("220 {HOST} ESMTP polywan-testbed"))?;
    let (mut tls, mut user) = (false, None::<String>);
    let (mut from, mut rcpt) = (None::<String>, Vec::new());
    loop {
        let mut line = String::new();
        if r.read_line(&mut line)? == 0 {
            anyhow::bail!("closed without QUIT");
        }
        let line = line.trim_end_matches(['\r', '\n']);
        let (verb, arg) = line.split_once(' ').unwrap_or((line, ""));
        match verb.to_ascii_uppercase().as_str() {
            "EHLO" => {
                let mut caps = vec![format!("250-{HOST}"), format!("250-SIZE {MAX_MESSAGE}")];
                if tls {
                    caps.push("250-AUTH PLAIN".into());
                } else {
                    caps.push("250-STARTTLS".into());
                }
                caps.push("250 8BITMIME".into());
                reply(&mut r, &caps.join("\r\n"))?;
            }
            "STARTTLS" if !tls => {
                anyhow::ensure!(r.buffer().is_empty(), "commands pipelined after STARTTLS");
                let config = tls_config(dir)?;
                reply(&mut r, "220 ready to start TLS")?;
                let Conn::Plain(stream) = r.into_inner() else {
                    unreachable!("TLS before STARTTLS")
                };
                let mut s = rustls::StreamOwned::new(rustls::ServerConnection::new(config)?, stream);
                // The handshake, before anything else.
                while s.conn.is_handshaking() {
                    if let Err(e) = s.conn.complete_io(&mut s.sock) {
                        log(Event {
                            event: "tls_failed".into(),
                            detail: Some(e.to_string()),
                            ..Event::default()
                        });
                        return Ok(());
                    }
                }
                log(Event {
                    event: "tls".into(),
                    detail: s.conn.protocol_version().map(|v| format!("{v:?}")),
                    ..Event::default()
                });
                r = BufReader::new(Conn::Tls(Box::new(s)));
                tls = true;
            }
            "AUTH" if tls && user.is_none() => {
                let mut words = arg.split_whitespace();
                if !words.next().is_some_and(|m| m.eq_ignore_ascii_case("PLAIN")) {
                    reply(&mut r, "504 5.5.4 only PLAIN")?;
                    continue;
                }
                let response = match words.next() {
                    Some(initial) => initial.to_owned(),
                    None => {
                        reply(&mut r, "334 ")?;
                        let mut l = String::new();
                        r.read_line(&mut l)?;
                        l.trim_end().to_owned()
                    }
                };
                // authzid NUL authcid NUL passwd
                let decoded = crate::sendmail::base64_decode(&response).unwrap_or_default();
                let mut parts = decoded.split(|b| *b == 0).skip(1);
                let (login, password) = (parts.next().unwrap_or_default(), parts.next().unwrap_or_default());
                let expected = fs::read(dir.join("password")).unwrap_or_default();
                let login = String::from_utf8_lossy(login).into_owned();
                if login == USER && password == expected.trim_ascii_end() {
                    log(Event {
                        event: "auth".into(),
                        detail: Some(login.clone()),
                        ..Event::default()
                    });
                    user = Some(login);
                    reply(&mut r, "235 2.7.0 authenticated")?;
                } else {
                    // The credentials are never recorded.
                    log(Event {
                        event: "auth_failed".into(),
                        detail: Some(login),
                        ..Event::default()
                    });
                    reply(&mut r, "535 5.7.8 authentication credentials invalid")?;
                }
            }
            "MAIL" if user.is_none() => reply(&mut r, "530 5.7.0 authentication required")?,
            "MAIL" => {
                from = Some(path(arg, "FROM:"));
                rcpt.clear();
                reply(&mut r, "250 2.1.0 ok")?;
            }
            "RCPT" if from.is_some() => {
                rcpt.push(path(arg, "TO:"));
                reply(&mut r, "250 2.1.5 ok")?;
            }
            "DATA" if !rcpt.is_empty() => {
                reply(&mut r, "354 end with <CRLF>.<CRLF>")?;
                let mut data = String::new();
                loop {
                    let mut l = String::new();
                    anyhow::ensure!(r.read_line(&mut l)? > 0, "closed during DATA");
                    let l = l.trim_end_matches(['\r', '\n']);
                    if l == "." {
                        break;
                    }
                    anyhow::ensure!(data.len() < MAX_MESSAGE, "message too large");
                    data.push_str(l.strip_prefix('.').unwrap_or(l));
                    data.push('\n');
                }
                log(Event {
                    event: "data".into(),
                    ..Event::default()
                });
                // A slow server: `DIR/delay` holds milliseconds.
                if let Some(ms) = fs::read_to_string(dir.join("delay"))
                    .ok()
                    .and_then(|d| d.trim().parse().ok())
                {
                    thread::sleep(Duration::from_millis(ms));
                }
                log(Event {
                    event: "message".into(),
                    from: from.take(),
                    rcpt: std::mem::take(&mut rcpt),
                    data: Some(data),
                    ..Event::default()
                });
                reply(&mut r, "250 2.0.0 queued")?;
            }
            "RSET" => {
                (from, rcpt) = (None, Vec::new());
                reply(&mut r, "250 2.0.0 ok")?;
            }
            "NOOP" => reply(&mut r, "250 2.0.0 ok")?,
            "QUIT" => {
                reply(&mut r, "221 2.0.0 bye")?;
                return Ok(());
            }
            _ => reply(&mut r, "503 5.5.1 bad sequence of commands")?,
        }
    }
}

/// The address of `FROM:<a> ...` or `TO:<a> ...`.
fn path(arg: &str, prefix: &str) -> String {
    let rest = match arg.get(..prefix.len()) {
        Some(p) if p.eq_ignore_ascii_case(prefix) => &arg[prefix.len()..],
        _ => arg,
    };
    let address = rest.split_whitespace().next().unwrap_or_default();
    address.trim_start_matches('<').trim_end_matches('>').to_owned()
}

/// A certificate authority of the tests and a server certificate for
/// [`HOST`] that it issued.
pub struct Pki {
    /// The authority's certificate (PEM).
    pub ca: String,
    pub cert: String,
    pub key: String,
}

impl Pki {
    pub fn new(name: &str) -> Result<Pki> {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
        let mut ca = CertificateParams::new(Vec::<String>::new())?;
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.distinguished_name.push(DnType::CommonName, name);
        let ca_key = KeyPair::generate()?;
        let ca_cert = ca.self_signed(&ca_key)?;
        let issuer = Issuer::new(ca, ca_key);
        let mut leaf = CertificateParams::new(vec![HOST.to_owned()])?;
        leaf.distinguished_name.push(DnType::CommonName, HOST);
        leaf.use_authority_key_identifier_extension = true;
        let key = KeyPair::generate()?;
        let cert = leaf.signed_by(&key, &issuer)?;
        Ok(Pki {
            ca: ca_cert.pem(),
            cert: cert.pem(),
            key: key.serialize_pem(),
        })
    }
}

/// The server of a run, killed when dropped.
pub struct Server {
    pub dir: PathBuf,
    child: Child,
}

impl Topology {
    /// Starts the server on the internet node with the certificate of
    /// `pki` and `password`, once it accepts connections.
    pub fn start_smtp_server(&self, pki: &Pki, password: &str) -> Result<Server> {
        let dir = self.dir().join("smtp");
        fs::create_dir_all(&dir)?;
        let server = Server {
            child: self.inet().spawn(
                &self.agent_bin().to_string_lossy(),
                ["agent".as_ref(), "smtp".as_ref(), dir.as_os_str()],
                &self.dir().join("smtp.log"),
            )?,
            dir,
        };
        server.serve(pki)?;
        server.password(password)?;
        let log = self.dir().join("smtp.log");
        self.wait_for("the SMTP server", Duration::from_secs(10), || {
            Ok(fs::read_to_string(&log).is_ok_and(|l| l.contains("SMTP on")))
        })?;
        Ok(server)
    }

    /// The msmtp system configuration of the router (see the module): an
    /// account for [`HOST`] with `from` as the sender of its own messages,
    /// `password` in `/etc/netrc`, `trusted` as the system's certificate
    /// bundle. Mounted by the units started afterwards; `/etc/msmtprc` and
    /// `/etc/netrc` are created empty on the host when absent (mount
    /// points).
    pub fn msmtp_system(&self, trusted: &str, password: &str) -> Result<()> {
        for p in ["/etc/msmtprc", "/etc/netrc"] {
            if !Path::new(p).exists() {
                fs::write(p, "")?;
                fs::set_permissions(p, fs::Permissions::from_mode(0o600))?;
            }
        }
        let etc = self.netns_etc(Node::Router);
        fs::create_dir_all(etc.join("ssl/certs"))?;
        fs::write(etc.join("msmtprc"), msmtprc())?;
        fs::set_permissions(etc.join("msmtprc"), fs::Permissions::from_mode(0o644))?;
        fs::write(
            etc.join("netrc"),
            format!("machine {HOST} login {USER} password {password}\n"),
        )?;
        fs::set_permissions(etc.join("netrc"), fs::Permissions::from_mode(0o600))?;
        fs::write(etc.join("ssl/certs/ca-certificates.crt"), trusted)?;
        let hosts = fs::read_to_string("/etc/hosts").unwrap_or_default();
        fs::write(etc.join("hosts"), format!("{hosts}\n{} {HOST}\n", address()))?;
        Ok(())
    }
}

/// The documented system configuration of msmtp.
pub fn msmtprc() -> String {
    format!(
        "# PolyWAN's notifications through a submission server (msmtp(1)).\n\
         defaults\n\
         auth on\n\
         tls on\n\
         tls_starttls on\n\
         tls_trust_file /etc/ssl/certs/ca-certificates.crt\n\
         syslog LOG_MAIL\n\
         \n\
         account polywan\n\
         host {HOST}\n\
         port {PORT}\n\
         user {USER}\n\
         # The password is in /etc/netrc (root only).\n\
         \n\
         account default : polywan\n"
    )
}

impl Server {
    /// Serves `pki`'s certificate from the next connection.
    pub fn serve(&self, pki: &Pki) -> Result<()> {
        fs::write(self.dir.join("cert.pem"), &pki.cert)?;
        fs::write(self.dir.join("key.pem"), &pki.key)?;
        Ok(())
    }

    /// Expects `password` from the next authentication.
    pub fn password(&self, password: &str) -> Result<()> {
        Ok(fs::write(self.dir.join("password"), password)?)
    }

    /// Answers the end of each message after `delay`.
    pub fn delay(&self, delay: Duration) -> Result<()> {
        Ok(fs::write(self.dir.join("delay"), delay.as_millis().to_string())?)
    }

    /// The events so far.
    pub fn events(&self) -> Result<Vec<Event>> {
        fs::read_to_string(self.dir.join("events"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).with_context(|| format!("SMTP event {l}")))
            .collect()
    }

    /// The events of `kind` so far.
    pub fn of(&self, kind: &str) -> Result<Vec<Event>> {
        Ok(self.events()?.into_iter().filter(|e| e.event == kind).collect())
    }

    /// Waits until `count` events of `kind` or more exist.
    pub fn wait(&self, t: &Topology, kind: &str, count: usize, timeout: Duration) -> Result<Vec<Event>> {
        t.wait_for(&format!("{count} SMTP {kind} events"), timeout, || {
            Ok(self.of(kind)?.len() >= count)
        })
        .with_context(|| format!("SMTP events: {:?}", self.events()))?;
        self.of(kind)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::path;

    #[test]
    fn paths() {
        assert_eq!(path("FROM:<a@b> SIZE=10", "FROM:"), "a@b");
        assert_eq!(path("to:<c@d>", "TO:"), "c@d");
        assert_eq!(path("FROM:<>", "FROM:"), "");
    }
}
