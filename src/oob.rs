//! Out-of-band interaction server ("Collaborator" equivalent).
//!
//! The built-in server is HTTP-only. It is useful when the target can reach the
//! machine running burpcli (localhost, a lab network, or a public reverse
//! proxy). DNS callbacks require delegating a domain and are intentionally out
//! of scope; see docs/oob.md.

use crate::http::client::{self, ClientOptions};
use crate::http::Request;
use crate::storage::Project;
use crate::util::{now_rfc3339, random_token};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Provider used by active checks (SSRF/XXE) to create and poll callbacks.
pub trait OobProvider: Send + Sync {
    fn new_token(&self) -> String;
    fn payload_url(&self, token: &str) -> String;
    fn wait_for_hit(&self, token: &str, timeout: Duration) -> bool;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Interaction {
    pub ts: String,
    pub token: String,
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub query: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub remote: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body: String,
}

struct OobState {
    events: Mutex<Vec<Interaction>>,
    shutdown: AtomicBool,
    control: String,
    log: Option<PathBuf>,
}

pub struct OobServer {
    base_url: String,
    port: u16,
    state: Arc<OobState>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl OobServer {
    pub fn start(
        bind: &str,
        port: u16,
        public_url: Option<String>,
        log: Option<PathBuf>,
    ) -> Result<Self> {
        let listener = TcpListener::bind((bind, port))
            .with_context(|| format!("cannot bind OOB listener on {bind}:{port}"))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let base_url = public_url.unwrap_or_else(|| {
            let host = if bind == "0.0.0.0" || bind == "::" {
                "127.0.0.1"
            } else {
                bind
            };
            format!("http://{host}:{port}")
        });
        if let Some(path) = &log {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
        }
        let state = Arc::new(OobState {
            events: Mutex::new(Vec::new()),
            shutdown: AtomicBool::new(false),
            control: random_token(24),
            log,
        });
        let thread_state = state.clone();
        let thread = std::thread::spawn(move || {
            while !thread_state.shutdown.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, remote)) => {
                        // Accepted sockets inherit the listener's non-blocking
                        // mode on Windows; callbacks use blocking reads.
                        let _ = stream.set_nonblocking(false);
                        let state = thread_state.clone();
                        std::thread::spawn(move || {
                            if let Err(error) = handle_connection(stream, remote, &state) {
                                if std::env::var_os("BURPCLI_DEBUG").is_some() {
                                    eprintln!("[oob] connection error: {error}");
                                }
                            }
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(40));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            base_url,
            port,
            state,
            thread: Some(thread),
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn control_token(&self) -> &str {
        &self.state.control
    }

    pub fn events(&self) -> Vec<Interaction> {
        self.state
            .events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn wait_for_token(&self, token: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if self
                .state
                .events
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .any(|event| event.token == token)
            {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(75));
        }
    }

    pub fn stop(&mut self) {
        self.state.shutdown.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.join().ok();
        }
    }

    pub fn stopped(&self) -> bool {
        self.state.shutdown.load(Ordering::Relaxed)
    }

    pub fn clear(&self) {
        self.state
            .events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}

impl Drop for OobServer {
    fn drop(&mut self) {
        self.stop();
    }
}

impl OobProvider for OobServer {
    fn new_token(&self) -> String {
        random_token(16)
    }

    fn payload_url(&self, token: &str) -> String {
        format!("{}/oob/{}", self.base_url.trim_end_matches('/'), token)
    }

    fn wait_for_hit(&self, token: &str, timeout: Duration) -> bool {
        self.wait_for_token(token, timeout)
    }
}

fn handle_connection(
    mut stream: TcpStream,
    remote: std::net::SocketAddr,
    state: &OobState,
) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    let content_length = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0)
        .min(1024 * 1024);
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).ok();
    }
    let (path, query) = target
        .split_once('?')
        .map(|(p, q)| (p.to_string(), q.to_string()))
        .unwrap_or((target.clone(), String::new()));

    if path.starts_with("/__burpcli/") {
        match path.as_str() {
            "/__burpcli/health" => {
                write_response(&mut stream, 200, "application/json", b"{\"ok\":true}")?;
            }
            "/__burpcli/poll" => {
                let token = query_param(&query, "token");
                let events = state.events.lock().unwrap_or_else(|e| e.into_inner());
                let filtered: Vec<&Interaction> = events
                    .iter()
                    .filter(|event| token.as_deref().map(|t| event.token == t).unwrap_or(true))
                    .collect();
                let json = serde_json::to_vec(&filtered)?;
                drop(events);
                write_response(&mut stream, 200, "application/json", &json)?;
            }
            "/__burpcli/shutdown" => {
                let token = query_param(&query, "token").unwrap_or_default();
                if token == state.control {
                    state.shutdown.store(true, Ordering::Relaxed);
                    write_response(&mut stream, 200, "text/plain", b"bye")?;
                } else {
                    write_response(&mut stream, 403, "text/plain", b"forbidden")?;
                }
            }
            _ => write_response(&mut stream, 404, "text/plain", b"not found")?,
        }
        return Ok(());
    }

    let token = if let Some(rest) = path.strip_prefix("/oob/") {
        rest.split('/').next().unwrap_or("").to_string()
    } else {
        query_param(&query, "token")
            .or_else(|| {
                headers
                    .iter()
                    .find(|(n, _)| n.eq_ignore_ascii_case("host"))
                    .map(|(_, v)| v.clone())
            })
            .unwrap_or_else(|| path.trim_matches('/').to_string())
    };
    let host = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.clone())
        .unwrap_or_default();
    let interaction = Interaction {
        ts: now_rfc3339(),
        token,
        method,
        path,
        query,
        host,
        remote: remote.to_string(),
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    };
    if let Some(log) = &state.log {
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)
        {
            if serde_json::to_writer(&mut file, &interaction).is_ok() {
                let _ = file.write_all(b"\n");
            }
        }
    }
    state
        .events
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(interaction);
    write_response(
        &mut stream,
        200,
        "text/html",
        b"<html><body>burpcli collaborator</body></html>",
    )?;
    Ok(())
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "OK",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

fn query_param(query: &str, name: &str) -> Option<String> {
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == name {
            return Some(
                percent_encoding::percent_decode_str(value)
                    .decode_utf8_lossy()
                    .into_owned(),
            );
        }
    }
    None
}

pub struct RemoteOob {
    base_url: String,
}

impl RemoteOob {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }
}

impl OobProvider for RemoteOob {
    fn new_token(&self) -> String {
        random_token(16)
    }

    fn payload_url(&self, token: &str) -> String {
        format!("{}/oob/{}", self.base_url, token)
    }

    fn wait_for_hit(&self, token: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if poll_remote(&self.base_url, token)
                .map(|e| !e.is_empty())
                .unwrap_or(false)
            {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

fn poll_remote(base_url: &str, token: &str) -> Result<Vec<Interaction>> {
    let url = format!(
        "{}/__burpcli/poll?token={}",
        base_url,
        percent_encoding::utf8_percent_encode(token, percent_encoding::NON_ALPHANUMERIC)
    );
    let parsed = url::Url::parse(&url)?;
    let mut request = Request::from_url("GET", &parsed, Vec::new(), None);
    request.scheme = Some(parsed.scheme().to_string());
    let options = ClientOptions {
        timeout: Duration::from_secs(2),
        ..ClientOptions::default()
    };
    let response = client::send(&request, &options)?;
    if response.response.status != 200 {
        bail!("OOB poll returned status {}", response.response.status);
    }
    Ok(serde_json::from_slice(&response.response.body).unwrap_or_default())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaemonState {
    pub pid: u32,
    pub bind: String,
    pub port: u16,
    pub base_url: String,
    pub control: String,
    pub started: String,
}

pub fn state_path(project: &Project) -> PathBuf {
    project.root.join("oob").join("state.json")
}

pub fn events_path(project: &Project) -> PathBuf {
    project.root.join("oob").join("events.jsonl")
}

pub fn daemon_state(project: &Project) -> Result<Option<DaemonState>> {
    let path = state_path(project);
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&text).ok())
}

pub fn start_daemon(
    project: &Project,
    bind: &str,
    port: u16,
    public_url: Option<&str>,
) -> Result<DaemonState> {
    if let Some(state) = daemon_state(project)? {
        if health(&state.bind, state.port) {
            return Ok(state);
        }
        std::fs::remove_file(state_path(project)).ok();
    }
    let exe = std::env::current_exe().context("cannot locate burpcli executable")?;
    let mut command = std::process::Command::new(exe);
    command
        .arg("__oob-serve")
        .arg("--project")
        .arg(&project.root)
        .arg("--bind")
        .arg(bind)
        .arg("--port")
        .arg(port.to_string());
    if let Some(url) = public_url {
        command.arg("--public-url").arg(url);
    }
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let mut child = command.spawn().context("cannot start OOB daemon")?;
    for _ in 0..100 {
        std::thread::sleep(Duration::from_millis(50));
        if let Ok(Some(state)) = daemon_state(project) {
            if health(&state.bind, state.port) {
                return Ok(state);
            }
        }
    }
    let _ = child.kill();
    bail!("OOB daemon did not start within 5 seconds");
}

pub fn stop_daemon(project: &Project) -> Result<bool> {
    let Some(state) = daemon_state(project)? else {
        return Ok(false);
    };
    let url = format!(
        "http://127.0.0.1:{}/__burpcli/shutdown?token={}",
        state.port, state.control
    );
    let parsed = url::Url::parse(&url)?;
    let mut request = Request::from_url("GET", &parsed, Vec::new(), None);
    request.scheme = Some("http".into());
    let options = ClientOptions {
        timeout: Duration::from_secs(2),
        ..ClientOptions::default()
    };
    let _ = client::send(&request, &options);
    for _ in 0..50 {
        if !health(&state.bind, state.port) {
            std::fs::remove_file(state_path(project)).ok();
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    std::fs::remove_file(state_path(project)).ok();
    Ok(true)
}

pub fn daemon_events(project: &Project, token: Option<&str>) -> Result<Vec<Interaction>> {
    let path = events_path(project);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(path)?;
    let mut events = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(event) = serde_json::from_str::<Interaction>(line) {
            if token.map(|t| event.token == t).unwrap_or(true) {
                events.push(event);
            }
        }
    }
    Ok(events)
}

pub fn clear_daemon_events(project: &Project) -> Result<()> {
    std::fs::create_dir_all(project.root.join("oob")).ok();
    std::fs::File::create(events_path(project))?;
    Ok(())
}

pub fn serve_forever(
    project: &Project,
    bind: &str,
    port: u16,
    public_url: Option<String>,
) -> Result<()> {
    let events = events_path(project);
    let mut server = OobServer::start(bind, port, public_url, Some(events))?;
    let state = DaemonState {
        pid: std::process::id(),
        bind: bind.to_string(),
        port: server.port(),
        base_url: server.base_url().to_string(),
        control: server.control_token().to_string(),
        started: now_rfc3339(),
    };
    crate::config::atomic_write(
        &state_path(project),
        serde_json::to_string_pretty(&state)?.as_bytes(),
    )?;
    while !server.stopped() {
        std::thread::sleep(Duration::from_millis(200));
    }
    server.stop();
    std::fs::remove_file(state_path(project)).ok();
    Ok(())
}

fn health(bind: &str, port: u16) -> bool {
    use std::net::ToSocketAddrs;
    let host = if bind == "0.0.0.0" || bind == "::" {
        "127.0.0.1".to_string()
    } else {
        bind.to_string()
    };
    let Ok(mut addresses) = (host.as_str(), port).to_socket_addrs() else {
        return false;
    };
    let Some(address) = addresses.next() else {
        return false;
    };
    match TcpStream::connect_timeout(&address, Duration::from_millis(400)) {
        Ok(mut stream) => {
            let request = format!(
                "GET /__burpcli/health HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            );
            if stream.write_all(request.as_bytes()).is_err() {
                return false;
            }
            stream
                .set_read_timeout(Some(Duration::from_millis(500)))
                .ok();
            let mut buffer = [0u8; 64];
            match stream.read(&mut buffer) {
                Ok(n) => String::from_utf8_lossy(&buffer[..n]).contains("200"),
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_callbacks_and_filters_tokens() {
        let mut server = OobServer::start("127.0.0.1", 0, None, None).unwrap();
        let base = server.base_url().to_string();
        let token = server.new_token();
        let client = ClientOptions::default();
        let url = url::Url::parse(&server.payload_url(&token)).unwrap();
        let request = Request::from_url("GET", &url, Vec::new(), None);
        client::send(&request, &client).unwrap();
        assert!(server.wait_for_token(&token, Duration::from_secs(2)));
        let events = server.events();
        assert_eq!(events[0].token, token);
        assert!(events[0].path.contains("/oob/"));
        assert!(base.contains("127.0.0.1"));
        server.stop();
    }

    #[test]
    fn remote_provider_polls() {
        let mut server = OobServer::start("127.0.0.1", 0, None, None).unwrap();
        let remote = RemoteOob::new(server.base_url());
        let token = remote.new_token();
        let url = url::Url::parse(&remote.payload_url(&token)).unwrap();
        let request = Request::from_url("GET", &url, Vec::new(), None);
        client::send(&request, &ClientOptions::default()).unwrap();
        assert!(remote.wait_for_hit(&token, Duration::from_secs(2)));
        server.stop();
    }
}
