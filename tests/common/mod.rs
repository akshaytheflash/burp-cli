//! Shared integration-test helpers: a local threaded HTTP/HTTPS server.
//!
//! Every test talks to `127.0.0.1` on an ephemeral port; nothing here touches
//! the public internet.

#![allow(dead_code)]

use burpcli::http::{Request, Response};
use burpcli::storage::Project;
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tempfile::TempDir;

/// A disposable project rooted in a temporary directory.
pub struct TestProject {
    pub _dir: TempDir,
    pub project: Project,
}

impl TestProject {
    pub fn new() -> Self {
        let dir = TempDir::new().expect("temporary directory");
        let project = Project::create(&dir.path().join("project"), "integration")
            .expect("create test project");
        Self { _dir: dir, project }
    }
}

impl Default for TestProject {
    fn default() -> Self {
        Self::new()
    }
}

struct ServerState {
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    addr: SocketAddr,
    hits: Arc<Mutex<Vec<Request>>>,
}

impl Drop for ServerState {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// A one-request-per-connection HTTP server.
pub struct TestServer {
    state: ServerState,
}

impl TestServer {
    pub fn start<F>(handler: F) -> Self
    where
        F: Fn(&Request) -> Response + Send + Sync + 'static,
    {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind test server");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let addr = listener.local_addr().expect("local addr");
        let shutdown = Arc::new(AtomicBool::new(false));
        let hits = Arc::new(Mutex::new(Vec::new()));
        let thread_shutdown = shutdown.clone();
        let thread_hits = hits.clone();
        let handler = Arc::new(handler);
        let handle = thread::spawn(move || {
            while !thread_shutdown.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _remote)) => {
                        let _ = stream.set_nonblocking(false);
                        let handler = handler.clone();
                        let hits = thread_hits.clone();
                        thread::spawn(move || {
                            let _ = serve_connection(stream, &handler, &hits);
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            state: ServerState {
                shutdown,
                handle: Some(handle),
                addr,
                hits,
            },
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.state.addr, path)
    }

    pub fn addr(&self) -> SocketAddr {
        self.state.addr
    }

    pub fn hits(&self) -> Vec<Request> {
        self.state
            .hits
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
}

/// An HTTPS server using a caller-provided rustls configuration.
pub struct TlsTestServer {
    state: ServerState,
}

impl TlsTestServer {
    pub fn start<F>(config: Arc<ServerConfig>, handler: F) -> Self
    where
        F: Fn(&Request) -> Response + Send + Sync + 'static,
    {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind TLS test server");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let addr = listener.local_addr().expect("local addr");
        let shutdown = Arc::new(AtomicBool::new(false));
        let hits = Arc::new(Mutex::new(Vec::new()));
        let thread_shutdown = shutdown.clone();
        let thread_hits = hits.clone();
        let handler = Arc::new(handler);
        let handle = thread::spawn(move || {
            while !thread_shutdown.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _remote)) => {
                        let _ = stream.set_nonblocking(false);
                        let handler = handler.clone();
                        let hits = thread_hits.clone();
                        let config = config.clone();
                        thread::spawn(move || {
                            let Ok(connection) = ServerConnection::new(config) else {
                                return;
                            };
                            let mut stream = StreamOwned::new(connection, stream);
                            let _ = serve_connection(&mut stream, &handler, &hits);
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            state: ServerState {
                shutdown,
                handle: Some(handle),
                addr,
                hits,
            },
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("https://{}{}", self.state.addr, path)
    }

    pub fn hits(&self) -> Vec<Request> {
        self.state
            .hits
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }
}

fn serve_connection<S, F>(
    mut stream: S,
    handler: &Arc<F>,
    hits: &Arc<Mutex<Vec<Request>>>,
) -> std::io::Result<()>
where
    S: Read + Write,
    F: Fn(&Request) -> Response,
{
    let request = {
        let mut reader = BufReader::new(&mut stream);
        match read_request(&mut reader) {
            Ok(Some(request)) => request,
            _ => return Ok(()),
        }
    };
    hits.lock()
        .unwrap_or_else(|error| error.into_inner())
        .push(request.clone());
    let response = (handler.as_ref())(&request);
    let mut response = response;
    response.set_header("Content-Length", response.body.len().to_string());
    response.set_header("Connection", "close");
    stream.write_all(&response.to_bytes())?;
    stream.flush()
}

fn read_request<R: BufRead>(reader: &mut R) -> std::io::Result<Option<Request>> {
    let mut head = Vec::new();
    loop {
        let mut line = Vec::new();
        let read = reader.read_until(b'\n', &mut line)?;
        if read == 0 {
            return Ok(None);
        }
        if line == b"\r\n" || line == b"\n" {
            break;
        }
        head.extend_from_slice(&line);
        if head.len() > 1024 * 1024 {
            return Ok(None);
        }
    }
    let text = String::from_utf8_lossy(&head);
    let mut content_length = 0usize;
    for line in text.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }
    let mut raw = head;
    raw.extend_from_slice(b"\r\n");
    raw.extend_from_slice(&body);
    Ok(Request::parse(&raw).ok())
}

pub fn response(
    status: u16,
    reason: &str,
    content_type: &str,
    body: impl Into<Vec<u8>>,
) -> Response {
    let mut response = Response::new(status, reason);
    if !content_type.is_empty() {
        response.set_header("Content-Type", content_type);
    }
    response.body = body.into();
    response
}

pub fn html(body: impl Into<Vec<u8>>) -> Response {
    response(200, "OK", "text/html; charset=utf-8", body)
}

pub fn text(body: impl Into<Vec<u8>>) -> Response {
    response(200, "OK", "text/plain; charset=utf-8", body)
}

pub fn json(body: impl Into<Vec<u8>>) -> Response {
    response(200, "OK", "application/json", body)
}

pub fn redirect(location: &str) -> Response {
    let mut response = Response::new(302, "Found");
    response.set_header("Location", location);
    response.body = b"redirecting".to_vec();
    response
}

pub fn set_cookie(name: &str, value: &str) -> Response {
    let mut response = html("<html><title>cookie</title>ok</html>");
    response.set_header("Set-Cookie", format!("{name}={value}; Path=/"));
    response
}

/// Return a query parameter from the request target without needing `url()`.
pub fn query_param(request: &Request, name: &str) -> Option<String> {
    let query = request.target.split_once('?')?.1;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == name {
            return Some(percent_decode(value));
        }
    }
    None
}

pub fn form_param(request: &Request, name: &str) -> Option<String> {
    let body = String::from_utf8_lossy(&request.body);
    for pair in body.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == name {
            return Some(percent_decode(value));
        }
    }
    None
}

fn percent_decode(value: &str) -> String {
    percent_encoding::percent_decode_str(value)
        .decode_utf8_lossy()
        .into_owned()
}

/// A handler that reflects `q` verbatim (useful for XSS checks).
pub fn reflect_q(request: &Request) -> Response {
    let value = query_param(request, "q").unwrap_or_default();
    html(format!(
        "<html><head><title>search</title></head><body><p>results for {value}</p></body></html>"
    ))
}
