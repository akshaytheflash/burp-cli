//! Interactive proxy server with optional TLS interception.
//!
//! Architecture: one thread per client connection. Plain HTTP requests are
//! parsed, passed through session rules / plugins / intercept, forwarded with
//! the regular HTTP client, and recorded in the project history. `CONNECT`
//! requests are either tunnelled blindly or terminated with a generated leaf
//! certificate (MITM mode).

use super::ca::CertificateAuthority;
use crate::config::Rule;
use crate::http::client::{self, ClientOptions};
use crate::http::{CookieJar, Request, Response};
use crate::plugins::PluginManager;
use crate::scanner::IssueStore;
use crate::scope::Scope;
use crate::session;
use crate::storage::{HistoryStore, Project};
use crate::util::format_duration;
use anyhow::{anyhow, bail, Context, Result};
use rustls::{ServerConnection, StreamOwned};
use std::io::{BufRead, BufReader, IsTerminal, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_BODY: usize = 64 * 1024 * 1024;
const MAX_HEAD: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct ProxyOptions {
    pub bind: String,
    pub port: u16,
    pub mitm: bool,
    pub intercept_requests: bool,
    pub intercept_responses: bool,
    pub only_in_scope: bool,
    pub insecure: bool,
    pub timeout_ms: u64,
    pub verbose: bool,
}

impl Default for ProxyOptions {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1".into(),
            port: 8080,
            mitm: false,
            intercept_requests: false,
            intercept_responses: false,
            only_in_scope: false,
            insecure: true,
            timeout_ms: 30_000,
            verbose: true,
        }
    }
}

impl ProxyOptions {
    pub fn from_project(project: &Project) -> Self {
        let settings = &project.config.proxy;
        Self {
            bind: settings.bind.clone(),
            port: settings.port,
            mitm: settings.mitm,
            intercept_requests: settings.intercept_requests,
            intercept_responses: settings.intercept_responses,
            only_in_scope: settings.only_in_scope,
            insecure: true,
            timeout_ms: project.config.scan.timeout_ms,
            verbose: true,
        }
    }
}

pub struct ProxyServer {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    ca: Option<Arc<CertificateAuthority>>,
}

impl ProxyServer {
    pub fn start(project: &Project, options: &ProxyOptions) -> Result<Self> {
        project.ensure_dirs()?;
        let listener = TcpListener::bind((options.bind.as_str(), options.port))
            .with_context(|| format!("cannot bind proxy on {}:{}", options.bind, options.port))?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;

        let ca = if options.mitm {
            Some(Arc::new(CertificateAuthority::from_project(project)?))
        } else {
            None
        };
        let history = Arc::new(project.history()?);
        let issues = Arc::new(project.issue_store()?);
        let plugins = if project.config.plugins.enabled {
            PluginManager::optional_from_project(project)?
        } else {
            None
        };
        let scope = {
            let mut scope =
                Scope::new(&project.config.scope.include, &project.config.scope.exclude)?;
            scope.compile()?;
            scope
        };
        let auto_apply = project.config.session.auto_apply;
        let cookie_jar = if auto_apply {
            let state = crate::session::SessionState::from_project(project)?;
            Some(Arc::new(Mutex::new(state.cookies)))
        } else {
            None
        };
        let client = ClientOptions {
            timeout: Duration::from_millis(options.timeout_ms),
            connect_timeout: Duration::from_millis(options.timeout_ms.min(10_000)),
            tls: crate::http::TlsOptions {
                insecure: options.insecure,
                ..Default::default()
            },
            max_body: project.config.scan.max_body,
            cookie_jar: cookie_jar.clone(),
            ..ClientOptions::default()
        };
        let context = Arc::new(ProxyContext {
            client,
            history,
            issues,
            plugins,
            interceptor: Arc::new(Interceptor::new(
                options.intercept_requests,
                options.intercept_responses,
            )),
            rules: project.config.session.rules.clone(),
            headers: project.config.session.headers.clone(),
            cookie_jar,
            auto_apply,
            scope,
            only_in_scope: options.only_in_scope,
            mitm: options.mitm,
            ca: ca.clone(),
            verbose: options.verbose,
        });

        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = shutdown.clone();
        let thread_context = context.clone();
        let handle = std::thread::spawn(move || {
            while !thread_shutdown.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, remote)) => {
                        // On Windows an accepted socket inherits the listener's
                        // non-blocking mode; blocking I/O is required for the
                        // tunnel and TLS paths.
                        let _ = stream.set_nonblocking(false);
                        let context = thread_context.clone();
                        std::thread::spawn(move || {
                            if let Err(error) = handle_client(stream, remote, &context) {
                                if context.verbose {
                                    eprintln!("[proxy] client error: {error:#}");
                                }
                            }
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(25));
                    }
                    Err(error) => {
                        if thread_shutdown.load(Ordering::Relaxed) {
                            break;
                        }
                        eprintln!("[proxy] accept error: {error}");
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            }
        });

        Ok(Self {
            addr,
            shutdown,
            handle: Some(handle),
            ca,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn ca(&self) -> Option<&Arc<CertificateAuthority>> {
        self.ca.as_ref()
    }

    pub fn ca_pem(&self) -> Option<&str> {
        self.ca.as_ref().map(|ca| ca.pem())
    }

    pub fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            handle.join().ok();
        }
    }
}

impl Drop for ProxyServer {
    fn drop(&mut self) {
        self.stop();
    }
}

struct ProxyContext {
    client: ClientOptions,
    history: Arc<HistoryStore>,
    issues: Arc<IssueStore>,
    plugins: Option<Arc<PluginManager>>,
    interceptor: Arc<Interceptor>,
    rules: Vec<Rule>,
    headers: Vec<String>,
    cookie_jar: Option<Arc<Mutex<CookieJar>>>,
    auto_apply: bool,
    scope: Scope,
    only_in_scope: bool,
    mitm: bool,
    ca: Option<Arc<CertificateAuthority>>,
    verbose: bool,
}

impl ProxyContext {
    fn save_issues(&self, effects: &crate::plugins::PluginEffects) {
        for issue in &effects.issues {
            if let Err(error) = self.issues.append(issue) {
                if self.verbose {
                    eprintln!("[proxy] cannot save plugin issue: {error}");
                }
            }
        }
        for error in &effects.errors {
            if self.verbose {
                eprintln!("[proxy] plugin error: {error}");
            }
        }
    }

    fn record(
        &self,
        request: &Request,
        response: Option<&Response>,
        duration: Duration,
        tags: Vec<String>,
    ) {
        if let Err(error) = self.history.record(request, response, duration, tags) {
            if self.verbose {
                eprintln!("[proxy] cannot save history: {error}");
            }
        }
    }
}

enum Decision {
    Continue,
    Drop,
}

struct Interceptor {
    request_enabled: AtomicBool,
    response_enabled: AtomicBool,
    /// Serialises prompts when several connections need attention.
    prompt_lock: Mutex<()>,
}

impl Interceptor {
    fn new(requests: bool, responses: bool) -> Self {
        let interactive = std::io::stdin().is_terminal();
        Self {
            request_enabled: AtomicBool::new(requests && interactive),
            response_enabled: AtomicBool::new(responses && interactive),
            prompt_lock: Mutex::new(()),
        }
    }

    fn request(&self, request: &mut Request) -> Result<Decision> {
        if !self.request_enabled.load(Ordering::Relaxed) {
            return Ok(Decision::Continue);
        }
        let _guard = self.prompt_lock.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            println!();
            println!("{}", crate::util::bold("[intercept] request"));
            print!("{}", request.text());
            let answer = crate::util::prompt("[f]orward, [d]rop, [e]dit, [q]uit intercept: ")?;
            match answer.trim().to_ascii_lowercase().as_str() {
                "" | "f" | "forward" => return Ok(Decision::Continue),
                "d" | "drop" => return Ok(Decision::Drop),
                "e" | "edit" => {
                    if let Some(edited) = edit_bytes(&request.to_bytes(), "request")? {
                        match Request::parse(&edited) {
                            Ok(parsed) => *request = parsed,
                            Err(error) => eprintln!("invalid request: {error}"),
                        }
                    }
                }
                "q" | "quit" => {
                    self.request_enabled.store(false, Ordering::Relaxed);
                    self.response_enabled.store(false, Ordering::Relaxed);
                    return Ok(Decision::Continue);
                }
                other => eprintln!("unknown command '{other}'"),
            }
        }
    }

    fn response(&self, response: &mut Response) -> Result<Decision> {
        if !self.response_enabled.load(Ordering::Relaxed) {
            return Ok(Decision::Continue);
        }
        let _guard = self.prompt_lock.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            println!();
            println!("{}", crate::util::bold("[intercept] response"));
            print!("{}", response.text());
            let answer = crate::util::prompt("[f]orward, [d]rop, [e]dit, [q]uit intercept: ")?;
            match answer.trim().to_ascii_lowercase().as_str() {
                "" | "f" | "forward" => return Ok(Decision::Continue),
                "d" | "drop" => return Ok(Decision::Drop),
                "e" | "edit" => {
                    if let Some(edited) = edit_bytes(&response.to_bytes(), "response")? {
                        match Response::parse(&edited) {
                            Ok(parsed) => *response = parsed,
                            Err(error) => eprintln!("invalid response: {error}"),
                        }
                    }
                }
                "q" | "quit" => {
                    self.request_enabled.store(false, Ordering::Relaxed);
                    self.response_enabled.store(false, Ordering::Relaxed);
                    return Ok(Decision::Continue);
                }
                other => eprintln!("unknown command '{other}'"),
            }
        }
    }
}

fn edit_bytes(bytes: &[u8], label: &str) -> Result<Option<Vec<u8>>> {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("burpcli-{label}-{}.txt", std::process::id()));
    std::fs::write(&path, bytes)?;
    let editor = crate::config::editor();
    let args = crate::util::split_command(&editor);
    if args.is_empty() {
        return Ok(None);
    }
    let status = std::process::Command::new(&args[0])
        .args(&args[1..])
        .arg(&path)
        .status();
    let result = match status {
        Ok(status) if status.success() => Some(std::fs::read(&path)?),
        Ok(status) => {
            eprintln!("editor exited with {status}");
            None
        }
        Err(error) => {
            eprintln!("cannot start editor: {error}");
            None
        }
    };
    std::fs::remove_file(&path).ok();
    Ok(result)
}

fn handle_client(mut stream: TcpStream, remote: SocketAddr, ctx: &Arc<ProxyContext>) -> Result<()> {
    stream
        .set_read_timeout(Some(Duration::from_millis(
            ctx.client.timeout.as_millis() as u64
        )))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_millis(
            ctx.client.timeout.as_millis() as u64
        )))
        .ok();
    stream.set_nodelay(true).ok();
    let mut reader = BufReader::new(stream.try_clone()?);
    let Some(request) = read_request(&mut reader)? else {
        return Ok(());
    };
    if ctx.verbose {
        eprintln!("[proxy] {remote} {} {}", request.method, request.target);
    }
    if request.method.eq_ignore_ascii_case("CONNECT") {
        handle_connect(stream, reader, request, ctx)
    } else {
        let started = Instant::now();
        let bytes = process_request(request, ctx, started);
        stream.write_all(&bytes)?;
        stream.flush()?;
        Ok(())
    }
}

fn handle_connect(
    mut stream: TcpStream,
    reader: BufReader<TcpStream>,
    request: Request,
    ctx: &Arc<ProxyContext>,
) -> Result<()> {
    let target = request.target.clone();
    let (host, port) = crate::http::client::split_service(&target, true);
    if ctx.only_in_scope {
        let url = format!("https://{}:{}/", host, port);
        if !ctx.scope.allows_str(&url) {
            let body = b"CONNECT blocked by scope";
            write_simple(&mut stream, 403, "Forbidden", "text/plain", body)?;
            return Ok(());
        }
    }
    let established = b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: burpcli\r\n\r\n";
    stream.write_all(established)?;
    stream.flush()?;

    if ctx.mitm {
        let ca = ctx
            .ca
            .as_ref()
            .ok_or_else(|| anyhow!("MITM enabled but no CA is loaded"))?;
        let config = ca.server_config(&host)?;
        let connection = ServerConnection::new(config).context("TLS server setup failed")?;
        let tls = StreamOwned::new(connection, stream);
        serve_tls(tls, &host, ctx)?;
        return Ok(());
    }

    let address = (host.as_str(), port)
        .to_socket_addrs()
        .with_context(|| format!("cannot resolve {host}:{port}"))?
        .next()
        .ok_or_else(|| anyhow!("no address for {host}:{port}"))?;
    let mut upstream = TcpStream::connect_timeout(&address, Duration::from_secs(10))
        .with_context(|| format!("cannot connect to {host}:{port}"))?;
    let buffered = reader.buffer().to_vec();
    if ctx.verbose {
        eprintln!("[proxy] connect {host}:{port} buffered={}", buffered.len());
    }
    if !buffered.is_empty() {
        upstream.write_all(&buffered)?;
    }
    let mut connect_response = Response::new(200, "Connection Established");
    connect_response.set_header("Proxy-Agent", "burpcli");
    ctx.record(
        &request,
        Some(&connect_response),
        Duration::from_millis(0),
        vec!["proxy".into(), "connect".into()],
    );
    tunnel(stream, upstream)?;
    Ok(())
}

fn serve_tls(
    tls: StreamOwned<ServerConnection, TcpStream>,
    host: &str,
    ctx: &Arc<ProxyContext>,
) -> Result<()> {
    let mut reader = BufReader::new(tls);
    loop {
        let request = match read_request(&mut reader) {
            Ok(Some(request)) => request,
            Ok(None) => break,
            Err(error) => {
                // TLS alerts and abrupt browser disconnects are normal.
                if ctx.verbose {
                    eprintln!("[proxy] TLS read error for {host}: {error}");
                }
                break;
            }
        };
        let started = Instant::now();
        let bytes = process_request_with_scheme(request, ctx, started, Some("https"));
        reader.get_mut().write_all(&bytes)?;
        reader.get_mut().flush()?;
    }
    Ok(())
}

fn tunnel(mut client: TcpStream, mut upstream: TcpStream) -> Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(300))).ok();
    upstream
        .set_read_timeout(Some(Duration::from_secs(300)))
        .ok();
    let mut client_writer = client.try_clone()?;
    let mut upstream_writer = upstream.try_clone()?;
    let upload = std::thread::spawn(move || {
        std::io::copy(&mut client, &mut upstream_writer).ok();
        let _ = upstream_writer.shutdown(std::net::Shutdown::Write);
    });
    std::io::copy(&mut upstream, &mut client_writer).ok();
    let _ = client_writer.shutdown(std::net::Shutdown::Write);
    upload.join().ok();
    Ok(())
}

fn write_simple<W: Write>(
    writer: &mut W,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let mut response = Response::new(status, reason);
    response.set_header("Content-Type", content_type);
    response.set_header("Content-Length", body.len().to_string());
    response.set_header("Connection", "close");
    response.body = body.to_vec();
    writer.write_all(&response.to_bytes())?;
    writer.flush()?;
    Ok(())
}

fn process_request(request: Request, ctx: &Arc<ProxyContext>, started: Instant) -> Vec<u8> {
    process_request_with_scheme(request, ctx, started, None)
}

fn process_request_with_scheme(
    mut request: Request,
    ctx: &Arc<ProxyContext>,
    started: Instant,
    scheme: Option<&str>,
) -> Vec<u8> {
    match scheme {
        Some(scheme) => {
            if request.scheme.is_none() {
                request.scheme = Some(scheme.to_string());
            }
        }
        None => {
            if let Ok(url) = url::Url::parse(&request.target) {
                request.scheme = Some(url.scheme().to_string());
            } else if request.scheme.is_none() {
                request.scheme = Some("http".into());
            }
        }
    }
    let url = match request.url() {
        Ok(url) => url,
        Err(error) => {
            let mut response = Response::new(400, "Bad Request");
            response.set_header("Connection", "close");
            response.body = format!("burpcli: {error}").into_bytes();
            return response.to_bytes();
        }
    };
    if ctx.only_in_scope && !ctx.scope.allows(&url) {
        ctx.record(
            &request,
            None,
            started.elapsed(),
            vec!["proxy".into(), "blocked".into()],
        );
        let mut response = Response::new(403, "Forbidden");
        response.set_header("Content-Type", "text/plain");
        response.set_header("Connection", "close");
        response.body = b"burpcli: target is outside project scope".to_vec();
        return response.to_bytes();
    }

    if ctx.auto_apply {
        session::apply_headers(&mut request, &ctx.headers);
        if let Some(jar) = &ctx.cookie_jar {
            let jar = jar.lock().unwrap_or_else(|e| e.into_inner());
            session::apply_cookies(&mut request, &jar);
        }
        if let Err(error) = session::apply_request_rules(&mut request, &ctx.rules) {
            if ctx.verbose {
                eprintln!("[proxy] rule error: {error}");
            }
        }
    }

    if let Some(plugins) = &ctx.plugins {
        let effects = plugins.apply_request(&mut request);
        ctx.save_issues(&effects);
        if effects.dropped {
            ctx.record(
                &request,
                None,
                started.elapsed(),
                vec!["proxy".into(), "dropped".into()],
            );
            let mut response = Response::new(403, "Forbidden");
            response.set_header("Content-Type", "text/plain");
            response.set_header("Connection", "close");
            response.body = b"burpcli: request dropped by plugin".to_vec();
            return response.to_bytes();
        }
    }

    match ctx.interceptor.request(&mut request) {
        Ok(Decision::Drop) => {
            ctx.record(
                &request,
                None,
                started.elapsed(),
                vec!["proxy".into(), "dropped".into()],
            );
            let mut response = Response::new(403, "Forbidden");
            response.set_header("Content-Type", "text/plain");
            response.set_header("Connection", "close");
            response.body = b"burpcli: request dropped".to_vec();
            return response.to_bytes();
        }
        Ok(Decision::Continue) => {}
        Err(error) => {
            if ctx.verbose {
                eprintln!("[proxy] intercept error: {error}");
            }
        }
    }

    if request.header("Content-Length").is_some() {
        request.set_header("Content-Length", request.body.len().to_string());
    }

    match client::send(&request, &ctx.client) {
        Ok(http) => {
            let duration = started.elapsed();
            let mut response = http.response;
            if ctx.auto_apply {
                if let Err(error) = session::apply_response_rules(&mut response, &ctx.rules) {
                    if ctx.verbose {
                        eprintln!("[proxy] response rule error: {error}");
                    }
                }
            }
            if let Some(plugins) = &ctx.plugins {
                let effects = plugins.apply_response(&request, &mut response);
                ctx.save_issues(&effects);
            }
            let dropped = match ctx.interceptor.response(&mut response) {
                Ok(Decision::Drop) => true,
                Ok(Decision::Continue) => false,
                Err(error) => {
                    if ctx.verbose {
                        eprintln!("[proxy] response intercept error: {error}");
                    }
                    false
                }
            };
            if dropped {
                ctx.record(
                    &request,
                    None,
                    duration,
                    vec!["proxy".into(), "dropped".into()],
                );
                response = Response::new(403, "Forbidden");
                response.set_header("Content-Type", "text/plain");
                response.body = b"burpcli: response dropped".to_vec();
            } else {
                ctx.record(&request, Some(&response), duration, vec!["proxy".into()]);
            }
            if ctx.verbose {
                eprintln!(
                    "[proxy] {} {} -> {} ({} in {})",
                    request.method,
                    url,
                    response.status,
                    crate::util::format_size(response.body.len()),
                    format_duration(duration)
                );
            }
            finish_response(response)
        }
        Err(error) => {
            let duration = started.elapsed();
            ctx.record(
                &request,
                None,
                duration,
                vec!["proxy".into(), "error".into()],
            );
            if ctx.verbose {
                eprintln!("[proxy] {} {} failed: {error:#}", request.method, url);
            }
            let mut response = Response::new(502, "Bad Gateway");
            response.set_header("Content-Type", "text/plain");
            response.set_header("Connection", "close");
            response.body = format!("burpcli: {error:#}").into_bytes();
            response.to_bytes()
        }
    }
}

fn finish_response(mut response: Response) -> Vec<u8> {
    // Hop-by-hop headers must not be forwarded by a proxy.
    response.remove_header("Connection");
    response.remove_header("Keep-Alive");
    response.remove_header("Proxy-Connection");
    response.remove_header("Transfer-Encoding");
    response.set_header("Connection", "close");
    response.to_bytes()
}

fn read_request<R: BufRead>(reader: &mut R) -> Result<Option<Request>> {
    let mut head = Vec::new();
    let mut saw_line = false;
    loop {
        let mut line = Vec::new();
        let read = reader.read_until(b'\n', &mut line)?;
        if read == 0 {
            if !saw_line {
                return Ok(None);
            }
            break;
        }
        if !saw_line && (line == b"\r\n" || line == b"\n") {
            // Tolerate a stray leading blank line.
            continue;
        }
        saw_line = true;
        head.extend_from_slice(&line);
        if line == b"\r\n" || line == b"\n" {
            break;
        }
        if head.len() > MAX_HEAD {
            bail!("request header exceeds {MAX_HEAD} bytes");
        }
    }
    if head.is_empty() {
        return Ok(None);
    }
    let mut request = Request::parse(&head)?;

    let chunked = request
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("Transfer-Encoding"))
        .any(|header| header.value.to_ascii_lowercase().contains("chunked"));
    if chunked {
        let body = read_chunked_body(reader)?;
        request.body = body;
        request.remove_header("Transfer-Encoding");
        request.set_header("Content-Length", request.body.len().to_string());
    } else if let Some(length) = request
        .header("Content-Length")
        .and_then(|value| value.split(',').next())
        .and_then(|value| value.trim().parse::<usize>().ok())
    {
        if length > MAX_BODY {
            bail!("request body exceeds {MAX_BODY} bytes");
        }
        let mut body = vec![0u8; length];
        reader.read_exact(&mut body)?;
        request.body = body;
    }
    Ok(Some(request))
}

fn read_chunked_body<R: BufRead>(reader: &mut R) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let mut line = Vec::new();
        if reader.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        let text = String::from_utf8_lossy(&line);
        let size_text = text.trim().split(';').next().unwrap_or("");
        let size = usize::from_str_radix(size_text, 16)
            .with_context(|| format!("invalid chunk size '{size_text}'"))?;
        if size == 0 {
            loop {
                let mut trailer = Vec::new();
                if reader.read_until(b'\n', &mut trailer)? == 0 {
                    break;
                }
                if trailer == b"\r\n" || trailer == b"\n" {
                    break;
                }
            }
            break;
        }
        if body.len() + size > MAX_BODY {
            bail!("chunked request body exceeds {MAX_BODY} bytes");
        }
        let mut chunk = vec![0u8; size];
        reader.read_exact(&mut chunk)?;
        body.extend_from_slice(&chunk);
        let mut crlf = [0u8; 2];
        let mut total = 0;
        while total < 2 {
            match reader.read(&mut crlf[total..])? {
                0 => break,
                n => total += n,
            }
        }
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parses_request_with_content_length() {
        let raw = b"POST /a HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhelloGET /b";
        let mut reader = BufReader::new(Cursor::new(raw.to_vec()));
        let request = read_request(&mut reader).unwrap().unwrap();
        assert_eq!(request.body, b"hello");
        let second = read_request(&mut reader).unwrap().unwrap();
        assert_eq!(second.target, "/b");
    }

    #[test]
    fn parses_chunked_request() {
        let raw = b"POST /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let mut reader = BufReader::new(Cursor::new(raw.to_vec()));
        let request = read_request(&mut reader).unwrap().unwrap();
        assert_eq!(request.body, b"hello");
        assert_eq!(request.header("Content-Length"), Some("5"));
    }

    #[test]
    fn eof_returns_none() {
        let mut reader = BufReader::new(Cursor::new(Vec::new()));
        assert!(read_request(&mut reader).unwrap().is_none());
    }
}
