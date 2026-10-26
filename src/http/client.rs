//! Blocking HTTP/1.1 client with TLS, proxy support, redirects and a cookie jar.
//!
//! The client intentionally normalises framing (`Connection: close`,
//! `Content-Length`) so that every response can be read deterministically. It
//! keeps user-supplied headers (including `Host`) intact, which matters when
//! testing host-header handling.

use crate::http::cookies::CookieJar;
use crate::http::message::{parse_host_header, Request, Response};
use crate::http::tls::{self, TlsOptions};
use anyhow::{anyhow, bail, Context, Result};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use url::Url;

const MAX_HEADER_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub struct ClientOptions {
    pub timeout: Duration,
    pub connect_timeout: Duration,
    pub follow_redirects: usize,
    pub tls: TlsOptions,
    /// Upstream HTTP proxy, e.g. `http://127.0.0.1:8080`.
    pub proxy: Option<String>,
    pub decode: bool,
    pub max_body: usize,
    pub cookie_jar: Option<Arc<Mutex<CookieJar>>>,
    pub user_agent: Option<String>,
}

impl std::fmt::Debug for ClientOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientOptions")
            .field("timeout", &self.timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("follow_redirects", &self.follow_redirects)
            .field("tls", &self.tls)
            .field("proxy", &self.proxy)
            .field("decode", &self.decode)
            .field("max_body", &self.max_body)
            .field("cookie_jar", &self.cookie_jar.is_some())
            .field("user_agent", &self.user_agent)
            .finish()
    }
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(15),
            connect_timeout: Duration::from_secs(10),
            follow_redirects: 0,
            tls: TlsOptions::default(),
            proxy: None,
            decode: true,
            max_body: 10 * 1024 * 1024,
            cookie_jar: None,
            user_agent: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RedirectHop {
    pub status: u16,
    pub from: String,
    pub to: String,
}

#[derive(Debug)]
pub struct HttpResponse {
    pub response: Response,
    pub final_url: String,
    pub redirects: Vec<RedirectHop>,
    pub duration: Duration,
    pub truncated: bool,
}

/// Send one request, following up to `follow_redirects` redirects.
pub fn send(request: &Request, opts: &ClientOptions) -> Result<HttpResponse> {
    let mut current = request.clone();
    if let Some(ua) = &opts.user_agent {
        current.set_header("User-Agent", ua.clone());
    }
    if let Some(jar) = &opts.cookie_jar {
        if let Ok(url) = current.url() {
            let jar = jar.lock().unwrap_or_else(|e| e.into_inner());
            if current.header("Cookie").is_none() {
                if let Some(header) = jar.header_for(&url) {
                    current.set_header("Cookie", header);
                }
            }
        }
    }

    let started = Instant::now();
    let mut redirects = Vec::new();
    let mut visited = std::collections::HashSet::new();
    let mut hops = 0usize;
    loop {
        let url = current
            .url()
            .with_context(|| format!("invalid request target '{}'", current.target))?;
        visited.insert(url.to_string());
        let (response, truncated) = send_once(&current, &url, opts)?;

        if let Some(jar) = &opts.cookie_jar {
            let mut jar = jar.lock().unwrap_or_else(|e| e.into_inner());
            let set_cookies: Vec<String> = response
                .headers_named("Set-Cookie")
                .map(str::to_string)
                .collect();
            jar.update_from_response(&url, &set_cookies);
        }

        let location = response.redirected_to().map(str::to_string);
        let can_follow = location.is_some()
            && hops < opts.follow_redirects
            && !matches!(response.status, 304)
            && current.method != "HEAD";
        if !can_follow {
            return Ok(HttpResponse {
                response,
                final_url: url.to_string(),
                redirects,
                duration: started.elapsed(),
                truncated,
            });
        }

        let location = location.unwrap();
        let next_url = url
            .join(&location)
            .with_context(|| format!("invalid redirect location '{location}'"))?;
        if visited.contains(next_url.as_str()) {
            return Ok(HttpResponse {
                response,
                final_url: url.to_string(),
                redirects,
                duration: started.elapsed(),
                truncated,
            });
        }
        redirects.push(RedirectHop {
            status: response.status,
            from: url.to_string(),
            to: next_url.to_string(),
        });
        current = redirect_request(&current, &url, &next_url, response.status);
        hops += 1;
    }
}

fn redirect_request(current: &Request, old: &Url, next: &Url, status: u16) -> Request {
    let mut req = current.clone();
    req.scheme = Some(next.scheme().to_string());
    let target = match next.query() {
        Some(q) => format!("{}?{}", next.path(), q),
        None => next.path().to_string(),
    };
    req.target = target;
    req.set_header("Host", host_header(next));
    let drop_body = matches!(status, 301..=303) && req.method != "GET" && req.method != "HEAD";
    if drop_body {
        req.method = "GET".into();
        req.body.clear();
        req.remove_header("Content-Type");
        req.remove_header("Content-Length");
        req.remove_header("Transfer-Encoding");
    }
    if old.host_str() != next.host_str() {
        req.remove_header("Authorization");
        req.remove_header("Cookie");
    }
    req.connect_to = None;
    req.tls_server_name = None;
    req
}

fn send_once(request: &Request, url: &Url, opts: &ClientOptions) -> Result<(Response, bool)> {
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("URL has no host: {url}"))?
        .to_string();
    let scheme = url.scheme().to_string();
    let tls_enabled = scheme == "https" || scheme == "wss";
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("cannot determine port for {url}"))?;
    let (connect_host, connect_port) = match request.connect_to.as_deref() {
        Some(target) => {
            let (target_host, target_port) = parse_host_header(target);
            (target_host, target_port.unwrap_or(port))
        }
        None => (host.clone(), port),
    };
    let tls_name = request
        .tls_server_name
        .clone()
        .unwrap_or_else(|| host.clone());

    let mut outbound = request.clone();
    outbound.scheme = Some(scheme.clone());
    if outbound.header("Host").is_none() {
        outbound.set_header("Host", host_header(url));
    }
    outbound.remove_header("Proxy-Connection");
    outbound.set_header("Connection", "close");
    if outbound.header("Accept-Encoding").is_none() {
        outbound.set_header("Accept-Encoding", "gzip, deflate");
    }
    // Bodies are always sent decoded with an explicit length.
    outbound.remove_header("Transfer-Encoding");
    if !outbound.body.is_empty() || outbound.header("Content-Length").is_some() {
        outbound.set_header("Content-Length", outbound.body.len().to_string());
    }

    let proxy = opts.proxy.as_deref().map(parse_proxy).transpose()?;
    let upstream_host = proxy
        .as_ref()
        .map(|p| p.host.clone())
        .unwrap_or_else(|| connect_host.clone());
    let upstream_port = proxy.as_ref().map(|p| p.port).unwrap_or(connect_port);
    let tcp = connect_tcp(&upstream_host, upstream_port, opts.connect_timeout)?;
    tcp.set_read_timeout(Some(opts.timeout)).ok();
    tcp.set_write_timeout(Some(opts.timeout)).ok();
    tcp.set_nodelay(true).ok();

    let mut stream = if let Some(proxy) = &proxy {
        if tls_enabled {
            let target = format!("{}:{}", bracket_host(&connect_host), connect_port);
            let mut tcp = tcp;
            connect_via_proxy(&mut tcp, proxy, &target)?;
            Stream::tls(tcp, &tls_name, &opts.tls)?
        } else {
            Stream::Plain(tcp)
        }
    } else if tls_enabled {
        Stream::tls(tcp, &tls_name, &opts.tls)?
    } else {
        Stream::Plain(tcp)
    };

    // With a plain HTTP proxy the request line uses absolute-form.
    if proxy.is_some() && !tls_enabled {
        let mut absolute = url.clone();
        absolute.set_fragment(None);
        outbound.target = absolute.to_string();
    } else if let Ok(absolute) = Url::parse(&outbound.target) {
        outbound.target = match absolute.query() {
            Some(q) => format!("{}?{}", absolute.path(), q),
            None => absolute.path().to_string(),
        };
    }

    let bytes = outbound.to_bytes();
    stream
        .write_all(&bytes)
        .with_context(|| format!("failed to send request to {host}:{port}"))?;
    stream.flush().ok();

    let mut reader = BufReader::new(stream);
    let (response, truncated) = read_response(&mut reader, &outbound.method, opts.max_body)
        .with_context(|| format!("failed to read response from {url}"))?;

    Ok((response, truncated))
}

fn read_response(
    reader: &mut BufReader<Stream>,
    method: &str,
    max_body: usize,
) -> Result<(Response, bool)> {
    let head = loop {
        let head = read_head(reader)?;
        let parsed = Response::parse_head(&head)?;
        if (100..200).contains(&parsed.status) && parsed.status != 101 {
            // Informational response (100 Continue / 103 Early Hints).
            continue;
        }
        break head;
    };
    let mut response = Response::parse_head(&head)?;
    let no_body = method.eq_ignore_ascii_case("HEAD")
        || response.status == 204
        || response.status == 304
        || response.status == 101;
    if no_body {
        return Ok((response, false));
    }

    let chunked = response
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("Transfer-Encoding"))
        .any(|h| h.value.to_ascii_lowercase().contains("chunked"));
    let content_length = response
        .header("Content-Length")
        .and_then(|v| v.split(',').next())
        .and_then(|v| v.trim().parse::<usize>().ok());

    let mut truncated = false;
    let body = if chunked {
        let (body, cut) = read_chunked(reader, max_body)?;
        truncated = cut;
        response.remove_header("Transfer-Encoding");
        body
    } else if let Some(length) = content_length {
        let limit = length.min(max_body);
        let mut body = vec![0u8; limit];
        let mut read_total = 0;
        while read_total < limit {
            match reader.read(&mut body[read_total..]) {
                Ok(0) => break,
                Ok(n) => read_total += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        body.truncate(read_total);
        truncated = length > max_body;
        body
    } else {
        let mut body = Vec::new();
        let mut limited = reader.take(max_body as u64 + 1);
        limited.read_to_end(&mut body)?;
        if body.len() > max_body {
            body.truncate(max_body);
            truncated = true;
        }
        body
    };

    response.body = body;
    if chunked {
        response.set_header("Content-Length", response.body.len().to_string());
    }
    decode_content_encoding(&mut response);
    Ok((response, truncated))
}

fn decode_content_encoding(response: &mut Response) {
    if let Some(decoded) = response.decompressed_body() {
        response.body = decoded;
        response.remove_header("Content-Encoding");
        response.set_header("Content-Length", response.body.len().to_string());
    }
}

fn read_head<R: BufRead>(reader: &mut R) -> Result<Vec<u8>> {
    let mut head = Vec::new();
    loop {
        let mut line = Vec::new();
        let n = reader.read_until(b'\n', &mut line)?;
        if n == 0 {
            if head.is_empty() {
                bail!("connection closed before response headers");
            }
            break;
        }
        head.extend_from_slice(&line);
        if line == b"\r\n" || line == b"\n" {
            break;
        }
        if head.len() > MAX_HEADER_BYTES {
            bail!("response headers exceed {MAX_HEADER_BYTES} bytes");
        }
    }
    Ok(head)
}

fn read_chunked<R: BufRead>(reader: &mut R, max_body: usize) -> Result<(Vec<u8>, bool)> {
    let mut body = Vec::new();
    let mut truncated = false;
    loop {
        let mut line = Vec::new();
        let n = reader.read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        let line = String::from_utf8_lossy(&line);
        let size_str = line.trim().split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16)
            .with_context(|| format!("invalid chunk size '{size_str}'"))?;
        if size == 0 {
            // Consume trailers until the blank line.
            loop {
                let mut trailer = Vec::new();
                let n = reader.read_until(b'\n', &mut trailer)?;
                if n == 0 || trailer == b"\r\n" || trailer == b"\n" {
                    break;
                }
            }
            break;
        }
        if body.len() + size > max_body {
            let remaining = max_body.saturating_sub(body.len());
            let mut partial = vec![0u8; remaining];
            reader.read_exact(&mut partial)?;
            body.extend_from_slice(&partial);
            truncated = true;
            break;
        }
        let mut chunk = vec![0u8; size];
        reader.read_exact(&mut chunk)?;
        body.extend_from_slice(&chunk);
        let mut crlf = [0u8; 2];
        let mut read = 0;
        while read < 2 {
            match reader.read(&mut crlf[read..])? {
                0 => break,
                n => read += n,
            }
        }
    }
    Ok((body, truncated))
}

enum Stream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Stream {
    fn tls(tcp: TcpStream, host: &str, opts: &TlsOptions) -> Result<Self> {
        let config = tls_client_config(opts)?;
        let name: ServerName<'static> = tls::server_name(host)?;
        let conn = ClientConnection::new(config, name).context("TLS handshake setup failed")?;
        Ok(Stream::Tls(Box::new(StreamOwned::new(conn, tcp))))
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf),
            Stream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(buf),
            Stream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            Stream::Tls(s) => s.flush(),
        }
    }
}

fn tls_client_config(opts: &TlsOptions) -> Result<Arc<rustls::ClientConfig>> {
    if !opts.extra_roots.is_empty() {
        return tls::client_config(opts);
    }
    static SECURE: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    static INSECURE: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    let cell = if opts.insecure { &INSECURE } else { &SECURE };
    if let Some(config) = cell.get() {
        return Ok(config.clone());
    }
    let config = tls::client_config(opts)?;
    Ok(cell.get_or_init(|| config).clone())
}

fn connect_tcp(host: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("cannot resolve {host}:{port}"))?
        .collect();
    if addrs.is_empty() {
        bail!("no addresses found for {host}:{port}");
    }
    let mut last_error = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => return Ok(stream),
            Err(e) => last_error = Some(e),
        }
    }
    Err(last_error
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow!("connection failed"))
        .context(format!("cannot connect to {host}:{port}")))
}

#[derive(Debug, Clone)]
struct ProxyConfig {
    host: String,
    port: u16,
    auth: Option<String>,
}

fn parse_proxy(input: &str) -> Result<ProxyConfig> {
    let url = if input.contains("://") {
        Url::parse(input)?
    } else {
        Url::parse(&format!("http://{input}"))?
    };
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("proxy URL has no host"))?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(8080);
    let auth = if !url.username().is_empty() {
        let password = url.password().unwrap_or("");
        Some(format!("{}:{}", url.username(), password))
    } else {
        None
    };
    Ok(ProxyConfig { host, port, auth })
}

fn connect_via_proxy(tcp: &mut TcpStream, proxy: &ProxyConfig, target: &str) -> Result<()> {
    let mut request =
        format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Connection: close\r\n");
    if let Some(auth) = &proxy.auth {
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::STANDARD.encode(auth.as_bytes());
        request.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
    }
    request.push_str("\r\n");
    tcp.write_all(request.as_bytes())?;
    tcp.flush()?;
    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        let n = tcp.read(&mut byte)?;
        if n == 0 {
            bail!("proxy closed connection during CONNECT");
        }
        response.push(byte[0]);
        if response.len() > MAX_HEADER_BYTES {
            bail!("proxy CONNECT response too large");
        }
    }
    let text = String::from_utf8_lossy(&response);
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if status != 200 {
        bail!(
            "proxy CONNECT failed: {}",
            text.lines().next().unwrap_or("unknown error")
        );
    }
    Ok(())
}

fn host_header(url: &Url) -> String {
    let host = url.host_str().unwrap_or("");
    // Compare against the scheme default, not `port_or_known_default`, so an
    // ephemeral port is still written to the Host header.
    let default = match url.scheme() {
        "https" | "wss" => 443,
        _ => 80,
    };
    match url.port() {
        Some(p) if p != default => {
            if host.contains(':') {
                format!("[{host}]:{p}")
            } else {
                format!("{host}:{p}")
            }
        }
        _ => host.to_string(),
    }
}

fn bracket_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// Build a request from CLI-style parameters.
pub fn request_from_parts(
    method: &str,
    url: &str,
    headers: &[String],
    body: Option<&str>,
) -> Result<Request> {
    let url = Url::parse(url).with_context(|| format!("invalid URL '{url}'"))?;
    let body_bytes = body.map(|b| b.as_bytes().to_vec()).unwrap_or_default();
    let content_type = if body.is_some() {
        Some("application/x-www-form-urlencoded")
    } else {
        None
    };
    let mut request = Request::from_url(method, &url, body_bytes, content_type);
    for raw in headers {
        if let Some((name, value)) = raw.split_once(':') {
            request.set_header(name.trim(), value.trim());
        } else {
            bail!("invalid header '{raw}', expected 'Name: value'");
        }
    }
    // Allow a raw Host override (important for host-header tests).
    if let Some(host) = headers.iter().find_map(|h| {
        h.split_once(':')
            .filter(|(n, _)| n.eq_ignore_ascii_case("host"))
    }) {
        request.set_header("Host", host.1.trim());
    }
    Ok(request)
}

/// Parse a `host:port` service string. Returns the default port for the scheme.
pub fn split_service(service: &str, tls: bool) -> (String, u16) {
    let (host, port) = parse_host_header(service);
    (host, port.unwrap_or(if tls { 443 } else { 80 }))
}

pub fn ensure_host_header(request: &mut Request) -> Result<()> {
    if request.header("Host").is_none() {
        let host = request
            .host()
            .ok_or_else(|| anyhow!("cannot determine Host for request"))?;
        let port = request.port().unwrap_or(80);
        let scheme = request.scheme();
        let default = if scheme == "https" { 443 } else { 80 };
        if port == default {
            request.set_header("Host", host);
        } else {
            request.set_header("Host", format!("{host}:{port}"));
        }
    }
    Ok(())
}
