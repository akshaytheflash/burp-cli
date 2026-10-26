//! HTTP/1.1 message model, parser and serializer.
//!
//! Messages keep header order and duplicates, because security testing cares
//! about the exact bytes that go over the wire.

use crate::util::{b64_decode, b64_encode, display_bytes};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use url::Url;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

impl Header {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// An HTTP request. `scheme` is extra information that is not part of the wire
/// format; it is set when a request is created from a URL or from proxy traffic.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Request {
    pub method: String,
    pub target: String,
    pub version: String,
    #[serde(default)]
    pub headers: Vec<Header>,
    #[serde(default)]
    pub body: Vec<u8>,
    #[serde(default)]
    pub scheme: Option<String>,
    /// Optional TCP `host:port` override, used for Host-header tests while the
    /// connection still goes to the real target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_to: Option<String>,
    /// Optional TLS SNI/verification name override (defaults to the URL host).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_server_name: Option<String>,
}

impl Request {
    pub fn new(method: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            target: target.into(),
            version: "HTTP/1.1".into(),
            headers: Vec::new(),
            body: Vec::new(),
            scheme: None,
            connect_to: None,
            tls_server_name: None,
        }
    }

    /// Create a request from an absolute URL.
    pub fn from_url(method: &str, url: &Url, body: Vec<u8>, content_type: Option<&str>) -> Self {
        let target = match url.query() {
            Some(q) => format!("{}?{}", url.path(), q),
            None => {
                let p = url.path();
                if p.is_empty() {
                    "/".to_string()
                } else {
                    p.to_string()
                }
            }
        };
        let mut req = Request::new(method, target);
        req.scheme = Some(url.scheme().to_string());
        let host = url_host_header(url);
        req.set_header("Host", host);
        req.set_header("User-Agent", format!("burpcli/{}", crate::VERSION));
        req.set_header("Accept", "*/*");
        req.set_header("Connection", "close");
        if !body.is_empty() {
            if let Some(ct) = content_type {
                req.set_header("Content-Type", ct);
            }
            req.set_header("Content-Length", body.len().to_string());
            req.body = body;
        }
        req
    }

    pub fn parse(raw: &[u8]) -> Result<Self> {
        let (head, body) = split_head(raw)?;
        let text = String::from_utf8_lossy(head);
        let mut lines = text.lines();
        let request_line = lines.next().ok_or_else(|| anyhow!("empty request"))?;
        let mut parts = request_line.split_whitespace();
        let method = parts
            .next()
            .ok_or_else(|| anyhow!("missing method"))?
            .to_string();
        let target = parts
            .next()
            .ok_or_else(|| anyhow!("missing request target"))?
            .to_string();
        let version = parts.next().unwrap_or("HTTP/1.1").to_string();
        if !version.starts_with("HTTP/") {
            bail!("unsupported request version '{version}'");
        }
        let headers = parse_header_lines(text.lines().skip(1))?;
        Ok(Request {
            method,
            target,
            version,
            headers,
            body: body.to_vec(),
            scheme: None,
            connect_to: None,
            tls_server_name: None,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(
            format!("{} {} {}\r\n", self.method, self.target, self.version).as_bytes(),
        );
        for h in &self.headers {
            out.extend_from_slice(format!("{}: {}\r\n", h.name, h.value).as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }

    pub fn head_string(&self) -> String {
        let mut out = format!("{} {} {}\r\n", self.method, self.target, self.version);
        for h in &self.headers {
            out.push_str(&format!("{}: {}\r\n", h.name, h.value));
        }
        out
    }

    pub fn to_b64(&self) -> String {
        b64_encode(&self.to_bytes())
    }

    pub fn from_b64(data: &str) -> Result<Self> {
        Self::parse(&b64_decode(data)?)
    }

    pub fn text(&self) -> String {
        display_bytes(&self.to_bytes())
    }

    pub fn body_text(&self) -> String {
        display_bytes(&self.body)
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    pub fn headers_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    pub fn set_header(&mut self, name: &str, value: impl Into<String>) {
        let value = value.into();
        if let Some(h) = self
            .headers
            .iter_mut()
            .find(|h| h.name.eq_ignore_ascii_case(name))
        {
            h.value = value;
            h.name = name.to_string();
        } else {
            self.headers.push(Header::new(name, value));
        }
    }

    pub fn add_header(&mut self, name: &str, value: impl Into<String>) {
        self.headers.push(Header::new(name, value));
    }

    pub fn remove_header(&mut self, name: &str) {
        self.headers.retain(|h| !h.name.eq_ignore_ascii_case(name));
    }

    /// Host without port, derived from an absolute target or the `Host` header.
    pub fn host(&self) -> Option<String> {
        if let Ok(url) = Url::parse(&self.target) {
            return url.host_str().map(str::to_string);
        }
        let host = self.header("Host")?;
        Some(parse_host_header(host).0)
    }

    pub fn port(&self) -> Option<u16> {
        if let Ok(url) = Url::parse(&self.target) {
            return url.port_or_known_default();
        }
        let host = self.header("Host")?;
        let (_, port) = parse_host_header(host);
        port.or_else(|| self.scheme.as_deref().and_then(default_port))
    }

    pub fn scheme(&self) -> String {
        if let Ok(url) = Url::parse(&self.target) {
            return url.scheme().to_string();
        }
        self.scheme.clone().unwrap_or_else(|| "http".to_string())
    }

    pub fn url(&self) -> Result<Url> {
        if let Ok(url) = Url::parse(&self.target) {
            return Ok(url);
        }
        let host = self
            .host()
            .ok_or_else(|| anyhow!("request has no Host header"))?;
        let scheme = self.scheme();
        let port = self.port();
        let default = default_port(&scheme).unwrap_or(80);
        let authority = match port {
            Some(p) if p != default => format!("{host}:{p}"),
            _ => host,
        };
        let target = if self.target.starts_with('/') {
            self.target.clone()
        } else {
            format!("/{}", self.target)
        };
        Url::parse(&format!("{scheme}://{authority}{target}")).context("cannot build request URL")
    }

    pub fn service(&self) -> Result<(String, u16, bool)> {
        let url = self.url()?;
        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("URL has no host"))?
            .to_string();
        let port = url.port_or_known_default().unwrap_or(80);
        let tls = url.scheme() == "https";
        Ok((host, port, tls))
    }

    pub fn content_type(&self) -> Option<&str> {
        self.header("Content-Type")
    }

    pub fn is_form(&self) -> bool {
        self.content_type()
            .map(|c| {
                c.to_ascii_lowercase()
                    .contains("application/x-www-form-urlencoded")
            })
            .unwrap_or(false)
    }

    pub fn is_json(&self) -> bool {
        self.content_type()
            .map(|c| c.to_ascii_lowercase().contains("json"))
            .unwrap_or(false)
    }

    pub fn is_xml(&self) -> bool {
        self.content_type()
            .map(|c| {
                let c = c.to_ascii_lowercase();
                c.contains("xml") || c.contains("soap")
            })
            .unwrap_or(false)
    }

    /// A short display form used in tables.
    pub fn title(&self) -> String {
        format!("{} {}", self.method, self.target)
    }
}

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.text())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    pub version: String,
    pub status: u16,
    pub reason: String,
    #[serde(default)]
    pub headers: Vec<Header>,
    #[serde(default)]
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, reason: impl Into<String>) -> Self {
        Self {
            version: "HTTP/1.1".into(),
            status,
            reason: reason.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Parse a complete response. Chunked transfer encoding is decoded and the
    /// framing headers are normalised so that `to_bytes` round-trips cleanly.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        Self::parse_impl(raw, true)
    }

    /// Parse response headers only. The body is kept exactly as supplied and
    /// framing headers such as `Transfer-Encoding` are preserved, which lets a
    /// streaming client read the body itself.
    pub fn parse_head(raw: &[u8]) -> Result<Self> {
        Self::parse_impl(raw, false)
    }

    fn parse_impl(raw: &[u8], decode: bool) -> Result<Self> {
        let (head, body) = split_head(raw)?;
        let text = String::from_utf8_lossy(head);
        let mut lines = text.lines();
        let status_line = lines.next().ok_or_else(|| anyhow!("empty response"))?;
        let mut parts = status_line.splitn(3, ' ');
        let version = parts.next().unwrap_or("HTTP/1.1").to_string();
        let status: u16 = parts
            .next()
            .ok_or_else(|| anyhow!("missing status code"))?
            .parse()
            .with_context(|| format!("invalid status line '{status_line}'"))?;
        let reason = parts.next().unwrap_or("").trim().to_string();
        let mut headers = parse_header_lines(text.lines().skip(1))?;
        let chunked = headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case("Transfer-Encoding"))
            .any(|h| h.value.to_ascii_lowercase().contains("chunked"));
        let (body, decoded) = if decode && chunked {
            (
                decode_chunked(body).context("invalid chunked response")?,
                true,
            )
        } else {
            (body.to_vec(), false)
        };
        if decode {
            headers.retain(|h| !h.name.eq_ignore_ascii_case("Transfer-Encoding"));
            if decoded {
                set_or_add(&mut headers, "Content-Length", &body.len().to_string());
            }
        }
        Ok(Response {
            version,
            status,
            reason,
            headers,
            body,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(
            format!("{} {} {}\r\n", self.version, self.status, self.reason).as_bytes(),
        );
        for h in &self.headers {
            out.extend_from_slice(format!("{}: {}\r\n", h.name, h.value).as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }

    pub fn head_string(&self) -> String {
        let mut out = format!("{} {} {}\r\n", self.version, self.status, self.reason);
        for h in &self.headers {
            out.push_str(&format!("{}: {}\r\n", h.name, h.value));
        }
        out
    }

    pub fn to_b64(&self) -> String {
        b64_encode(&self.to_bytes())
    }

    pub fn from_b64(data: &str) -> Result<Self> {
        Self::parse(&b64_decode(data)?)
    }

    pub fn text(&self) -> String {
        display_bytes(&self.to_bytes())
    }

    pub fn body_text(&self) -> String {
        display_bytes(&self.body)
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    pub fn headers_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    pub fn set_header(&mut self, name: &str, value: impl Into<String>) {
        set_or_add(&mut self.headers, name, &value.into());
    }

    pub fn add_header(&mut self, name: &str, value: impl Into<String>) {
        self.headers.push(Header::new(name, value));
    }

    pub fn remove_header(&mut self, name: &str) {
        self.headers.retain(|h| !h.name.eq_ignore_ascii_case(name));
    }

    pub fn content_type(&self) -> Option<&str> {
        self.header("Content-Type")
    }

    pub fn is_html(&self) -> bool {
        self.content_type()
            .map(|c| c.to_ascii_lowercase().contains("html"))
            .unwrap_or(false)
    }

    pub fn is_textual(&self) -> bool {
        match self.content_type() {
            Some(c) => {
                let c = c.to_ascii_lowercase();
                c.starts_with("text/")
                    || c.contains("json")
                    || c.contains("xml")
                    || c.contains("javascript")
                    || c.contains("x-www-form-urlencoded")
            }
            None => true,
        }
    }

    pub fn redirected_to(&self) -> Option<&str> {
        if (300..400).contains(&self.status) {
            self.header("Location")
        } else {
            None
        }
    }

    /// Decode a gzip/deflate encoded body. Returns `None` when the body is not
    /// encoded or cannot be decoded (e.g. brotli, which is not supported).
    pub fn decompressed_body(&self) -> Option<Vec<u8>> {
        let encoding = self.header("Content-Encoding")?.to_ascii_lowercase();
        use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
        use std::io::Read;
        let mut out = Vec::new();
        if encoding.contains("gzip") {
            GzDecoder::new(&self.body[..]).read_to_end(&mut out).ok()?;
            Some(out)
        } else if encoding.contains("deflate") {
            if ZlibDecoder::new(&self.body[..])
                .read_to_end(&mut out)
                .is_ok()
            {
                return Some(out);
            }
            out.clear();
            DeflateDecoder::new(&self.body[..])
                .read_to_end(&mut out)
                .ok()?;
            Some(out)
        } else {
            None
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "{} {} ({})",
            self.status,
            self.reason,
            crate::util::format_size(self.body.len())
        )
    }
}

impl fmt::Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.text())
    }
}

pub fn split_head(raw: &[u8]) -> Result<(&[u8], &[u8])> {
    if let Some(pos) = find_subslice(raw, b"\r\n\r\n") {
        Ok((&raw[..pos], &raw[pos + 4..]))
    } else if let Some(pos) = find_subslice(raw, b"\n\n") {
        Ok((&raw[..pos], &raw[pos + 2..]))
    } else {
        // Headers without a body are common in hand-written files.
        if raw.is_empty() {
            bail!("empty message");
        }
        if raw.ends_with(b"\r\n") {
            Ok((&raw[..raw.len() - 2], &[]))
        } else if raw.ends_with(b"\n") {
            Ok((&raw[..raw.len() - 1], &[]))
        } else {
            Ok((raw, &[]))
        }
    }
}

fn parse_header_lines<'a>(lines: impl Iterator<Item = &'a str>) -> Result<Vec<Header>> {
    let mut headers: Vec<Header> = Vec::new();
    for line in lines {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            // Obsolete line folding: append to the previous header.
            if let Some(last) = headers.last_mut() {
                last.value.push(' ');
                last.value.push_str(line.trim());
                continue;
            }
            bail!("header continuation without a header");
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| anyhow!("malformed header line '{line}'"))?;
        if name.trim().is_empty() {
            bail!("empty header name");
        }
        headers.push(Header::new(name.trim(), value.trim()));
    }
    Ok(headers)
}

pub fn decode_chunked(mut data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = find_subslice(data, b"\r\n")
            .map(|p| (p, 2))
            .or_else(|| find_subslice(data, b"\n").map(|p| (p, 1)))
            .ok_or_else(|| anyhow!("truncated chunk size"))?;
        let size_line = std::str::from_utf8(&data[..line_end.0]).context("chunk size not UTF-8")?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .with_context(|| format!("invalid chunk size '{size_hex}'"))?;
        data = &data[line_end.0 + line_end.1..];
        if size == 0 {
            break;
        }
        if data.len() < size {
            bail!("truncated chunk body");
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size..];
        if data.starts_with(b"\r\n") {
            data = &data[2..];
        } else if data.starts_with(b"\n") {
            data = &data[1..];
        } else if !data.is_empty() {
            bail!("missing CRLF after chunk");
        }
    }
    Ok(out)
}

pub fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

pub fn parse_host_header(value: &str) -> (String, Option<u16>) {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('[') {
        if let Some((host, tail)) = rest.split_once(']') {
            let port = tail.strip_prefix(':').and_then(|p| p.parse().ok());
            return (format!("[{host}]"), port);
        }
    }
    match value.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            (host.to_string(), port.parse().ok())
        }
        _ => (value.to_string(), None),
    }
}

fn default_port(scheme: &str) -> Option<u16> {
    match scheme.to_ascii_lowercase().as_str() {
        "http" | "ws" => Some(80),
        "https" | "wss" => Some(443),
        _ => None,
    }
}

fn url_host_header(url: &Url) -> String {
    let host = url.host_str().unwrap_or("");
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

fn set_or_add(headers: &mut Vec<Header>, name: &str, value: &str) {
    if let Some(h) = headers
        .iter_mut()
        .find(|h| h.name.eq_ignore_ascii_case(name))
    {
        h.value = value.to_string();
    } else {
        headers.push(Header::new(name, value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request_with_duplicate_headers() {
        let raw = b"POST /login?x=1 HTTP/1.1\r\nHost: example.com\r\nX-A: 1\r\nX-A: 2\r\nContent-Length: 5\r\n\r\nhello";
        let req = Request::parse(raw).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.target, "/login?x=1");
        assert_eq!(req.headers_named("x-a").count(), 2);
        assert_eq!(req.body, b"hello");
        assert_eq!(req.host().unwrap(), "example.com");
        assert_eq!(req.to_bytes(), raw);
    }

    #[test]
    fn request_from_url() {
        let url = Url::parse("https://example.com:8443/a?b=c").unwrap();
        let req = Request::from_url("GET", &url, vec![], None);
        assert_eq!(req.target, "/a?b=c");
        assert_eq!(req.header("Host").unwrap(), "example.com:8443");
        assert_eq!(req.scheme(), "https");
        assert_eq!(req.port().unwrap(), 8443);
        assert_eq!(
            req.url().unwrap().as_str(),
            "https://example.com:8443/a?b=c"
        );
    }

    #[test]
    fn chunked_decoding() {
        let body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(body).unwrap(), b"hello world");
    }

    #[test]
    fn parse_chunked_response_normalises_headers() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let res = Response::parse(raw).unwrap();
        assert_eq!(res.body, b"hello");
        assert_eq!(res.header("Content-Length"), Some("5"));
        assert!(res.header("Transfer-Encoding").is_none());
    }

    #[test]
    fn host_header_parsing() {
        assert_eq!(
            parse_host_header("example.com:8080"),
            ("example.com".into(), Some(8080))
        );
        assert_eq!(parse_host_header("[::1]:443"), ("[::1]".into(), Some(443)));
        assert_eq!(
            parse_host_header("example.com"),
            ("example.com".into(), None)
        );
    }

    #[test]
    fn absolute_form_target() {
        let req = Request::parse(b"GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
        assert_eq!(req.scheme(), "http");
        assert_eq!(req.url().unwrap().as_str(), "http://example.com/x");
    }
}
