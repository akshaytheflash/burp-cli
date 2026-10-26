//! Integration tests for the HTTP client and message handling.

mod common;

use burpcli::http::{client, ClientOptions, CookieJar, Request, Response, TlsOptions};
use common::{html, query_param, redirect, response, set_cookie, TestServer};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[test]
fn get_and_post_round_trip() {
    let server = TestServer::start(|request| {
        if request.method == "POST" {
            let body = String::from_utf8_lossy(&request.body).to_string();
            common::text(format!(
                "POST {} body={} custom={}",
                request.target,
                body,
                request.header("X-Custom").unwrap_or("")
            ))
        } else {
            let q = query_param(request, "q").unwrap_or_default();
            common::text(format!("GET {} q={q}", request.target))
        }
    });

    let get = Request::from_url(
        "GET",
        &url::Url::parse(&server.url("/hello?q=world")).unwrap(),
        Vec::new(),
        None,
    );
    let result = client::send(&get, &ClientOptions::default()).unwrap();
    assert_eq!(result.response.status, 200);
    assert!(result.response.body_text().contains("q=world"));
    assert_eq!(result.final_url, server.url("/hello?q=world"));

    let mut post = Request::from_url(
        "POST",
        &url::Url::parse(&server.url("/submit")).unwrap(),
        b"a=1&b=2".to_vec(),
        Some("application/x-www-form-urlencoded"),
    );
    post.set_header("X-Custom", "yes");
    let result = client::send(&post, &ClientOptions::default()).unwrap();
    let body = result.response.body_text();
    assert!(body.contains("body=a=1&b=2"), "{body}");
    assert!(body.contains("custom=yes"), "{body}");

    let hits = server.hits();
    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0].method, "GET");
    assert_eq!(hits[1].method, "POST");
}

#[test]
fn follows_redirects_and_records_hops() {
    let server = TestServer::start(|request| match request.target.as_str() {
        "/start" => redirect("/middle"),
        "/middle" => redirect("/final"),
        "/final" => html("<html><title>done</title>arrived</html>"),
        _ => response(404, "Not Found", "text/plain", "missing"),
    });

    let request = Request::from_url(
        "GET",
        &url::Url::parse(&server.url("/start")).unwrap(),
        Vec::new(),
        None,
    );
    let options = ClientOptions {
        follow_redirects: 5,
        ..ClientOptions::default()
    };
    let result = client::send(&request, &options).unwrap();
    assert_eq!(result.response.status, 200);
    assert!(result.response.body_text().contains("arrived"));
    assert_eq!(result.final_url, server.url("/final"));
    assert_eq!(result.redirects.len(), 2);
    assert_eq!(result.redirects[0].status, 302);
    assert!(result.redirects[0].to.ends_with("/middle"));
    assert!(result.redirects[1].to.ends_with("/final"));
    assert_eq!(server.hits().len(), 3);
}

#[test]
fn redirect_limit_is_respected() {
    let server = TestServer::start(|request| {
        let number: u32 = request.target.trim_start_matches("/r").parse().unwrap_or(0);
        redirect(&format!("/r{}", number + 1))
    });
    let request = Request::from_url(
        "GET",
        &url::Url::parse(&server.url("/r0")).unwrap(),
        Vec::new(),
        None,
    );
    let result = client::send(
        &request,
        &ClientOptions {
            follow_redirects: 2,
            ..ClientOptions::default()
        },
    )
    .unwrap();
    assert_eq!(result.response.status, 302);
    assert_eq!(result.redirects.len(), 2);
    assert!(result.final_url.ends_with("/r2"), "{}", result.final_url);
    assert_eq!(server.hits().len(), 3);
}

#[test]
fn redirect_loops_stop_early() {
    let server = TestServer::start(|_| redirect("/loop"));
    let request = Request::from_url(
        "GET",
        &url::Url::parse(&server.url("/loop")).unwrap(),
        Vec::new(),
        None,
    );
    let result = client::send(
        &request,
        &ClientOptions {
            follow_redirects: 10,
            ..ClientOptions::default()
        },
    )
    .unwrap();
    assert_eq!(result.response.status, 302);
    // The loop is detected before the hop is followed, so no redirect is
    // recorded and the original response is returned.
    assert_eq!(result.redirects.len(), 0);
    assert_eq!(server.hits().len(), 1);
}

#[test]
fn cookie_jar_persists_across_requests() {
    let jar = Arc::new(Mutex::new(CookieJar::new()));
    let server = TestServer::start(|request| {
        if request.target.starts_with("/login") {
            set_cookie("session", "abc123")
        } else {
            let cookie = request.header("Cookie").unwrap_or("<none>");
            common::text(format!("cookie: {cookie}"))
        }
    });
    let options = ClientOptions {
        cookie_jar: Some(jar.clone()),
        ..ClientOptions::default()
    };

    let login = Request::from_url(
        "GET",
        &url::Url::parse(&server.url("/login")).unwrap(),
        Vec::new(),
        None,
    );
    client::send(&login, &options).unwrap();

    let check = Request::from_url(
        "GET",
        &url::Url::parse(&server.url("/check")).unwrap(),
        Vec::new(),
        None,
    );
    let result = client::send(&check, &options).unwrap();
    assert!(
        result.response.body_text().contains("session=abc123"),
        "{}",
        result.response.body_text()
    );
    assert_eq!(jar.lock().unwrap().cookies.len(), 1);
}

#[test]
fn decodes_chunked_and_gzip_responses() {
    // A raw server so that the transfer encoding is exactly what we choose.
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0u8; 4096];
        let mut seen = Vec::new();
        loop {
            let read = stream.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            seen.extend_from_slice(&buffer[..read]);
            if seen.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let chunks = ["hello ", "chunked ", "world"];
        let mut raw = String::from(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        for chunk in chunks {
            raw.push_str(&format!("{:x}\r\n{}\r\n", chunk.len(), chunk));
        }
        raw.push_str("0\r\n\r\n");
        stream.write_all(raw.as_bytes()).unwrap();
        stream.flush().unwrap();
    });

    let request = Request::from_url(
        "GET",
        &url::Url::parse(&format!("http://{addr}/chunked")).unwrap(),
        Vec::new(),
        None,
    );
    let result = client::send(&request, &ClientOptions::default()).unwrap();
    handle.join().unwrap();
    assert_eq!(result.response.body_text(), "hello chunked world");
}

#[test]
fn decodes_gzip_response_bodies() {
    use flate2::write::GzEncoder;
    use flate2::Compression;

    let server = TestServer::start(|_| {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"<html>compressed</html>").unwrap();
        let mut response = Response::new(200, "OK");
        response.set_header("Content-Type", "text/html");
        response.set_header("Content-Encoding", "gzip");
        response.body = encoder.finish().unwrap();
        response
    });

    let request = Request::from_url(
        "GET",
        &url::Url::parse(&server.url("/gzip")).unwrap(),
        Vec::new(),
        None,
    );
    let result = client::send(&request, &ClientOptions::default()).unwrap();
    assert_eq!(result.response.status, 200);
    assert_eq!(result.response.body_text(), "<html>compressed</html>");
    assert_eq!(result.response.header("Content-Encoding"), None);
    assert_eq!(result.response.header("Content-Length"), Some("23"));
}

#[test]
fn response_parsing_handles_binary_and_framing_headers() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nX-Test: 1\r\n\r\n\x00\x01\x02\x03";
    let response = Response::parse(raw).unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, vec![0, 1, 2, 3]);
    assert_eq!(response.header("x-test"), Some("1"));
    let reparsed = Response::parse(&response.to_bytes()).unwrap();
    assert_eq!(reparsed.body, response.body);
}

#[test]
fn insecure_tls_options_are_not_used_for_plain_http() {
    // Guard against accidental coupling: plain HTTP must work even when the
    // client is configured to accept any TLS certificate.
    let server = TestServer::start(|_| common::text("plain"));
    let request = Request::from_url(
        "GET",
        &url::Url::parse(&server.url("/")).unwrap(),
        Vec::new(),
        None,
    );
    let options = ClientOptions {
        timeout: Duration::from_secs(5),
        tls: TlsOptions {
            insecure: true,
            ..Default::default()
        },
        ..ClientOptions::default()
    };
    assert_eq!(
        client::send(&request, &options).unwrap().response.status,
        200
    );
}
