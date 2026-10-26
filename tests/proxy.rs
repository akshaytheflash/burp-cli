//! Integration tests for proxy forwarding, CONNECT tunnelling and TLS MITM.

mod common;

use burpcli::http::{client, tls, ClientOptions, Request, TlsOptions};
use burpcli::proxy::{CertificateAuthority, ProxyOptions, ProxyServer};
use common::{html, response, TlsTestServer};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn proxy_options(port: u16, mitm: bool) -> ProxyOptions {
    ProxyOptions {
        bind: "127.0.0.1".into(),
        port,
        mitm,
        intercept_requests: false,
        intercept_responses: false,
        only_in_scope: false,
        insecure: true,
        timeout_ms: 10_000,
        verbose: false,
    }
}

#[test]
fn forwards_plain_http_and_records_history() {
    let origin = common::TestServer::start(|request| {
        html(format!(
            "<html><title>proxied</title>{}</html>",
            request.target
        ))
    });
    let test_project = common::TestProject::new();
    let mut proxy = ProxyServer::start(&test_project.project, &proxy_options(0, false)).unwrap();
    let proxy_addr = proxy.local_addr();

    let request = Request::from_url(
        "GET",
        &url::Url::parse(&origin.url("/through-proxy?x=1")).unwrap(),
        Vec::new(),
        None,
    );
    let options = ClientOptions {
        proxy: Some(format!("http://{proxy_addr}")),
        timeout: Duration::from_secs(10),
        ..ClientOptions::default()
    };
    let result = client::send(&request, &options).unwrap();
    assert_eq!(result.response.status, 200);
    assert!(result.response.body_text().contains("/through-proxy?x=1"));

    let hits = origin.hits();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].target, "/through-proxy?x=1");

    let history = test_project.project.history().unwrap();
    assert_eq!(history.count().unwrap(), 1);
    let entry = history.list(&Default::default()).unwrap().remove(0);
    assert_eq!(entry.method, "GET");
    assert_eq!(entry.status, 200);
    assert!(entry.url.contains("/through-proxy?x=1"));
    assert!(entry.tags.iter().any(|tag| tag == "proxy"));
    proxy.stop();
}

#[test]
fn proxy_applies_session_cookies_and_headers() {
    let origin = common::TestServer::start(|request| {
        let cookie = request.header("Cookie").unwrap_or("<none>").to_string();
        let header = request.header("X-Session").unwrap_or("<none>").to_string();
        common::text(format!("cookie={cookie};header={header}"))
    });
    let mut test_project = common::TestProject::new();
    let mut state = burpcli::session::SessionState::from_project(&test_project.project).unwrap();
    state.cookies.add("sid", "abc123", "127.0.0.1", false);
    state.save_to_project(&test_project.project).unwrap();
    test_project.project.config.session.headers = vec!["X-Session: enabled".into()];
    test_project.project.save_config().unwrap();

    let mut proxy = ProxyServer::start(&test_project.project, &proxy_options(0, false)).unwrap();
    let request = Request::from_url(
        "GET",
        &url::Url::parse(&origin.url("/session")).unwrap(),
        Vec::new(),
        None,
    );
    let options = ClientOptions {
        proxy: Some(format!("http://{}", proxy.local_addr())),
        timeout: Duration::from_secs(10),
        ..ClientOptions::default()
    };
    let result = client::send(&request, &options).unwrap();
    assert_eq!(result.response.status, 200);
    let body = result.response.body_text();
    assert!(body.contains("sid=abc123"), "{body}");
    assert!(body.contains("header=enabled"), "{body}");
    proxy.stop();
}

#[test]
fn connect_tunnel_passes_bytes_through() {
    let origin = common::TestServer::start(|_| common::text("tunnel-ok"));
    let test_project = common::TestProject::new();
    let mut proxy = ProxyServer::start(&test_project.project, &proxy_options(0, false)).unwrap();
    let proxy_addr = proxy.local_addr();

    let mut stream = TcpStream::connect(proxy_addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{} \r\n\r\n",
        origin.addr().port(),
        origin.addr().port()
    )
    .unwrap();
    stream.flush().unwrap();

    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        let read = stream.read(&mut byte).unwrap();
        if read == 0 {
            break;
        }
        response.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&response);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");

    let request = format!(
        "GET / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        origin.addr().port()
    );
    stream.write_all(request.as_bytes()).unwrap();
    stream.flush().unwrap();
    let mut body = Vec::new();
    stream.read_to_end(&mut body).unwrap();
    let body = String::from_utf8_lossy(&body);
    assert!(body.contains("tunnel-ok"), "{body}");
    proxy.stop();
}

#[test]
fn mitm_intercepts_https_with_trusted_ca() {
    let test_project = common::TestProject::new();
    let authority = CertificateAuthority::from_project(&test_project.project).unwrap();
    let origin_config = authority.server_config("127.0.0.1").unwrap();
    let origin = TlsTestServer::start(origin_config, |request| {
        html(format!(
            "<html><title>secure</title>secret:{}:{}</html>",
            request.method, request.target
        ))
    });

    let mut proxy = ProxyServer::start(&test_project.project, &proxy_options(0, true)).unwrap();
    let proxy_addr = proxy.local_addr();
    let roots = tls::load_certs_pem(&test_project.project.ca_cert_path()).unwrap();
    assert!(!roots.is_empty());

    let request = Request::from_url(
        "GET",
        &url::Url::parse(&origin.url("/mitm?token=1")).unwrap(),
        Vec::new(),
        None,
    );
    let options = ClientOptions {
        proxy: Some(format!("http://{proxy_addr}")),
        timeout: Duration::from_secs(10),
        tls: TlsOptions {
            insecure: false,
            extra_roots: roots,
        },
        ..ClientOptions::default()
    };
    let result = client::send(&request, &options).unwrap();
    assert_eq!(result.response.status, 200);
    let body = result.response.body_text();
    assert!(body.contains("secret:GET:/mitm?token=1"), "{body}");

    let hits = origin.hits();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].target, "/mitm?token=1");

    let history = test_project.project.history().unwrap();
    let entries = history.list(&Default::default()).unwrap();
    assert!(
        entries
            .iter()
            .any(|entry| entry.url.contains("/mitm?token=1")),
        "MITM request was not recorded"
    );
    proxy.stop();
}

#[test]
fn mitm_can_be_disabled_for_blind_tunnel() {
    // With MITM disabled, the proxy should not present a certificate of its
    // own; a TLS client that trusts only the proxy CA must fail the handshake.
    let test_project = common::TestProject::new();
    // The origin uses its own CA, which the client does not trust, so a blind
    // tunnel can only pass if the proxy silently re-signs the connection.
    let origin_project = common::TestProject::new();
    let origin_authority = CertificateAuthority::from_project(&origin_project.project).unwrap();
    let origin_config = origin_authority.server_config("127.0.0.1").unwrap();
    let origin = TlsTestServer::start(origin_config, |_| common::text("origin"));

    // Materialise the proxy CA so the client can trust it.
    CertificateAuthority::from_project(&test_project.project).unwrap();
    let roots = tls::load_certs_pem(&test_project.project.ca_cert_path()).unwrap();

    let mut proxy = ProxyServer::start(&test_project.project, &proxy_options(0, false)).unwrap();
    let proxy_addr = proxy.local_addr();
    let request = Request::from_url(
        "GET",
        &url::Url::parse(&origin.url("/")).unwrap(),
        Vec::new(),
        None,
    );
    let options = ClientOptions {
        proxy: Some(format!("http://{proxy_addr}")),
        timeout: Duration::from_secs(5),
        tls: TlsOptions {
            insecure: false,
            extra_roots: roots,
        },
        ..ClientOptions::default()
    };
    let result = client::send(&request, &options);
    assert!(
        result.is_err(),
        "blind tunnel to a self-signed origin must not verify"
    );
    proxy.stop();
}

#[test]
fn proxy_scope_can_block_connect() {
    let origin = common::TestServer::start(|_| response(200, "OK", "text/plain", "hit"));
    let mut test_project = common::TestProject::new();
    test_project.project.config.scope.include = vec!["http://example.com/*".into()];
    test_project.project.save_config().unwrap();
    let mut proxy = ProxyServer::start(
        &test_project.project,
        &ProxyOptions {
            only_in_scope: true,
            ..proxy_options(0, false)
        },
    )
    .unwrap();
    let proxy_addr = proxy.local_addr();

    let mut stream = TcpStream::connect(proxy_addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        origin.addr().port(),
        origin.addr().port()
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.contains("403"), "{response}");
    assert!(response.contains("blocked"), "{response}");
    proxy.stop();
}
