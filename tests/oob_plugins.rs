//! Integration tests for the OOB collaborator and the plugin protocol.

mod common;

use burpcli::http::{client, Response};
use burpcli::oob::{OobProvider, OobServer, RemoteOob};
use burpcli::plugins::{self, PluginManager};
use burpcli::scanner::Severity;
use std::time::Duration;

#[test]
fn local_oob_records_a_callback() {
    let test_project = common::TestProject::new();
    let mut server = OobServer::start(
        "127.0.0.1",
        0,
        None,
        Some(burpcli::oob::events_path(&test_project.project)),
    )
    .unwrap();
    let token = server.new_token();
    let url = server.payload_url(&token);
    assert!(url.contains(&token));

    let request =
        burpcli::http::Request::from_url("GET", &url::Url::parse(&url).unwrap(), Vec::new(), None);
    let result = client::send(&request, &Default::default()).unwrap();
    assert_eq!(result.response.status, 200);

    assert!(
        server.wait_for_hit(&token, Duration::from_secs(5)),
        "callback was not recorded"
    );
    let events = server.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].token, token);
    assert_eq!(events[0].method, "GET");
    assert!(events[0].path.contains(&token));
    assert!(burpcli::oob::events_path(&test_project.project).exists());
    server.stop();
}

#[test]
fn remote_oob_provider_polls_the_server() {
    let server = OobServer::start("127.0.0.1", 0, None, None).unwrap();
    let provider = RemoteOob::new(server.base_url());
    let token = provider.new_token();
    let url = provider.payload_url(&token);
    let request = burpcli::http::Request::from_url(
        "POST",
        &url::Url::parse(&url).unwrap(),
        b"exfiltrated=1".to_vec(),
        Some("application/x-www-form-urlencoded"),
    );
    client::send(&request, &Default::default()).unwrap();
    assert!(provider.wait_for_hit(&token, Duration::from_secs(5)));
    assert!(server.wait_for_token(&token, Duration::from_secs(2)));
    let events = server.events();
    assert_eq!(events[0].method, "POST");
    assert!(
        events[0].body.contains("exfiltrated=1"),
        "{:?}",
        events[0].body
    );
}

fn install_test_plugin(project: &burpcli::storage::Project) -> std::path::PathBuf {
    let exe = std::env::var("CARGO_BIN_EXE_burpcli").unwrap_or_else(|_| {
        std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .join("burpcli.exe")
            .display()
            .to_string()
    });
    let command = format!("{} __plugin-demo", exe.replace('\\', "/"));
    let dir = project.plugins_dir().join("demo");
    std::fs::create_dir_all(&dir).unwrap();
    let manifest = format!(
        "name = \"demo\"\ndescription = \"integration demo\"\ncommand = \"{command}\"\nhooks = [\"request\", \"response\", \"passive\"]\nenabled = true\ntimeout_ms = 10000\n"
    );
    let path = dir.join("plugin.toml");
    std::fs::write(&path, manifest).unwrap();
    path
}

#[test]
fn plugin_protocol_round_trip() {
    let test_project = common::TestProject::new();
    let manifest = install_test_plugin(&test_project.project);
    assert!(manifest.exists());

    let manager =
        PluginManager::load(&test_project.project.plugins_dir(), Duration::from_secs(10)).unwrap();
    assert_eq!(manager.plugins().len(), 1);
    assert!(manager.plugins()[0].accepts("response"));

    let request =
        burpcli::http::Request::parse(b"GET /plugin-demo HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
    let mut response = Response::new(200, "OK");
    response.set_header("Content-Type", "text/html");
    response.body = b"<html>plugin-demo</html>".to_vec();

    let effects = manager.apply_response(&request, &mut response);
    assert!(effects.errors.is_empty(), "{:?}", effects.errors);
    assert!(!effects.dropped);
    assert_eq!(
        response.header("X-Burpcli-Plugin"),
        Some("demo"),
        "plugin did not modify the response"
    );
    assert!(
        effects
            .issues
            .iter()
            .any(|issue| issue.check == "plugin-demo" && issue.severity == Severity::Low),
        "{:?}",
        effects.issues.iter().map(|i| &i.check).collect::<Vec<_>>()
    );

    let passive = manager.passive(&request, &response);
    assert!(passive.errors.is_empty(), "{:?}", passive.errors);
    assert!(passive
        .issues
        .iter()
        .any(|issue| issue.check == "plugin-demo"));

    let plugin = &manager.plugins()[0];
    let output = plugins::test_plugin(plugin).unwrap();
    assert_eq!(output.action.as_deref(), Some("continue"));
    assert!(output.request.is_none());
    assert!(output.response.is_none());
}

#[test]
fn scanner_runs_passive_plugin_hooks() {
    let mut test_project = common::TestProject::new();
    install_test_plugin(&test_project.project);
    test_project.project.config.plugins.enabled = true;

    let server =
        common::TestServer::start(|_| common::html("<html><body>plugin-demo page</body></html>"));
    let options = burpcli::scanner::ScanOptions {
        target: burpcli::scanner::Target::Url(server.url("/")),
        checks: Vec::new(),
        passive_only: true,
        timeout_ms: 5_000,
        quiet: true,
        ..Default::default()
    };
    let result = burpcli::scanner::scan(&test_project.project, &options).unwrap();
    assert!(
        result
            .issues
            .iter()
            .any(|issue| issue.check == "plugin-demo" && issue.severity == Severity::Low),
        "passive plugin finding missing: {:?}",
        result
            .issues
            .iter()
            .map(|issue| &issue.check)
            .collect::<Vec<_>>()
    );
}

#[test]
fn plugin_disable_and_remove_helpers_work() {
    let test_project = common::TestProject::new();
    install_test_plugin(&test_project.project);
    let dir = test_project.project.plugins_dir();
    let mut manager = PluginManager::load(&dir, Duration::from_secs(5)).unwrap();
    assert_eq!(manager.plugins().len(), 1);
    let plugin = manager.plugins()[0].clone();
    assert!(plugins::remove_plugin(&dir, &plugin.manifest.name).unwrap());
    manager = PluginManager::load(&dir, Duration::from_secs(5)).unwrap();
    assert!(manager.is_empty());
}
