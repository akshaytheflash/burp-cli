//! End-to-end tests that drive the compiled `burpcli` binary.

mod common;

use common::{reflect_q, TestServer};
use std::process::{Command, Output};
use tempfile::TempDir;

fn home() -> TempDir {
    TempDir::new().unwrap()
}

fn run(home: &TempDir, args: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_burpcli"))
        .args(args)
        .env("BURPCLI_HOME", home.path())
        .env("NO_COLOR", "1")
        .output()
        .expect("run burpcli")
}

fn run_ok(home: &TempDir, args: &[String]) -> String {
    let output = run(home, args);
    assert!(
        output.status.success(),
        "burpcli {:?} failed\nstdout:\n{}\nstderr:\n{}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn s(value: &str) -> String {
    value.to_string()
}

#[test]
fn version_and_help() {
    let home = home();
    let version = run_ok(&home, &[s("--version")]);
    assert!(version.contains("1.0.0"), "{version}");
    let help = run_ok(&home, &[s("--help")]);
    for command in [
        "proxy",
        "scanner",
        "scan",
        "intruder",
        "repeater",
        "decoder",
        "comparer",
        "sequencer",
        "report",
        "plugin",
        "oob",
    ] {
        assert!(help.contains(command), "missing {command} in help");
    }
}

#[test]
fn decoder_and_comparer_round_trip() {
    let home = home();
    let encoded = run_ok(
        &home,
        &[
            s("decoder"),
            s("hello world"),
            s("--codec"),
            s("base64"),
            s("--encode"),
        ],
    );
    let encoded = encoded.trim();
    assert_eq!(encoded, "aGVsbG8gd29ybGQ=");
    let decoded = run_ok(
        &home,
        &[s("decoder"), s(encoded), s("--codec"), s("base64")],
    );
    assert_eq!(decoded.trim(), "hello world");

    let diff = run_ok(
        &home,
        &[
            s("comparer"),
            s("alpha\nbeta"),
            s("alpha\ngamma"),
            s("--json"),
        ],
    );
    let value: serde_json::Value = serde_json::from_str(&diff).unwrap();
    assert_eq!(value["added"], 1);
    assert_eq!(value["removed"], 1);

    let workspace = TempDir::new().unwrap();
    let file_a = workspace.path().join("a.txt");
    let file_b = workspace.path().join("b.txt");
    std::fs::write(&file_a, "one\ntwo\n").unwrap();
    std::fs::write(&file_b, "one\nthree\n").unwrap();
    let diff = run_ok(
        &home,
        &[
            s("comparer"),
            s("--file-a"),
            file_a.display().to_string(),
            s("--file-b"),
            file_b.display().to_string(),
            s("--mode"),
            s("lines"),
        ],
    );
    assert!(diff.contains("two"));
    assert!(diff.contains("three"));
}

#[test]
fn project_scope_session_and_config_commands() {
    let home = home();
    let workspace = TempDir::new().unwrap();
    let project = workspace.path().join("proj");
    let project_arg = project.display().to_string();
    let created = run_ok(
        &home,
        &[
            s("project"),
            s("create"),
            s(&project_arg),
            s("--name"),
            s("cli-test"),
        ],
    );
    assert!(created.contains("created project"), "{created}");
    assert!(project.join("project.toml").exists());

    let info = run_ok(
        &home,
        &[
            s("project"),
            s("info"),
            s("--project"),
            s(&project_arg),
            s("--json"),
        ],
    );
    let info: serde_json::Value = serde_json::from_str(&info).unwrap();
    assert_eq!(info["name"], "cli-test");

    run_ok(
        &home,
        &[
            s("scope"),
            s("add"),
            s("http://example.com/*"),
            s("--project"),
            s(&project_arg),
        ],
    );
    let check = run_ok(
        &home,
        &[
            s("scope"),
            s("check"),
            s("http://example.com/a"),
            s("--project"),
            s(&project_arg),
        ],
    );
    assert!(check.contains("in scope"), "{check}");

    run_ok(
        &home,
        &[
            s("session"),
            s("set-cookie"),
            s("example.com"),
            s("sid"),
            s("abc"),
            s("--project"),
            s(&project_arg),
        ],
    );
    let session = run_ok(
        &home,
        &[
            s("session"),
            s("show"),
            s("--project"),
            s(&project_arg),
            s("--json"),
        ],
    );
    let session: serde_json::Value = serde_json::from_str(&session).unwrap();
    assert_eq!(session["cookies"][0]["name"], "sid");

    run_ok(&home, &[s("config"), s("set"), s("color"), s("never")]);
    let color = run_ok(&home, &[s("config"), s("get"), s("color")]);
    assert_eq!(color.trim(), "never");
}

#[test]
fn repeater_history_and_sitemap_commands() {
    let home = home();
    let workspace = TempDir::new().unwrap();
    let project = workspace.path().join("proj");
    let project_arg = project.display().to_string();
    run_ok(&home, &[s("project"), s("create"), s(&project_arg)]);
    let server = TestServer::start(|request| {
        common::html(format!(
            "<html><title>echo</title>{}</html>",
            request.target
        ))
    });

    let repeated = run_ok(
        &home,
        &[
            s("repeater"),
            s("--url"),
            s(&server.url("/repeater?x=1")),
            s("--project"),
            s(&project_arg),
            s("--json"),
        ],
    );
    let value: serde_json::Value = serde_json::from_str(&repeated).unwrap();
    assert_eq!(value[0]["status"], 200);
    assert!(value[0]["response"]
        .as_str()
        .unwrap()
        .contains("/repeater?x=1"));

    let history = run_ok(
        &home,
        &[
            s("history"),
            s("list"),
            s("--project"),
            s(&project_arg),
            s("--json"),
        ],
    );
    let history: serde_json::Value = serde_json::from_str(&history).unwrap();
    assert_eq!(history.as_array().unwrap().len(), 1);
    assert_eq!(history[0]["method"], "GET");

    run_ok(
        &home,
        &[
            s("sitemap"),
            s("add"),
            s(&server.url("/sitemap")),
            s("--project"),
            s(&project_arg),
        ],
    );
    let listed = run_ok(
        &home,
        &[
            s("sitemap"),
            s("list"),
            s("--project"),
            s(&project_arg),
            s("--json"),
        ],
    );
    let listed: serde_json::Value = serde_json::from_str(&listed).unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert!(listed[0]["url"].as_str().unwrap().contains("/sitemap"));
}

#[test]
fn scan_report_and_intruder_commands() {
    let home = home();
    let workspace = TempDir::new().unwrap();
    let project = workspace.path().join("proj");
    let project_arg = project.display().to_string();
    run_ok(&home, &[s("project"), s("create"), s(&project_arg)]);
    let server = TestServer::start(reflect_q);

    let report_path = workspace.path().join("scan.json");
    let report_arg = report_path.display().to_string();
    let output = run_ok(
        &home,
        &[
            s("scan"),
            s(&server.url("/search?q=hello")),
            s("--check"),
            s("xss"),
            s("--point"),
            s("query"),
            s("--save-evidence"),
            s("--format"),
            s("json"),
            s("--output"),
            s(&report_arg),
            s("--project"),
            s(&project_arg),
        ],
    );
    assert!(output.contains("findings"), "{output}");
    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
    assert_eq!(report["summary"]["high"], 1);
    assert_eq!(report["issues"][0]["check"], "xss");

    let sarif_path = workspace.path().join("report.sarif");
    let sarif_arg = sarif_path.display().to_string();
    run_ok(
        &home,
        &[
            s("report"),
            s("--format"),
            s("sarif"),
            s("--output"),
            s(&sarif_arg),
            s("--project"),
            s(&project_arg),
        ],
    );
    let sarif: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sarif_path).unwrap()).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    assert!(!sarif["runs"][0]["results"].as_array().unwrap().is_empty());

    let stats = run_ok(
        &home,
        &[s("report"), s("--stats"), s("--project"), s(&project_arg)],
    );
    assert!(stats.contains("High"), "{stats}");

    let attack = run_ok(
        &home,
        &[
            s("intruder"),
            s("--url"),
            s(&server.url("/search?q=hello")),
            s("--wrap"),
            s("hello"),
            s("--payload"),
            s("list:<script>,safe"),
            s("--project"),
            s(&project_arg),
            s("--show"),
            s("0"),
        ],
    );
    assert!(attack.contains("<script>"), "{attack}");
    assert!(
        attack.contains("sniper") || attack.contains("requests"),
        "{attack}"
    );

    let marker_attack = run_ok(
        &home,
        &[
            s("intruder"),
            s("--url"),
            s(&server.url("/search?q=§x§")),
            s("--payload"),
            s("list:one,two"),
            s("--project"),
            s(&project_arg),
            s("--show"),
            s("0"),
        ],
    );
    assert!(marker_attack.contains("2 requests"), "{marker_attack}");
}

#[test]
fn ca_plugin_and_sequencer_commands() {
    let home = home();
    let workspace = TempDir::new().unwrap();
    let project = workspace.path().join("proj");
    let project_arg = project.display().to_string();
    run_ok(&home, &[s("project"), s("create"), s(&project_arg)]);

    let ca = run_ok(
        &home,
        &[s("ca"), s("show"), s("--project"), s(&project_arg)],
    );
    assert!(ca.contains("BEGIN CERTIFICATE"), "{ca}");
    let ca_info = run_ok(
        &home,
        &[s("ca"), s("info"), s("--project"), s(&project_arg)],
    );
    assert!(ca_info.contains("sha256"), "{ca_info}");
    assert!(project.join("ca").exists());

    run_ok(
        &home,
        &[
            s("plugin"),
            s("install-demo"),
            s("--project"),
            s(&project_arg),
        ],
    );
    let plugins = run_ok(
        &home,
        &[
            s("plugin"),
            s("list"),
            s("--project"),
            s(&project_arg),
            s("--json"),
        ],
    );
    let plugins: serde_json::Value = serde_json::from_str(&plugins).unwrap();
    assert_eq!(plugins[0]["name"], "demo");
    let tested = run_ok(
        &home,
        &[
            s("plugin"),
            s("test"),
            s("demo"),
            s("--project"),
            s(&project_arg),
        ],
    );
    assert!(tested.contains("ok:"), "{tested}");

    let tokens = workspace.path().join("tokens.txt");
    let values = (0..40)
        .map(|index| format!("{:016x}", index * 7919 + 13))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&tokens, values).unwrap();
    let sequencer = run_ok(
        &home,
        &[
            s("sequencer"),
            s("--file"),
            s(&tokens.display().to_string()),
            s("--json"),
        ],
    );
    let analysis: serde_json::Value = serde_json::from_str(&sequencer).unwrap();
    assert_eq!(analysis["count"], 40);
    assert!(analysis["verdict"].is_string());
}

#[test]
fn scan_fail_on_returns_non_zero_exit_code() {
    let home = home();
    let workspace = TempDir::new().unwrap();
    let project = workspace.path().join("proj");
    let project_arg = project.display().to_string();
    run_ok(&home, &[s("project"), s("create"), s(&project_arg)]);
    let server = TestServer::start(reflect_q);
    let output = run(
        &home,
        &[
            s("scan"),
            s(&server.url("/search?q=x")),
            s("--check"),
            s("xss"),
            s("--point"),
            s("query"),
            s("--fail-on"),
            s("high"),
            s("--project"),
            s(&project_arg),
        ],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("finding"), "{stderr}");
}
