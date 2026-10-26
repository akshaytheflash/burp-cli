//! Integration tests for the intruder engine.

mod common;

use burpcli::http::{ClientOptions, Request};
use burpcli::intruder::{self, AttackType, ExtractRule, IntruderOptions, PayloadSet, Processor};
use common::{query_param, TestServer};
use std::collections::HashSet;

fn template(url: &str) -> Request {
    let parsed = url::Url::parse(url).unwrap();
    let mut request = Request::from_url("GET", &parsed, Vec::new(), None);
    request.target = "/login?user=§u§&pass=§p§".to_string();
    request
}

#[test]
fn cluster_bomb_sends_every_combination_and_extracts_tokens() {
    let server = TestServer::start(|request| {
        let user = query_param(request, "user").unwrap_or_default();
        let pass = query_param(request, "pass").unwrap_or_default();
        if user == "ADMIN" && pass == "pw1" {
            common::text("welcome token=tok-ok")
        } else {
            common::text(format!("denied token=tok-{user}-{pass}"))
        }
    });
    let template = template(&server.url("/login"));
    let options = IntruderOptions {
        attack: AttackType::ClusterBomb,
        payload_sets: vec![
            PayloadSet::parse("list:admin,guest")
                .unwrap()
                .with_processors(vec![Processor::Upper]),
            PayloadSet::parse("list:pw1,pw2").unwrap(),
        ],
        concurrency: 2,
        delay_ms: 0,
        grep: vec!["welcome".into()],
        extract: vec![ExtractRule::parse("token=token=tok-(\\S+)").unwrap()],
        stop_on: Vec::new(),
        max_requests: 0,
        save_responses: true,
        quiet: true,
    };
    let run = intruder::run(&template, &options, &ClientOptions::default()).unwrap();
    assert_eq!(run.generated, 4);
    assert_eq!(run.results.len(), 4);
    assert!(run.errors.is_empty(), "{:?}", run.errors);
    assert_eq!(run.total_positions, 2);

    let payloads: HashSet<String> = run
        .results
        .iter()
        .map(|result| result.payloads.join("|"))
        .collect();
    assert_eq!(payloads.len(), 4);
    assert!(payloads.contains("ADMIN|pw1"));

    let admin = run
        .results
        .iter()
        .find(|result| result.payloads[0] == "ADMIN" && result.payloads[1] == "pw1")
        .unwrap();
    assert_eq!(admin.status, 200);
    assert!(admin.grep_hit());
    assert_eq!(admin.extracted.get("token").unwrap(), "ok");
    assert!(admin.response_b64.is_some());

    let hits = server.hits();
    assert_eq!(hits.len(), 4);
    assert!(
        hits.iter()
            .any(|hit| query_param(hit, "user").as_deref() == Some("ADMIN")),
        "processor was not applied"
    );
    assert!(
        !hits
            .iter()
            .any(|hit| query_param(hit, "user").as_deref() == Some("admin")),
        "unprocessed payload leaked"
    );
    let csv = intruder::to_csv(&run.results, &["token".to_string()]);
    assert!(csv.contains("token"), "{csv}");
    let json: serde_json::Value =
        serde_json::from_str(&intruder::to_json(&run.results).unwrap()).unwrap();
    let admin_json = json
        .as_array()
        .unwrap()
        .iter()
        .find(|result| result["payloads"][0] == "ADMIN" && result["payloads"][1] == "pw1")
        .expect("admin result in JSON");
    assert_eq!(admin_json["extracted"]["token"], "ok");
}

#[test]
fn sniper_uses_one_payload_set_per_position() {
    let server = TestServer::start(|request| {
        common::text(format!(
            "{}={}",
            request.target,
            request.header("X-Test").unwrap_or("")
        ))
    });
    let mut template = template(&server.url("/sniper"));
    template.target = "/sniper?x=§a§&y=§b§".to_string();
    let options = IntruderOptions {
        attack: AttackType::Sniper,
        payload_sets: vec![PayloadSet::parse("list:1,2").unwrap()],
        ..IntruderOptions::default()
    };
    let run = intruder::run(&template, &options, &ClientOptions::default()).unwrap();
    assert_eq!(run.generated, 4);
    assert_eq!(run.results.len(), 4);
    let payloads: HashSet<String> = run
        .results
        .iter()
        .map(|result| result.payloads.join("|"))
        .collect();
    assert!(payloads.contains("1|"));
    assert!(payloads.contains("|1"));
}

#[test]
fn stop_rule_ends_the_attack_early() {
    let server = TestServer::start(|request| {
        if query_param(request, "user").as_deref() == Some("banned") {
            common::text("STOP-NOW")
        } else {
            common::text("ok")
        }
    });
    let mut request = Request::from_url(
        "GET",
        &url::Url::parse(&server.url("/stop?user=x")).unwrap(),
        Vec::new(),
        None,
    );
    request.target = "/stop?user=§u§".to_string();
    let options = IntruderOptions {
        attack: AttackType::Sniper,
        payload_sets: vec![PayloadSet::parse("list:first,banned,last").unwrap()],
        stop_on: vec!["STOP-NOW".into()],
        concurrency: 1,
        ..IntruderOptions::default()
    };
    let run = intruder::run(&request, &options, &ClientOptions::default()).unwrap();
    assert!(run.stopped_early);
    assert!(run.results.len() < 3, "{} results", run.results.len());
    assert!(run
        .results
        .iter()
        .any(|result| result.payloads.first().map(String::as_str) == Some("banned")));
}

#[test]
fn max_requests_limits_generation() {
    let server = TestServer::start(|_| common::text("ok"));
    let template = template(&server.url("/limit"));
    let options = IntruderOptions {
        attack: AttackType::Sniper,
        payload_sets: vec![PayloadSet::parse("numbers:1-100").unwrap()],
        max_requests: 2,
        ..IntruderOptions::default()
    };
    let run = intruder::run(&template, &options, &ClientOptions::default()).unwrap();
    assert_eq!(run.generated, 2);
    assert_eq!(run.results.len(), 2);
    assert_eq!(server.hits().len(), 2);
}

#[test]
fn payload_sources_and_processors_round_trip() {
    assert_eq!(
        PayloadSet::parse("numbers:001-003")
            .unwrap()
            .values()
            .unwrap(),
        vec!["001", "002", "003"]
    );
    assert_eq!(
        PayloadSet::parse("hex:0a-0c").unwrap().values().unwrap(),
        vec!["0a", "0b", "0c"]
    );
    let processed = PayloadSet::parse("list:a b,Hello")
        .unwrap()
        .with_processors(vec![Processor::UrlEncode, Processor::Lower]);
    assert_eq!(processed.values().unwrap(), vec!["a%20b", "hello"]);
}
