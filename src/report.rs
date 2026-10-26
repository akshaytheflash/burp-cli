//! Report generation: console tables, JSON, HTML, Burp XML, SARIF and Markdown.
//!
//! Every renderer is a pure function over a slice of issues so that the output
//! can be tested and reused by plugins or CI pipelines without starting a
//! project.

use crate::scanner::{Issue, Severity};
use crate::util::{b64_decode, format_size, html_escape, now_rfc3339, truncate};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportFormat {
    Table,
    Json,
    Html,
    BurpXml,
    Sarif,
    Markdown,
}

impl ReportFormat {
    pub fn parse(value: &str) -> Result<Self> {
        match value
            .trim()
            .to_ascii_lowercase()
            .replace(['_', ' '], "-")
            .as_str()
        {
            "table" | "text" | "console" => Ok(Self::Table),
            "json" => Ok(Self::Json),
            "html" | "htm" => Ok(Self::Html),
            "burp" | "burp-xml" | "burpxml" | "xml" => Ok(Self::BurpXml),
            "sarif" | "sarif-json" => Ok(Self::Sarif),
            "markdown" | "md" => Ok(Self::Markdown),
            other => bail!(
                "unknown report format '{other}' (use table, json, html, burp-xml, sarif or markdown)"
            ),
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Table => "table",
            Self::Json => "json",
            Self::Html => "html",
            Self::BurpXml => "burp-xml",
            Self::Sarif => "sarif",
            Self::Markdown => "markdown",
        }
    }

    pub fn extension(&self) -> &'static str {
        match self {
            Self::Table => "txt",
            Self::Json => "json",
            Self::Html => "html",
            Self::BurpXml => "xml",
            Self::Sarif => "sarif",
            Self::Markdown => "md",
        }
    }

    /// Guess the format from a file extension, falling back to `Table`.
    pub fn from_path(path: &Path) -> Self {
        match path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase()
            .as_str()
        {
            "json" | "sarif" => Self::Json,
            "html" | "htm" => Self::Html,
            "xml" => Self::BurpXml,
            "md" | "markdown" => Self::Markdown,
            _ => Self::Table,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ReportOptions {
    pub title: String,
    pub min_severity: Severity,
    /// Include raw request/response evidence in machine-readable formats.
    pub include_evidence: bool,
}

impl Default for ReportOptions {
    fn default() -> Self {
        Self {
            title: "burpcli security report".into(),
            min_severity: Severity::Info,
            include_evidence: true,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ReportStats {
    pub total: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub by_check: BTreeMap<String, usize>,
}

pub fn filter(issues: &[Issue], min_severity: Severity) -> Vec<Issue> {
    issues
        .iter()
        .filter(|issue| issue.severity.rank() >= min_severity.rank())
        .cloned()
        .collect()
}

pub fn stats(issues: &[Issue]) -> ReportStats {
    let mut stats = ReportStats {
        total: issues.len(),
        ..Default::default()
    };
    for issue in issues {
        match issue.severity {
            Severity::High => stats.high += 1,
            Severity::Medium => stats.medium += 1,
            Severity::Low => stats.low += 1,
            Severity::Info => stats.info += 1,
        }
        *stats.by_check.entry(issue.check.clone()).or_insert(0) += 1;
    }
    stats
}

fn sorted(issues: &[Issue]) -> Vec<Issue> {
    let mut out = issues.to_vec();
    out.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then_with(|| a.title.cmp(&b.title))
            .then_with(|| a.url.cmp(&b.url))
    });
    out
}

pub fn table(issues: &[Issue], min_severity: Severity) -> String {
    let issues = sorted(&filter(issues, min_severity));
    if issues.is_empty() {
        return "no findings\n".to_string();
    }
    let stats = stats(&issues);
    let mut out = String::new();
    out.push_str(&format!(
        "{} ({} findings: {} high, {} medium, {} low, {} info)\n\n",
        "Findings", stats.total, stats.high, stats.medium, stats.low, stats.info
    ));
    let headers = ["Severity", "Check", "Title", "Method", "URL"];
    let rows: Vec<Vec<String>> = issues
        .iter()
        .map(|issue| {
            vec![
                issue.severity.label().to_string(),
                issue.check.clone(),
                truncate(&issue.title, 46),
                issue.method.clone(),
                truncate(&issue.url, 72),
            ]
        })
        .collect();
    let limits = [10usize, 16, 48, 7, 74];
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in &rows {
        for (index, cell) in row.iter().enumerate() {
            widths[index] = widths[index].max(cell.chars().count()).min(limits[index]);
        }
    }
    let border = || {
        let mut line = String::from("+");
        for width in &widths {
            line.push_str(&"-".repeat(width + 2));
            line.push('+');
        }
        line.push('\n');
        line
    };
    out.push_str(&border());
    let mut header = String::from("|");
    for (index, name) in headers.iter().enumerate() {
        header.push_str(&format!(" {:<width$} |", name, width = widths[index]));
    }
    header.push('\n');
    out.push_str(&header);
    out.push_str(&border());
    for row in &rows {
        let mut line = String::from("|");
        for (index, cell) in row.iter().enumerate() {
            let cell = truncate(cell, widths[index]);
            line.push_str(&format!(" {:<width$} |", cell, width = widths[index]));
        }
        line.push('\n');
        out.push_str(&line);
    }
    out.push_str(&border());
    out
}

#[derive(Serialize)]
struct JsonReport<'a> {
    tool: ToolInfo,
    project: &'a str,
    generated: String,
    title: &'a str,
    summary: ReportStats,
    issues: Vec<serde_json::Value>,
}

#[derive(Serialize)]
struct ToolInfo {
    name: &'static str,
    version: &'static str,
}

pub fn json(issues: &[Issue], options: &ReportOptions, project: &str) -> Result<String> {
    let issues = sorted(&filter(issues, options.min_severity));
    let mut values = Vec::with_capacity(issues.len());
    for issue in &issues {
        let mut value = serde_json::to_value(issue)?;
        if !options.include_evidence {
            if let Some(object) = value.as_object_mut() {
                object.remove("request");
                object.remove("response");
            }
        }
        values.push(value);
    }
    let report = JsonReport {
        tool: ToolInfo {
            name: crate::PRODUCT,
            version: crate::VERSION,
        },
        project,
        generated: now_rfc3339(),
        title: &options.title,
        summary: stats(&issues),
        issues: values,
    };
    Ok(serde_json::to_string_pretty(&report)?)
}

pub fn html(issues: &[Issue], options: &ReportOptions, project: &str) -> String {
    let issues = sorted(&filter(issues, options.min_severity));
    let stats = stats(&issues);
    let mut body = String::new();
    for issue in &issues {
        let severity_class = issue.severity.label().to_ascii_lowercase();
        body.push_str(&format!(
            "<article class=\"issue sev-{severity_class}\" id=\"issue-{id}\">\n",
            id = html_escape(&issue.id)
        ));
        body.push_str(&format!(
            "<header><span class=\"badge\">{}</span><h2>{}</h2></header>\n",
            issue.severity.label(),
            html_escape(&issue.title)
        ));
        body.push_str(&format!(
            "<p class=\"meta\"><code>{method}</code> <a href=\"{url}\">{url}</a> &middot; confidence: {confidence} &middot; check: {check}{cwe}</p>\n",
            method = html_escape(&issue.method),
            url = html_escape(&issue.url),
            confidence = html_escape(issue.confidence.label()),
            check = html_escape(&issue.check),
            cwe = issue
                .cwe
                .map(|cwe| format!(" &middot; CWE-{cwe}"))
                .unwrap_or_default()
        ));
        if let Some(parameter) = &issue.parameter {
            body.push_str(&format!(
                "<p class=\"meta\">Parameter: <code>{}</code>{}</p>\n",
                html_escape(parameter),
                issue
                    .payload
                    .as_ref()
                    .map(|payload| format!(
                        " &middot; Payload: <code>{}</code>",
                        html_escape(payload)
                    ))
                    .unwrap_or_default()
            ));
        }
        if !issue.detail.is_empty() {
            body.push_str(&format!("<p>{}</p>\n", html_escape(&issue.detail)));
        }
        if !issue.evidence.is_empty() {
            body.push_str(&format!(
                "<details><summary>Evidence</summary><pre>{}</pre></details>\n",
                html_escape(&issue.evidence)
            ));
        }
        if options.include_evidence {
            if let Some(request) = decode_evidence(&issue.request) {
                body.push_str(&format!(
                    "<details><summary>Request</summary><pre>{}</pre></details>\n",
                    html_escape(&request)
                ));
            }
            if let Some(response) = decode_evidence(&issue.response) {
                body.push_str(&format!(
                    "<details><summary>Response</summary><pre>{}</pre></details>\n",
                    html_escape(&response)
                ));
            }
        }
        if !issue.remediation.is_empty() {
            body.push_str(&format!(
                "<p class=\"remediation\"><strong>Remediation:</strong> {}</p>\n",
                html_escape(&issue.remediation)
            ));
        }
        if !issue.references.is_empty() {
            body.push_str("<ul class=\"references\">");
            for reference in &issue.references {
                body.push_str(&format!(
                    "<li><a href=\"{0}\">{0}</a></li>",
                    html_escape(reference)
                ));
            }
            body.push_str("</ul>\n");
        }
        body.push_str("</article>\n");
    }
    if issues.is_empty() {
        body.push_str("<p class=\"empty\">No findings at or above the selected severity.</p>\n");
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{ color-scheme: light; }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
       color: #17202a; background: #f4f6f8; line-height: 1.55; }}
main {{ max-width: 1080px; margin: 0 auto; padding: 40px 24px 80px; }}
h1 {{ margin: 0 0 4px; font-size: 2rem; letter-spacing: -0.02em; }}
.sub {{ color: #667085; margin: 0 0 28px; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; margin-bottom: 32px; }}
.card {{ background: #fff; border: 1px solid #e4e7ec; border-radius: 10px; padding: 14px 16px; }}
.card b {{ display: block; font-size: 1.6rem; line-height: 1.2; }}
.card span {{ color: #667085; font-size: .82rem; text-transform: uppercase; letter-spacing: .06em; }}
.card.high b {{ color: #b42318; }} .card.medium b {{ color: #b54708; }}
.card.low b {{ color: #0b6bcb; }} .card.info b {{ color: #475467; }}
.issue {{ background: #fff; border: 1px solid #e4e7ec; border-left: 5px solid #98a2b3;
          border-radius: 10px; padding: 18px 20px; margin-bottom: 14px; }}
.issue.sev-high {{ border-left-color: #d92d20; }}
.issue.sev-medium {{ border-left-color: #f79009; }}
.issue.sev-low {{ border-left-color: #2e90fa; }}
.issue.sev-info {{ border-left-color: #98a2b3; }}
.issue header {{ display: flex; align-items: center; gap: 10px; }}
.issue h2 {{ margin: 0; font-size: 1.05rem; }}
.badge {{ font-size: .72rem; font-weight: 700; text-transform: uppercase; letter-spacing: .06em;
          padding: 2px 8px; border-radius: 999px; background: #eef2f6; color: #344054; }}
.sev-high .badge {{ background: #fee4e2; color: #b42318; }}
.sev-medium .badge {{ background: #fef0c7; color: #b54708; }}
.sev-low .badge {{ background: #d1e9ff; color: #0b6bcb; }}
.meta {{ color: #475467; font-size: .88rem; margin: 8px 0; }}
a {{ color: #175cd3; }}
code {{ background: #f2f4f7; padding: 1px 5px; border-radius: 4px; font-size: .86em; }}
pre {{ background: #101828; color: #e4e7ec; padding: 12px; border-radius: 8px;
       overflow-x: auto; font-size: .82rem; line-height: 1.45; }}
details {{ margin: 10px 0; }}
summary {{ cursor: pointer; color: #475467; font-weight: 600; }}
.remediation {{ background: #ecfdf3; border: 1px solid #abefc6; border-radius: 8px; padding: 10px 12px; }}
.references {{ font-size: .86rem; color: #475467; }}
footer {{ color: #98a2b3; font-size: .8rem; margin-top: 40px; }}
.empty {{ background: #fff; border: 1px solid #e4e7ec; border-radius: 10px; padding: 24px; }}
@media print {{ body {{ background: #fff; }} .issue {{ break-inside: avoid; }} }}
</style>
</head>
<body>
<main>
<h1>{title}</h1>
<p class="sub">Project <strong>{project}</strong> &middot; generated {generated} &middot; {tool} {version}</p>
<div class="cards">
  <div class="card"><b>{total}</b><span>Total</span></div>
  <div class="card high"><b>{high}</b><span>High</span></div>
  <div class="card medium"><b>{medium}</b><span>Medium</span></div>
  <div class="card low"><b>{low}</b><span>Low</span></div>
  <div class="card info"><b>{info}</b><span>Info</span></div>
</div>
{body}
<footer>Generated by {tool} {version}. Findings are the result of automated testing and require manual validation.</footer>
</main>
</body>
</html>
"#,
        title = html_escape(&options.title),
        project = html_escape(project),
        generated = now_rfc3339(),
        tool = crate::PRODUCT,
        version = crate::VERSION,
        total = stats.total,
        high = stats.high,
        medium = stats.medium,
        low = stats.low,
        info = stats.info,
        body = body
    )
}

pub fn markdown(issues: &[Issue], options: &ReportOptions, project: &str) -> String {
    let issues = sorted(&filter(issues, options.min_severity));
    let stats = stats(&issues);
    let mut out = String::new();
    out.push_str(&format!("# {}\n\n", options.title));
    out.push_str(&format!(
        "Project **{}** | generated {} | {} {}\n\n",
        project,
        now_rfc3339(),
        crate::PRODUCT,
        crate::VERSION
    ));
    out.push_str(&format!(
        "| Total | High | Medium | Low | Info |\n|---:|---:|---:|---:|---:|\n| {} | {} | {} | {} | {} |\n\n",
        stats.total, stats.high, stats.medium, stats.low, stats.info
    ));
    if issues.is_empty() {
        out.push_str("_No findings at or above the selected severity._\n");
        return out;
    }
    out.push_str("## Findings\n\n");
    for (index, issue) in issues.iter().enumerate() {
        out.push_str(&format!(
            "### {}. {}: {}\n\n",
            index + 1,
            issue.severity.label(),
            issue.title
        ));
        out.push_str(&format!(
            "- **URL:** `{}`\n- **Method:** `{}`\n- **Confidence:** {}\n- **Check:** `{}`\n",
            issue.url,
            issue.method,
            issue.confidence.label(),
            issue.check
        ));
        if let Some(parameter) = &issue.parameter {
            out.push_str(&format!("- **Parameter:** `{parameter}`\n"));
        }
        if let Some(payload) = &issue.payload {
            out.push_str(&format!("- **Payload:** `{payload}`\n"));
        }
        if let Some(cwe) = issue.cwe {
            out.push_str(&format!("- **CWE:** CWE-{cwe}\n"));
        }
        out.push('\n');
        if !issue.detail.is_empty() {
            out.push_str(&format!("{}\n\n", issue.detail));
        }
        if !issue.evidence.is_empty() {
            out.push_str(&format!("```\n{}\n```\n\n", issue.evidence));
        }
        if !issue.remediation.is_empty() {
            out.push_str(&format!("**Remediation:** {}\n\n", issue.remediation));
        }
    }
    out
}

pub fn burp_xml(issues: &[Issue], options: &ReportOptions) -> String {
    let issues = sorted(&filter(issues, options.min_severity));
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!(
        "<issues burpVersion=\"{}\" exportTime=\"{}\">\n",
        xml_escape(crate::VERSION),
        xml_escape(&now_rfc3339())
    ));
    for issue in &issues {
        let parsed = url::Url::parse(&issue.url).ok();
        let host = parsed
            .as_ref()
            .and_then(|u| u.host_str())
            .unwrap_or(&issue.url)
            .to_string();
        let path = parsed
            .as_ref()
            .map(|u| u.path().to_string())
            .unwrap_or_else(|| issue.url.clone());
        let location = parsed
            .as_ref()
            .map(|u| {
                format!(
                    "{}://{}{}",
                    u.scheme(),
                    u.host_str().unwrap_or(""),
                    u.path()
                )
            })
            .unwrap_or_else(|| issue.url.clone());
        let type_id = issue.check.bytes().fold(0u64, |acc, byte| {
            acc.wrapping_mul(31).wrapping_add(byte as u64)
        }) % 9_000_000
            + 1_000_000;
        let detail = {
            let mut text = issue.detail.clone();
            if let Some(parameter) = &issue.parameter {
                text.push_str(&format!("\nParameter: {parameter}"));
            }
            if let Some(payload) = &issue.payload {
                text.push_str(&format!("\nPayload: {payload}"));
            }
            if !issue.evidence.is_empty() {
                text.push_str(&format!("\nEvidence: {}", issue.evidence));
            }
            text
        };
        out.push_str("  <issue>\n");
        out.push_str(&format!(
            "    <serialNumber>{}</serialNumber>\n",
            xml_escape(&issue.id)
        ));
        out.push_str(&format!("    <type>{type_id}</type>\n"));
        out.push_str(&format!("    <name>{}</name>\n", xml_escape(&issue.title)));
        out.push_str(&format!("    <host>{}</host>\n", xml_escape(&host)));
        out.push_str(&format!("    <path>{}</path>\n", xml_escape(&path)));
        out.push_str(&format!(
            "    <location>{}</location>\n",
            xml_escape(&location)
        ));
        out.push_str(&format!(
            "    <severity>{}</severity>\n",
            issue.severity.label()
        ));
        out.push_str(&format!(
            "    <confidence>{}</confidence>\n",
            issue.confidence.label()
        ));
        out.push_str(&format!(
            "    <issueBackground>{}</issueBackground>\n",
            xml_escape(&issue.detail)
        ));
        out.push_str(&format!(
            "    <remediationBackground>{}</remediationBackground>\n",
            xml_escape(&issue.remediation)
        ));
        out.push_str(&format!(
            "    <issueDetail>{}</issueDetail>\n",
            xml_escape(&detail)
        ));
        if let Some(cwe) = issue.cwe {
            out.push_str(&format!(
                "    <vulnerabilityClassifications>CWE-{cwe}</vulnerabilityClassifications>\n"
            ));
        }
        out.push_str("    <requestresponse>\n");
        out.push_str(&format!(
            "      <request method=\"{}\" base64=\"false\">{}</request>\n",
            xml_escape(&issue.method),
            cdata(&decode_evidence(&issue.request).unwrap_or_default())
        ));
        out.push_str(&format!(
            "      <response base64=\"false\">{}</response>\n",
            cdata(&decode_evidence(&issue.response).unwrap_or_default())
        ));
        out.push_str("    </requestresponse>\n");
        out.push_str("  </issue>\n");
    }
    out.push_str("</issues>\n");
    out
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

pub fn sarif(issues: &[Issue], options: &ReportOptions) -> Result<String> {
    let issues = sorted(&filter(issues, options.min_severity));
    let mut rules: Vec<serde_json::Value> = Vec::new();
    let mut rule_index: BTreeMap<String, usize> = BTreeMap::new();
    for issue in &issues {
        if !rule_index.contains_key(&issue.check) {
            rule_index.insert(issue.check.clone(), rules.len());
            rules.push(serde_json::json!({
                "id": issue.check,
                "name": issue.check,
                "shortDescription": { "text": issue.title },
                "help": { "text": issue.remediation },
                "properties": { "tags": ["security"] }
            }));
        }
    }
    let mut results = Vec::with_capacity(issues.len());
    for issue in &issues {
        let mut properties = serde_json::Map::new();
        properties.insert(
            "confidence".into(),
            serde_json::Value::String(issue.confidence.label().into()),
        );
        if let Some(cwe) = issue.cwe {
            properties.insert("cwe".into(), serde_json::json!(cwe));
        }
        if let Some(parameter) = &issue.parameter {
            properties.insert("parameter".into(), serde_json::json!(parameter));
        }
        if let Some(payload) = &issue.payload {
            properties.insert("payload".into(), serde_json::json!(payload));
        }
        results.push(serde_json::json!({
            "ruleId": issue.check,
            "ruleIndex": rule_index.get(&issue.check).copied().unwrap_or(0),
            "level": sarif_level(issue.severity),
            "message": { "text": format!("{}: {}", issue.title, issue.detail.trim()) },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": issue.url },
                    "region": { "startLine": 1 }
                }
            }],
            "properties": properties
        }));
    }
    let document = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": crate::PRODUCT,
                    "version": crate::VERSION,
                    "informationUri": "https://github.com/",
                    "rules": rules
                }
            },
            "results": results
        }]
    });
    Ok(serde_json::to_string_pretty(&document)?)
}

pub fn render(
    issues: &[Issue],
    format: ReportFormat,
    options: &ReportOptions,
    project: &str,
) -> Result<String> {
    match format {
        ReportFormat::Table => Ok(table(issues, options.min_severity)),
        ReportFormat::Json => json(issues, options, project),
        ReportFormat::Html => Ok(html(issues, options, project)),
        ReportFormat::BurpXml => Ok(burp_xml(issues, options)),
        ReportFormat::Sarif => sarif(issues, options),
        ReportFormat::Markdown => Ok(markdown(issues, options, project)),
    }
}

pub fn write(path: &Path, content: &str) -> Result<()> {
    crate::config::atomic_write(path, content.as_bytes())
        .with_context(|| format!("cannot write report '{}'", path.display()))
}

/// Format a summary line used by the CLI.
pub fn summary_line(stats: &ReportStats) -> String {
    format!(
        "{} findings ({} high, {} medium, {} low, {} info)",
        stats.total, stats.high, stats.medium, stats.low, stats.info
    )
}

/// Size of all retained response evidence, for `report --stats`.
pub fn evidence_size(issues: &[Issue]) -> usize {
    issues
        .iter()
        .map(|issue| {
            decode_evidence(&issue.request)
                .map(|r| r.len())
                .unwrap_or(0)
                + decode_evidence(&issue.response)
                    .map(|r| r.len())
                    .unwrap_or(0)
        })
        .sum()
}

pub fn evidence_size_label(issues: &[Issue]) -> String {
    format_size(evidence_size(issues))
}

fn decode_evidence(data: &Option<String>) -> Option<String> {
    data.as_deref()
        .and_then(|value| b64_decode(value).ok())
        .map(|bytes| crate::util::display_bytes(&bytes))
}

fn xml_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\u{0}'..='\u{8}' | '\u{b}' | '\u{c}' | '\u{e}'..='\u{1f}' => {}
            other => out.push(other),
        }
    }
    out
}

fn cdata(input: &str) -> String {
    let safe = input.replace("]]>", "]]]]><![CDATA[>");
    format!("<![CDATA[{safe}]]>")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<Issue> {
        vec![
            Issue::builder("xss", "Reflected XSS", Severity::High)
                .url("http://example.com/search?q=1")
                .method("GET")
                .parameter("q")
                .payload("<script>")
                .evidence("<script>")
                .detail("Payload reflected verbatim.")
                .remediation("Encode output.")
                .cwe(79)
                .build(),
            Issue::builder("headers", "Missing CSP", Severity::Info)
                .url("http://example.com/")
                .build(),
            Issue::builder("sqli", "SQL injection", Severity::Medium)
                .url("http://example.com/item?id=1")
                .parameter("id")
                .build(),
        ]
    }

    #[test]
    fn filtering_and_stats() {
        let issues = sample();
        assert_eq!(filter(&issues, Severity::Medium).len(), 2);
        let stats = stats(&issues);
        assert_eq!(stats.total, 3);
        assert_eq!(stats.high, 1);
        assert_eq!(stats.medium, 1);
        assert_eq!(stats.low, 0);
        assert_eq!(stats.info, 1);
        let table = table(&issues, Severity::High);
        assert!(table.contains("Reflected XSS"));
        assert!(!table.contains("Missing CSP"));
    }

    #[test]
    fn html_is_escaped() {
        let issues = vec![
            Issue::builder("x", "<script>alert(1)</script>", Severity::High)
                .url("http://example.com/?q=<x>")
                .build(),
        ];
        let page = html(&issues, &ReportOptions::default(), "test");
        assert!(page.contains("&lt;script&gt;"));
        assert!(!page.contains("<script>alert(1)</script>"));
        assert!(page.contains("&lt;x&gt;"));
    }

    #[test]
    fn json_and_sarif_are_valid() {
        let issues = sample();
        let json = json(&issues, &ReportOptions::default(), "test").unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["summary"]["high"], 1);
        let sarif = sarif(&issues, &ReportOptions::default()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        assert_eq!(value["version"], "2.1.0");
        assert_eq!(value["runs"][0]["results"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn burp_xml_escapes_and_cdata() {
        let request =
            crate::http::Request::parse(b"GET /?a=]]> HTTP/1.1\r\nHost: example.com\r\n\r\n")
                .unwrap();
        let issues = vec![Issue::builder("xss", "XSS & friends", Severity::High)
            .url("http://example.com/?a=]]>")
            .request(&request, true)
            .build()];
        let xml = burp_xml(&issues, &ReportOptions::default());
        assert!(xml.contains("XSS &amp; friends"));
        assert!(xml.contains("]]]]><![CDATA[>"));
        assert!(xml.contains("<severity>High</severity>"));
    }

    #[test]
    fn formats_parse() {
        assert_eq!(ReportFormat::parse("burp").unwrap(), ReportFormat::BurpXml);
        assert_eq!(ReportFormat::parse("md").unwrap(), ReportFormat::Markdown);
        assert!(ReportFormat::parse("nope").is_err());
        assert_eq!(
            ReportFormat::from_path(Path::new("x.html")),
            ReportFormat::Html
        );
    }
}
