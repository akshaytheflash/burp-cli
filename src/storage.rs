//! Project storage: configuration, proxy history and file locking.
//!
//! History is stored as newline-delimited JSON. Raw HTTP messages are base64
//! encoded so that binary bodies survive a round-trip. This keeps projects
//! portable and inspectable without a database dependency.

use crate::config::{self, ProjectConfig};
use crate::http::{Request, Response};
use crate::util::{b64_decode, now_rfc3339};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

pub const PROJECT_FILE: &str = "project.toml";
pub const HISTORY_FILE: &str = "history.jsonl";
pub const ISSUES_FILE: &str = "issues.jsonl";
pub const SITEMAP_FILE: &str = "sitemap.json";
pub const SESSION_FILE: &str = "session.json";

#[derive(Clone, Debug)]
pub struct Project {
    pub root: PathBuf,
    pub config: ProjectConfig,
}

impl Project {
    pub fn create(root: &Path, name: &str) -> Result<Self> {
        std::fs::create_dir_all(root)
            .with_context(|| format!("cannot create project directory '{}'", root.display()))?;
        let project = Project {
            root: root.to_path_buf(),
            config: ProjectConfig {
                name: name.to_string(),
                ..ProjectConfig::default()
            },
        };
        project.save_config()?;
        project.ensure_dirs()?;
        Ok(project)
    }

    pub fn open(root: &Path) -> Result<Self> {
        let config_path = root.join(PROJECT_FILE);
        if !config_path.exists() {
            bail!(
                "no project found at '{}' (run `burpcli project create {}`)",
                root.display(),
                root.display()
            );
        }
        let text = std::fs::read_to_string(&config_path)
            .with_context(|| format!("cannot read '{}'", config_path.display()))?;
        let config: ProjectConfig = toml::from_str(&text)
            .with_context(|| format!("cannot parse project config '{}'", config_path.display()))?;
        let project = Project {
            root: root.to_path_buf(),
            config,
        };
        project.ensure_dirs()?;
        Ok(project)
    }

    pub fn open_or_init(root: &Path) -> Result<Self> {
        if root.join(PROJECT_FILE).exists() {
            Self::open(root)
        } else {
            let name = root
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("default")
                .trim_start_matches('.')
                .to_string();
            let name = if name.is_empty() {
                "default".into()
            } else {
                name
            };
            Self::create(root, &name)
        }
    }

    /// Resolve the project to use: explicit path, `BURPCLI_PROJECT`, the
    /// globally selected project, or `./.burpcli`.
    pub fn resolve(explicit: Option<PathBuf>, allow_create: bool) -> Result<Self> {
        let root = if let Some(path) = explicit {
            path
        } else if let Some(path) = std::env::var_os("BURPCLI_PROJECT") {
            PathBuf::from(path)
        } else {
            let global = config::load_global().unwrap_or_default();
            if let Some(path) = global.current_project {
                PathBuf::from(path)
            } else {
                std::env::current_dir()?.join(".burpcli")
            }
        };
        if allow_create {
            Self::open_or_init(&root)
        } else {
            Self::open(&root)
        }
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        for dir in [
            self.plugins_dir(),
            self.root.join("ca"),
            self.root.join("reports"),
            self.root.join("wordlists"),
        ] {
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("cannot create directory '{}'", dir.display()))?;
        }
        Ok(())
    }

    pub fn save_config(&self) -> Result<()> {
        let text = toml::to_string_pretty(&self.config)?;
        config::atomic_write(&self.root.join(PROJECT_FILE), text.as_bytes())
    }

    pub fn history_path(&self) -> PathBuf {
        self.root.join(HISTORY_FILE)
    }

    pub fn issues_path(&self) -> PathBuf {
        self.root.join(ISSUES_FILE)
    }

    pub fn sitemap_path(&self) -> PathBuf {
        self.root.join(SITEMAP_FILE)
    }

    pub fn session_path(&self) -> PathBuf {
        self.root.join(SESSION_FILE)
    }

    pub fn plugins_dir(&self) -> PathBuf {
        self.root.join(&self.config.plugins.dir)
    }

    pub fn reports_dir(&self) -> PathBuf {
        self.root.join("reports")
    }

    pub fn ca_cert_path(&self) -> PathBuf {
        self.root.join("ca").join("burpcli-ca.pem")
    }

    pub fn ca_key_path(&self) -> PathBuf {
        self.root.join("ca").join("burpcli-ca.key")
    }

    pub fn history(&self) -> Result<HistoryStore> {
        HistoryStore::open(self.history_path())
    }

    pub fn issue_store(&self) -> Result<crate::scanner::IssueStore> {
        crate::scanner::IssueStore::open(self.issues_path())
    }

    pub fn sitemap(&self) -> Result<crate::sitemap::Sitemap> {
        crate::sitemap::Sitemap::load(self.sitemap_path())
    }
}

pub struct LockGuard {
    path: PathBuf,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub(crate) fn acquire_lock(path: &Path) -> Result<LockGuard> {
    let lock_path = path.with_extension("lock");
    for _ in 0..300 {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(mut file) => {
                let _ = writeln!(file, "{}", std::process::id());
                return Ok(LockGuard { path: lock_path });
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Break stale locks after 60 seconds.
                if let Ok(meta) = std::fs::metadata(&lock_path) {
                    if let Ok(modified) = meta.modified() {
                        if SystemTime::now()
                            .duration_since(modified)
                            .unwrap_or_default()
                            > Duration::from_secs(60)
                        {
                            let _ = std::fs::remove_file(&lock_path);
                            continue;
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("cannot create lock '{}'", lock_path.display()))
            }
        }
    }
    Err(anyhow!(
        "timed out waiting for lock '{}'",
        lock_path.display()
    ))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub id: u64,
    pub ts: String,
    pub method: String,
    pub url: String,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub status: u16,
    #[serde(default)]
    pub mime: String,
    /// Base64 of the raw request.
    pub request: String,
    /// Base64 of the raw response (absent for dropped/failed requests).
    #[serde(default)]
    pub response: Option<String>,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub note: String,
}

impl HistoryEntry {
    pub fn request(&self) -> Result<Request> {
        Request::from_b64(&self.request)
    }

    pub fn response(&self) -> Result<Option<Response>> {
        match &self.response {
            Some(data) => Ok(Some(Response::from_b64(data)?)),
            None => Ok(None),
        }
    }

    pub fn request_bytes(&self) -> Result<Vec<u8>> {
        b64_decode(&self.request)
    }

    pub fn response_bytes(&self) -> Result<Option<Vec<u8>>> {
        match &self.response {
            Some(data) => Ok(Some(b64_decode(data)?)),
            None => Ok(None),
        }
    }

    pub fn size(&self) -> usize {
        self.response
            .as_deref()
            .map(|r| r.len() * 3 / 4)
            .unwrap_or(0)
    }

    pub fn title(&self) -> String {
        format!("{} {} {}", self.id, self.method, self.url)
    }
}

#[derive(Clone, Debug, Default)]
pub struct HistoryFilter {
    pub method: Option<String>,
    pub status: Option<u16>,
    pub host: Option<String>,
    pub search: Option<String>,
    pub tags: Vec<String>,
    pub offset: usize,
    pub limit: usize,
    pub in_scope: Option<crate::scope::Scope>,
}

impl HistoryFilter {
    pub fn matches(&self, entry: &HistoryEntry) -> bool {
        if let Some(method) = &self.method {
            if !entry.method.eq_ignore_ascii_case(method) {
                return false;
            }
        }
        if let Some(status) = self.status {
            if entry.status != status {
                return false;
            }
        }
        if let Some(host) = &self.host {
            if !entry.host.eq_ignore_ascii_case(host) {
                return false;
            }
        }
        if !self.tags.is_empty() && !self.tags.iter().all(|t| entry.tags.contains(t)) {
            return false;
        }
        if let Some(scope) = &self.in_scope {
            if !scope.allows_str(&entry.url) {
                return false;
            }
        }
        if let Some(search) = &self.search {
            let needle = search.to_ascii_lowercase();
            let mut haystack = format!(
                "{} {} {} {} {}",
                entry.url, entry.method, entry.note, entry.ts, entry.status
            );
            if !haystack.to_ascii_lowercase().contains(&needle) {
                if let Ok(bytes) = entry.request_bytes() {
                    haystack.push_str(&String::from_utf8_lossy(&bytes));
                }
                if let Some(response) = entry.response.as_ref() {
                    if let Ok(bytes) = b64_decode(response) {
                        haystack.push_str(&String::from_utf8_lossy(&bytes));
                    }
                }
                if !haystack.to_ascii_lowercase().contains(&needle) {
                    return false;
                }
            }
        }
        true
    }
}

pub struct HistoryStore {
    path: PathBuf,
    next_id: AtomicU64,
    write_lock: Mutex<()>,
}

impl HistoryStore {
    pub fn open(path: PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        if !path.exists() {
            File::create(&path)
                .with_context(|| format!("cannot create history '{}'", path.display()))?;
        }
        let next_id = last_id(&path).map(|id| id + 1).unwrap_or(1);
        Ok(Self {
            path,
            next_id: AtomicU64::new(next_id),
            write_lock: Mutex::new(()),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&self, entry: &mut HistoryEntry) -> Result<u64> {
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let _file_lock = acquire_lock(&self.path)?;
        // Re-scan under the lock so that concurrent processes do not collide.
        if let Ok(last) = last_id(&self.path) {
            let current = self.next_id.load(Ordering::Relaxed);
            if current <= last {
                self.next_id.store(last + 1, Ordering::Relaxed);
            }
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        entry.id = id;
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .with_context(|| format!("cannot append to '{}'", self.path.display()))?;
        serde_json::to_writer(&mut file, entry)?;
        file.write_all(b"\n")?;
        file.flush()?;
        Ok(id)
    }

    pub fn record(
        &self,
        request: &Request,
        response: Option<&Response>,
        duration: Duration,
        tags: Vec<String>,
    ) -> Result<u64> {
        let url = request
            .url()
            .map(|u| u.to_string())
            .unwrap_or_else(|_| request.target.clone());
        let (host, port, tls) = request
            .service()
            .unwrap_or_else(|_| ("unknown".into(), 0, false));
        let status = response.map(|r| r.status).unwrap_or(0);
        let mime = response
            .and_then(|r| r.content_type())
            .map(|c| c.split(';').next().unwrap_or(c).trim().to_string())
            .unwrap_or_default();
        let mut entry = HistoryEntry {
            id: 0,
            ts: now_rfc3339(),
            method: request.method.clone(),
            url,
            host,
            port,
            tls,
            status,
            mime,
            request: request.to_b64(),
            response: response.map(|r| r.to_b64()),
            duration_ms: duration.as_millis() as u64,
            tags,
            note: String::new(),
        };
        self.append(&mut entry)
    }

    pub fn list(&self, filter: &HistoryFilter) -> Result<Vec<HistoryEntry>> {
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut out = Vec::new();
        let mut skipped = 0usize;
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: HistoryEntry = match serde_json::from_str(&line) {
                Ok(e) => e,
                Err(_) => continue,
            };
            if !filter.matches(&entry) {
                continue;
            }
            if skipped < filter.offset {
                skipped += 1;
                continue;
            }
            out.push(entry);
            if filter.limit > 0 && out.len() >= filter.limit {
                break;
            }
        }
        Ok(out)
    }

    pub fn get(&self, id: u64) -> Result<Option<HistoryEntry>> {
        let file = File::open(&self.path)?;
        for line in BufReader::new(file).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(entry) = serde_json::from_str::<HistoryEntry>(&line) {
                if entry.id == id {
                    return Ok(Some(entry));
                }
            }
        }
        Ok(None)
    }

    pub fn count(&self) -> Result<usize> {
        let file = File::open(&self.path)?;
        Ok(BufReader::new(file)
            .lines()
            .filter(|l| l.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false))
            .count())
    }

    pub fn clear(&self) -> Result<()> {
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let _file_lock = acquire_lock(&self.path)?;
        File::create(&self.path)?;
        self.next_id.store(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn delete(&self, id: u64) -> Result<bool> {
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let _file_lock = acquire_lock(&self.path)?;
        let entries = self.read_all_unlocked()?;
        let before = entries.len();
        let kept: Vec<_> = entries.into_iter().filter(|e| e.id != id).collect();
        if kept.len() == before {
            return Ok(false);
        }
        self.rewrite_unlocked(&kept)?;
        Ok(true)
    }

    pub fn update<F>(&self, id: u64, mut f: F) -> Result<bool>
    where
        F: FnMut(&mut HistoryEntry),
    {
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let _file_lock = acquire_lock(&self.path)?;
        let mut entries = self.read_all_unlocked()?;
        let mut found = false;
        for entry in &mut entries {
            if entry.id == id {
                f(entry);
                found = true;
                break;
            }
        }
        if found {
            self.rewrite_unlocked(&entries)?;
        }
        Ok(found)
    }

    pub fn add_note(&self, id: u64, note: &str) -> Result<bool> {
        self.update(id, |entry| entry.note = note.to_string())
    }

    pub fn add_tag(&self, id: u64, tag: &str) -> Result<bool> {
        self.update(id, |entry| {
            if !entry.tags.iter().any(|t| t == tag) {
                entry.tags.push(tag.to_string());
            }
        })
    }

    pub fn remove_tag(&self, id: u64, tag: &str) -> Result<bool> {
        self.update(id, |entry| entry.tags.retain(|t| t != tag))
    }

    fn read_all_unlocked(&self) -> Result<Vec<HistoryEntry>> {
        let file = File::open(&self.path)?;
        let mut entries = Vec::new();
        for line in BufReader::new(file).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(entry) = serde_json::from_str::<HistoryEntry>(&line) {
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    fn rewrite_unlocked(&self, entries: &[HistoryEntry]) -> Result<()> {
        let tmp = self.path.with_extension("jsonl.tmp");
        {
            let mut file = File::create(&tmp)?;
            for entry in entries {
                serde_json::to_writer(&mut file, entry)?;
                file.write_all(b"\n")?;
            }
            file.flush()?;
        }
        if self.path.exists() {
            std::fs::remove_file(&self.path).ok();
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

fn last_id(path: &Path) -> Result<u64> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(0);
    }
    let start = len.saturating_sub(64 * 1024);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let buf = String::from_utf8_lossy(&bytes);
    for line in buf.lines().rev() {
        if let Ok(entry) = serde_json::from_str::<HistoryEntry>(line) {
            return Ok(entry.id);
        }
    }
    // Fall back to scanning the whole file (e.g. one very long line).
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let buf = String::from_utf8_lossy(&bytes);
    for line in buf.lines().rev() {
        if let Ok(entry) = serde_json::from_str::<HistoryEntry>(line) {
            return Ok(entry.id);
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project() -> (tempfile::TempDir, Project) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("project");
        let project = Project::create(&root, "test").unwrap();
        (dir, project)
    }

    #[test]
    fn history_roundtrip() {
        let (_tmp, project) = project();
        let history = project.history().unwrap();
        let mut request = Request::parse(b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
        request.scheme = Some("http".into());
        let response =
            Response::parse(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nhi").unwrap();
        let id = history
            .record(
                &request,
                Some(&response),
                Duration::from_millis(12),
                vec!["tag".into()],
            )
            .unwrap();
        assert_eq!(id, 1);
        let entries = history.list(&HistoryFilter::default()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].status, 200);
        assert_eq!(entries[0].request().unwrap().target, "/a");
        assert_eq!(entries[0].response().unwrap().unwrap().body, b"hi");
        assert_eq!(history.count().unwrap(), 1);

        history.add_note(id, "hello").unwrap();
        assert_eq!(history.get(id).unwrap().unwrap().note, "hello");
        assert!(history.delete(id).unwrap());
        assert_eq!(history.count().unwrap(), 0);
    }

    #[test]
    fn history_filtering() {
        let (_tmp, project) = project();
        let history = project.history().unwrap();
        for (path, status) in [("/a", 200u16), ("/b", 404)] {
            let mut req = Request::parse(
                format!("GET {path} HTTP/1.1\r\nHost: example.com\r\n\r\n").as_bytes(),
            )
            .unwrap();
            req.scheme = Some("http".into());
            let resp = Response::parse(
                format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\n\r\n").as_bytes(),
            )
            .unwrap();
            history
                .record(&req, Some(&resp), Duration::from_millis(1), vec![])
                .unwrap();
        }
        let filter = HistoryFilter {
            status: Some(404),
            ..Default::default()
        };
        let entries = history.list(&filter).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].url, "http://example.com/b");
    }

    #[test]
    fn project_config_roundtrip() {
        let (_tmp, mut project) = project();
        project
            .config
            .scope
            .include
            .push("https://example.com/*".into());
        project.save_config().unwrap();
        let reopened = Project::open(&project.root).unwrap();
        assert_eq!(reopened.config.scope.include[0], "https://example.com/*");
    }
}
