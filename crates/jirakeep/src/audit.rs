//! Operator-only JSONL audit stream (I15).
//!
//! Never exposed through MCP. Records carry guard verdicts and suppressed
//! issue keys; never API tokens, emails, or free-text issue content.

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    Open,
    ClosedWritesDenials,
    ClosedAll,
}

impl FailMode {
    pub fn resolve(configured: Option<FailMode>, transport_http: bool) -> Self {
        configured.unwrap_or(if transport_http {
            FailMode::ClosedAll
        } else {
            FailMode::Open
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    pub path: PathBuf,
    #[serde(default)]
    pub fsync: bool,
    #[serde(default)]
    pub fail_mode: Option<FailMode>,
    #[serde(default = "default_rotate_max")]
    pub rotate_max_bytes: u64,
    #[serde(default = "default_rotate_keep")]
    pub rotate_keep: u32,
    #[serde(default = "default_true")]
    pub suppressed_ids: bool,
}

fn default_rotate_max() -> u64 {
    64 * 1024 * 1024
}
fn default_rotate_keep() -> u32 {
    8
}
fn default_true() -> bool {
    true
}

impl AuditConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let s = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read audit config {}", path.display()))?;
        let cfg: Self = toml::from_str(&s).context("invalid audit configuration TOML")?;
        if cfg.rotate_max_bytes > 0 && cfg.rotate_keep == 0 {
            anyhow::bail!("rotate_keep must be >= 1 when rotation is enabled");
        }
        Ok(cfg)
    }
}

pub fn policy_hash_of(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    // Hex-encode manually: sha2 0.11's digest type no longer implements LowerHex.
    let digest = Sha256::digest(bytes);
    let mut hash = String::with_capacity("sha256:".len() + digest.len() * 2);
    hash.push_str("sha256:");
    for byte in &digest {
        let _ = write!(hash, "{byte:02x}");
    }
    hash
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub v: u32,
    pub seq: u64,
    pub ts: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppressed_keys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppressed_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Served,
    Denied,
    Refused,
    Filtered,
}

impl Verdict {
    fn as_str(self) -> &'static str {
        match self {
            Verdict::Served => "served",
            Verdict::Denied => "denied",
            Verdict::Refused => "refused",
            Verdict::Filtered => "filtered",
        }
    }
}

/// Per-request enrichment cell (optional).
#[derive(Debug, Default)]
pub struct AuditCell {
    verdict: Mutex<Option<Verdict>>,
    rule: Mutex<Option<String>>,
    suppressed: Mutex<Vec<String>>,
    suppressed_count: Mutex<Option<u64>>,
}

impl AuditCell {
    pub fn note_verdict(&self, v: Verdict) {
        *self.verdict.lock().unwrap_or_else(|e| e.into_inner()) = Some(v);
    }
    pub fn note_verdict_rule(&self, v: Verdict, rule: &str) {
        self.note_verdict(v);
        *self.rule.lock().unwrap_or_else(|e| e.into_inner()) = Some(rule.to_owned());
    }
    pub fn note_suppressed(&self, keys: Vec<String>) {
        self.suppressed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend(keys);
    }
    pub fn note_suppressed_count(&self, n: u64) {
        *self
            .suppressed_count
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(n);
    }
    pub fn snapshot(&self) -> (Option<Verdict>, Option<String>, Vec<String>, Option<u64>) {
        (
            *self.verdict.lock().unwrap_or_else(|e| e.into_inner()),
            self.rule.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            self.suppressed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            *self
                .suppressed_count
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        )
    }
}

pub struct AuditSink {
    file: Mutex<File>,
    path: PathBuf,
    fsync: bool,
    rotate_max_bytes: u64,
    rotate_keep: u32,
    bytes: AtomicU64,
    seq: AtomicU64,
    failing: Mutex<bool>,
}

impl AuditSink {
    pub fn open(cfg: AuditConfig) -> anyhow::Result<Self> {
        if let Some(parent) = cfg.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create audit dir {}", parent.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&cfg.path)
            .with_context(|| format!("open audit file {}", cfg.path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(&cfg.path, std::fs::Permissions::from_mode(0o600));
        }
        let bytes = std::fs::metadata(&cfg.path).map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            file: Mutex::new(file),
            path: cfg.path,
            fsync: cfg.fsync,
            rotate_max_bytes: cfg.rotate_max_bytes,
            rotate_keep: cfg.rotate_keep,
            bytes: AtomicU64::new(bytes),
            seq: AtomicU64::new(0),
            failing: Mutex::new(false),
        })
    }

    pub fn record(&self, mut event: AuditEvent) -> anyhow::Result<()> {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        event.seq = seq;
        if event.ts.is_empty() {
            event.ts = now_rfc3339();
        }
        event.v = SCHEMA_VERSION;
        let line = serde_json::to_string(&event).context("serialize audit event")?;
        let mut file = self.file.lock().unwrap_or_else(|e| e.into_inner());
        if self.rotate_max_bytes > 0 {
            let cur = self.bytes.load(Ordering::Relaxed);
            if cur + line.len() as u64 + 1 > self.rotate_max_bytes {
                self.rotate(&mut file)?;
            }
        }
        writeln!(file, "{line}").context("write audit record")?;
        if self.fsync {
            file.sync_data().context("fsync audit record")?;
        }
        self.bytes
            .fetch_add(line.len() as u64 + 1, Ordering::Relaxed);
        *self.failing.lock().unwrap_or_else(|e| e.into_inner()) = false;
        Ok(())
    }

    fn rotate(&self, file: &mut File) -> anyhow::Result<()> {
        // Best-effort size rotation: path -> path.1 ... path.N
        drop(std::mem::replace(
            file,
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?,
        ));
        for i in (1..self.rotate_keep).rev() {
            let from = PathBuf::from(format!("{}.{}", self.path.display(), i));
            let to = PathBuf::from(format!("{}.{}", self.path.display(), i + 1));
            let _ = std::fs::rename(&from, &to);
        }
        let rotated = PathBuf::from(format!("{}.1", self.path.display()));
        let _ = std::fs::rename(&self.path, &rotated);
        *file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .context("reopen audit file after rotation")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
        }
        self.bytes.store(0, Ordering::Relaxed);
        Ok(())
    }

    pub fn mark_failing(&self) {
        *self.failing.lock().unwrap_or_else(|e| e.into_inner()) = true;
    }

    pub fn is_failing(&self) -> bool {
        *self.failing.lock().unwrap_or_else(|e| e.into_inner())
    }
}

pub struct AuditState {
    pub sink: AuditSink,
    pub fail_mode: FailMode,
    pub policy_hash: Option<String>,
    pub suppressed_ids: bool,
    pub transport: String,
    pub stdio_session_id: String,
}

impl AuditState {
    pub fn new(
        sink: AuditSink,
        fail_mode: FailMode,
        policy_hash: Option<String>,
        suppressed_ids: bool,
        transport: &str,
    ) -> Arc<Self> {
        Arc::new(Self {
            sink,
            fail_mode,
            policy_hash,
            suppressed_ids,
            transport: transport.to_owned(),
            stdio_session_id: format!("stdio-{}", now_rfc3339()),
        })
    }

    pub fn record_tool(
        &self,
        tool: &str,
        cell: &AuditCell,
        duration_ms: u64,
        error: Option<String>,
    ) -> anyhow::Result<()> {
        let (verdict, rule, suppressed, count) = cell.snapshot();
        let suppressed_count =
            count.or_else(|| (!suppressed.is_empty()).then_some(suppressed.len() as u64));
        let suppressed_keys = if self.suppressed_ids && !suppressed.is_empty() {
            Some(suppressed)
        } else {
            None
        };
        let event = AuditEvent {
            v: SCHEMA_VERSION,
            seq: 0,
            ts: String::new(),
            kind: "tool_call".into(),
            tool: Some(tool.to_owned()),
            verdict: verdict.map(|v| v.as_str().to_owned()),
            rule,
            suppressed_keys,
            suppressed_count,
            policy_hash: self.policy_hash.clone(),
            transport: Some(self.transport.clone()),
            duration_ms: Some(duration_ms),
            error,
        };
        match self.sink.record(event) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.sink.mark_failing();
                Err(e)
            }
        }
    }
}

fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Compact UTC timestamp without chrono dependency in formatting path.
    format!("{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn writes_jsonl() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let cfg = AuditConfig {
            path: path.clone(),
            fsync: false,
            fail_mode: Some(FailMode::Open),
            rotate_max_bytes: 0,
            rotate_keep: 1,
            suppressed_ids: true,
        };
        let sink = AuditSink::open(cfg).unwrap();
        sink.record(AuditEvent {
            v: 1,
            seq: 0,
            ts: String::new(),
            kind: "tool_call".into(),
            tool: Some("mcp_server_info".into()),
            verdict: Some("served".into()),
            rule: None,
            suppressed_keys: None,
            suppressed_count: None,
            policy_hash: None,
            transport: Some("stdio".into()),
            duration_ms: Some(1),
            error: None,
        })
        .unwrap();
        let text = std::fs::read_to_string(path).unwrap();
        assert!(text.contains("mcp_server_info"));
        assert!(text.contains("\"v\":1"));
    }
}
