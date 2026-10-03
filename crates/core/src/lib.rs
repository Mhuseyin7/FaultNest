//! Local-first, inspectable failure capture and replay primitives.
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process::{Child, Command},
    thread,
    time::{Duration, Instant},
};
use thiserror::Error;
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SCHEMA: u32 = 1;
#[derive(Error, Debug)]
pub enum Error {
    #[error("configuration: {0}")]
    Config(String),
    #[error("unsafe bundle: {0}")]
    Unsafe(String),
    #[error("bundle: {0}")]
    Bundle(String),
    #[error("replay: {0}")]
    Replay(String),
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub application: Application,
    #[serde(default)]
    pub capture: Capture,
    #[serde(default)]
    pub environment: Environment,
    #[serde(default)]
    pub redaction: Redaction,
    pub replay: Replay,
}
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Application {
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
}
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    #[serde(default)]
    pub repository: bool,
    #[serde(default)]
    pub include_patch: bool,
    #[serde(default)]
    pub logs: Vec<LogSpec>,
    #[serde(default)]
    pub commands: Vec<CommandSpec>,
    #[serde(default)]
    pub docker: DockerCapture,
}
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct LogSpec {
    pub path: String,
    #[serde(default = "default_tail")]
    pub tail_lines: usize,
    #[serde(default)]
    pub tail_bytes: Option<usize>,
}
fn default_tail() -> usize {
    5000
}
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct CommandSpec {
    pub name: String,
    pub executable: String,
    #[serde(default)]
    pub args: Vec<String>,
}
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct DockerCapture {
    #[serde(default)]
    pub enabled: bool,
}
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    #[serde(default)]
    pub allow_names: Vec<String>,
}
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Redaction {
    #[serde(default = "yes")]
    pub emails: bool,
    #[serde(default = "yes")]
    pub ip_addresses: bool,
    #[serde(default = "yes")]
    pub paths: bool,
}
fn yes() -> bool {
    true
}
impl Default for Redaction {
    fn default() -> Self {
        Self {
            emails: true,
            ip_addresses: true,
            paths: true,
        }
    }
}
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Replay {
    pub command: CommandSpec,
    #[serde(default)]
    pub network: Network,
    #[serde(default = "timeout")]
    pub timeout_seconds: u64,
    #[serde(default)]
    pub container: Option<ContainerPolicy>,
}
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ContainerPolicy {
    pub image: String,
    #[serde(default = "default_cpus")]
    pub cpus: String,
    #[serde(default = "default_memory")]
    pub memory: String,
    #[serde(default = "default_pids")]
    pub pids_limit: u32,
}
fn default_cpus() -> String {
    "2".into()
}
fn default_memory() -> String {
    "1g".into()
}
fn default_pids() -> u32 {
    256
}
fn timeout() -> u64 {
    300
}
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum Network {
    #[default]
    Off,
    Dependencies,
    Allowlist,
    Full,
}
pub fn load_config(path: &Path) -> Result<Config> {
    let s = fs::read_to_string(path).map_err(|e| Error::Config(e.to_string()))?;
    let c: Config = serde_yaml::from_str(&s).map_err(|e| Error::Config(e.to_string()))?;
    if c.version != 1 {
        return Err(Error::Config(
            "only configuration version 1 is supported".into(),
        ));
    };
    if c.application.name.trim().is_empty() {
        return Err(Error::Config("application.name cannot be empty".into()));
    };
    Ok(c)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Manifest {
    pub schema_version: u32,
    pub faultnest_version: String,
    pub created_at: DateTime<Utc>,
    pub application: Application,
    pub git: Option<Git>,
    pub platform: String,
    pub architecture: String,
    pub runtime_versions: BTreeMap<String, String>,
    pub capture_modules: Vec<String>,
    pub required_replay_capabilities: Vec<String>,
    pub redaction_summary: BTreeMap<String, u64>,
    pub replay: Replay,
    pub entries: BTreeMap<String, String>,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Git {
    pub commit: String,
    pub branch: String,
    pub dirty: bool,
    pub changed: Vec<String>,
    pub remote: Option<String>,
}
#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct RedactionReport {
    #[serde(flatten)]
    pub counts: BTreeMap<String, u64>,
}
pub struct Sanitizer {
    cfg: Redaction,
    maps: HashMap<String, String>,
    report: RedactionReport,
}
impl Sanitizer {
    pub fn new(cfg: Redaction) -> Self {
        Self {
            cfg,
            maps: HashMap::new(),
            report: Default::default(),
        }
    }
    fn redact(&mut self, value: &str, kind: &str) -> String {
        let n = self.maps.len() + 1;
        let p = self
            .maps
            .entry(format!("{kind}:{value}"))
            .or_insert_with(|| format!("<{kind}_{n}>"));
        *self.report.counts.entry(kind.to_lowercase()).or_default() += 1;
        p.clone()
    }
    pub fn sanitize(&mut self, input: &str) -> String {
        let mut out = input.to_string();
        let patterns = [
            (
                "PRIVATE_KEY",
                r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\\s\\S]*?-----END [A-Z ]*PRIVATE KEY-----",
            ),
            (
                "JWT",
                r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b",
            ),
            ("GITHUB_TOKEN", r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
            ("AWS_KEY", r"\bAKIA[0-9A-Z]{16}\b"),
            ("BEARER_TOKEN", r"(?i)(Bearer\s+)[A-Za-z0-9._~+/-]{12,}"),
            ("DATABASE_URL", r"(?i)([a-z]+://[^\s:/]+:)[^@\s]+@"),
        ];
        for (kind, pat) in patterns {
            let re = Regex::new(pat).unwrap();
            let owned = out.clone();
            out = re
                .replace_all(&owned, |c: &regex::Captures| {
                    if kind == "BEARER_TOKEN" {
                        format!("{}{}", &c[1], self.redact(&c[0], kind))
                    } else if kind == "DATABASE_URL" {
                        format!("{}{}@", &c[1], self.redact(&c[0], kind))
                    } else {
                        self.redact(&c[0], kind)
                    }
                })
                .into_owned();
        }
        let header =
            Regex::new(r"(?im)^((?:authorization|cookie|x-api-key)\s*[:=]\s*)[^\r\n]+").unwrap();
        let owned = out.clone();
        out = header
            .replace_all(&owned, |c: &regex::Captures| {
                format!("{}{}", &c[1], self.redact(&c[0], "SECRET_HEADER"))
            })
            .into_owned();
        if self.cfg.emails {
            let re = Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap();
            let owned = out.clone();
            out = re
                .replace_all(&owned, |c: &regex::Captures| self.redact(&c[0], "EMAIL"))
                .into_owned();
        }
        if self.cfg.ip_addresses {
            let re = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();
            let owned = out.clone();
            out = re
                .replace_all(&owned, |c: &regex::Captures| self.redact(&c[0], "IP"))
                .into_owned();
        }
        out
    }
    pub fn report(&self) -> &RedactionReport {
        &self.report
    }
}

fn run(args: &[&str], cwd: &Path) -> Option<String> {
    let o = Command::new(args[0])
        .args(&args[1..])
        .current_dir(cwd)
        .output()
        .ok()?;
    if o.status.success() {
        Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
    } else {
        None
    }
}
fn git_info(root: &Path) -> Option<Git> {
    let commit = run(&["git", "rev-parse", "HEAD"], root)?;
    let branch =
        run(&["git", "branch", "--show-current"], root).unwrap_or_else(|| "DETACHED".into());
    let status = run(&["git", "status", "--porcelain"], root).unwrap_or_default();
    let changed = status
        .lines()
        .map(|l| l.get(3..).unwrap_or("").to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let remote = run(&["git", "remote", "get-url", "origin"], root).map(|u| {
        Regex::new(r"//[^/@]+@")
            .unwrap()
            .replace(&u, "//")
            .to_string()
    });
    Some(Git {
        commit,
        branch,
        dirty: !status.is_empty(),
        changed,
        remote,
    })
}
fn runtime_versions(root: &Path, specs: &[CommandSpec]) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for s in specs {
        if let Ok(o) = Command::new(&s.executable)
            .args(&s.args)
            .current_dir(root)
            .output()
            && o.status.success()
        {
            m.insert(
                s.name.clone(),
                String::from_utf8_lossy(&o.stdout).trim().to_string(),
            );
        }
    }
    m
}
fn tail(path: &Path, spec: &LogSpec) -> std::io::Result<String> {
    let bytes = fs::read(path)?;
    let v = if let Some(n) = spec.tail_bytes {
        bytes[bytes.len().saturating_sub(n)..].to_vec()
    } else {
        let s = String::from_utf8_lossy(&bytes);
        s.lines()
            .rev()
            .take(spec.tail_lines)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes()
    };
    Ok(String::from_utf8_lossy(&v).to_string())
}
pub fn dependency_files(root: &Path) -> Vec<PathBuf> {
    [
        "package.json",
        "pnpm-lock.yaml",
        "package-lock.json",
        "yarn.lock",
        "bun.lock",
        "pyproject.toml",
        "requirements.txt",
        "poetry.lock",
        "uv.lock",
        "composer.json",
        "composer.lock",
        "Cargo.toml",
        "Cargo.lock",
        "go.mod",
        "go.sum",
    ]
    .iter()
    .map(|x| root.join(x))
    .filter(|x| x.is_file())
    .collect()
}
fn safe_name(p: &str) -> Result<()> {
    let path = Path::new(p);
    if p.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
    {
        Err(Error::Unsafe(format!("unsafe archive path {p}")))
    } else {
        Ok(())
    }
}
pub fn capture(
    root: &Path,
    cfg: &Config,
    output: &Path,
    request: Option<&Path>,
) -> Result<Manifest> {
    let mut sz = Sanitizer::new(cfg.redaction.clone());
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for p in dependency_files(root) {
        let name = format!("repository/{}", p.file_name().unwrap().to_string_lossy());
        files.insert(
            name,
            sz.sanitize(&fs::read_to_string(p).map_err(|e| Error::Bundle(e.to_string()))?)
                .into_bytes(),
        );
    }
    for spec in &cfg.capture.logs {
        let p = root.join(&spec.path);
        if p.is_file() {
            let name = format!("logs/{}", p.file_name().unwrap().to_string_lossy());
            files.insert(
                name,
                sz.sanitize(&tail(&p, spec).map_err(|e| Error::Bundle(e.to_string()))?)
                    .into_bytes(),
            );
        }
    }
    if let Some(p) = request {
        files.insert(
            "requests/failure.json".into(),
            sz.sanitize(&fs::read_to_string(p).map_err(|e| Error::Bundle(e.to_string()))?)
                .into_bytes(),
        );
    }
    let git = if cfg.capture.repository {
        git_info(root)
    } else {
        None
    };
    if cfg.capture.include_patch
        && let Some(p) = run(&["git", "diff", "--no-ext-diff"], root)
    {
        files.insert(
            "repository/dirty.patch".into(),
            sz.sanitize(&p).into_bytes(),
        );
    }
    let env: Vec<String> = cfg
        .environment
        .allow_names
        .iter()
        .filter_map(|n| std::env::var(n).ok().map(|_| n.clone()))
        .collect();
    files.insert(
        "environment/names.json".into(),
        serde_json::to_vec_pretty(&env).unwrap(),
    );
    let mut entries = BTreeMap::new();
    for (n, b) in &files {
        entries.insert(n.clone(), blake3::hash(b).to_hex().to_string());
    }
    let manifest = Manifest {
        schema_version: SCHEMA,
        faultnest_version: VERSION.into(),
        created_at: Utc::now(),
        application: cfg.application.clone(),
        git,
        platform: std::env::consts::OS.into(),
        architecture: std::env::consts::ARCH.into(),
        runtime_versions: runtime_versions(root, &cfg.capture.commands),
        capture_modules: vec![
            "dependencies".into(),
            "logs".into(),
            "environment-names".into(),
            "redaction".into(),
        ],
        required_replay_capabilities: vec!["local-command".into()],
        redaction_summary: sz.report().counts.clone(),
        replay: cfg.replay.clone(),
        entries,
    };
    files.insert(
        "redaction-report.json".into(),
        serde_json::to_vec_pretty(sz.report()).unwrap(),
    );
    files.insert(
        "manifest.json".into(),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    );
    let checksums: BTreeMap<String, String> = files
        .iter()
        .map(|(n, b)| (n.clone(), blake3::hash(b).to_hex().to_string()))
        .collect();
    files.insert(
        "checksums.json".into(),
        serde_json::to_vec_pretty(&checksums).unwrap(),
    );
    write_bundle(output, &files)?;
    Ok(manifest)
}
fn write_bundle(out: &Path, files: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    let f = fs::File::create(out).map_err(|e| Error::Bundle(e.to_string()))?;
    let mut z = ZipWriter::new(f);
    for (n, b) in files {
        safe_name(n)?;
        z.start_file(
            n,
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Zstd),
        )
        .map_err(|e| Error::Bundle(e.to_string()))?;
        z.write_all(b).map_err(|e| Error::Bundle(e.to_string()))?;
    }
    z.finish().map_err(|e| Error::Bundle(e.to_string()))?;
    Ok(())
}
pub fn verify(bundle: &Path) -> Result<Manifest> {
    let f = fs::File::open(bundle).map_err(|e| Error::Bundle(e.to_string()))?;
    let mut z = ZipArchive::new(f).map_err(|e| Error::Bundle(e.to_string()))?;
    if z.len() > 10_000 {
        return Err(Error::Unsafe("too many entries".into()));
    }
    let mut all = BTreeMap::new();
    for i in 0..z.len() {
        let mut e = z.by_index(i).map_err(|e| Error::Bundle(e.to_string()))?;
        safe_name(e.name())?;
        if e.is_dir() {
            continue;
        }
        if e.size() > 100 * 1024 * 1024 {
            return Err(Error::Unsafe(format!("entry too large: {}", e.name())));
        }
        let mut b = Vec::new();
        e.read_to_end(&mut b)
            .map_err(|e| Error::Bundle(e.to_string()))?;
        all.insert(e.name().to_string(), b);
    }
    let m: Manifest = serde_json::from_slice(
        all.get("manifest.json")
            .ok_or_else(|| Error::Bundle("manifest missing".into()))?,
    )
    .map_err(|e| Error::Bundle(e.to_string()))?;
    if m.schema_version != SCHEMA {
        return Err(Error::Bundle("unsupported schema".into()));
    }
    let c: BTreeMap<String, String> = serde_json::from_slice(
        all.get("checksums.json")
            .ok_or_else(|| Error::Bundle("checksums missing".into()))?,
    )
    .map_err(|e| Error::Bundle(e.to_string()))?;
    for (n, h) in c {
        let b = all
            .get(&n)
            .ok_or_else(|| Error::Bundle(format!("missing {n}")))?;
        if blake3::hash(b).to_hex().as_str() != h {
            return Err(Error::Bundle(format!("checksum mismatch: {n}")));
        }
    }
    Ok(m)
}
pub fn inspect(bundle: &Path) -> Result<Manifest> {
    verify(bundle)
}
pub fn extract(bundle: &Path, dest: &Path) -> Result<Manifest> {
    let m = verify(bundle)?;
    let f = fs::File::open(bundle).map_err(|e| Error::Bundle(e.to_string()))?;
    let mut z = ZipArchive::new(f).map_err(|e| Error::Bundle(e.to_string()))?;
    for i in 0..z.len() {
        let mut e = z.by_index(i).map_err(|e| Error::Bundle(e.to_string()))?;
        safe_name(e.name())?;
        if e.is_dir() {
            continue;
        };
        let p = dest.join(e.name());
        if let Some(d) = p.parent() {
            fs::create_dir_all(d).map_err(|e| Error::Replay(e.to_string()))?
        };
        let mut o = fs::File::create(p).map_err(|e| Error::Replay(e.to_string()))?;
        std::io::copy(&mut e, &mut o).map_err(|e| Error::Replay(e.to_string()))?;
    }
    Ok(m)
}

/// Reconstruct source only from a credential-free HTTPS/SSH Git remote and exact commit.
/// Git hooks are disabled explicitly, and an optional captured patch is applied with `git apply`.
pub fn reconstruct_source(manifest: &Manifest, extracted: &Path) -> Result<PathBuf> {
    let Some(git) = &manifest.git else {
        return Ok(extracted.to_path_buf());
    };
    let Some(remote) = &git.remote else {
        return Ok(extracted.to_path_buf());
    };
    if !(remote.starts_with("https://")
        || remote.starts_with("ssh://")
        || remote.starts_with("git@"))
    {
        return Err(Error::Replay("source remote must use HTTPS or SSH".into()));
    }
    if remote.contains(' ') || remote.contains('\n') || remote.contains('\r') {
        return Err(Error::Replay("unsafe source remote".into()));
    }
    let source = extracted.join("source");
    let hooks = extracted.join("empty-hooks");
    fs::create_dir_all(&hooks).map_err(|e| Error::Replay(e.to_string()))?;
    let clone = Command::new("git")
        .args([
            "-c",
            &format!("core.hooksPath={}", hooks.display()),
            "clone",
            "--no-checkout",
            remote,
            source.to_string_lossy().as_ref(),
        ])
        .current_dir(extracted)
        .status()
        .map_err(|e| Error::Replay(format!("git unavailable: {e}")))?;
    if !clone.success() {
        return Err(Error::Replay("source clone failed".into()));
    }
    let checkout = Command::new("git")
        .args([
            "-c",
            &format!("core.hooksPath={}", hooks.display()),
            "checkout",
            "--detach",
            &git.commit,
        ])
        .current_dir(&source)
        .status()
        .map_err(|e| Error::Replay(e.to_string()))?;
    if !checkout.success() {
        return Err(Error::Replay("exact captured commit is unavailable".into()));
    }
    let patch = extracted.join("repository/dirty.patch");
    if patch.is_file() {
        let applied = Command::new("git")
            .args([
                "apply",
                "--whitespace=error",
                patch.to_string_lossy().as_ref(),
            ])
            .current_dir(&source)
            .status()
            .map_err(|e| Error::Replay(e.to_string()))?;
        if !applied.success() {
            return Err(Error::Replay("captured patch did not apply".into()));
        }
    }
    Ok(source)
}

/// Execute a trigger in a constrained Docker container. Docker is controlled only from the host;
/// no Docker socket, privileged mode, or host mounts beyond a read-only workspace are exposed.
pub fn container_replay(
    policy: &ContainerPolicy,
    network: &Network,
    workspace: &Path,
    trigger: &CommandSpec,
    timeout_seconds: u64,
) -> Result<bool> {
    if policy.image.trim().is_empty() {
        return Err(Error::Replay("container image is empty".into()));
    }
    let mut c = Command::new("docker");
    c.args([
        "run",
        "--rm",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        &policy.pids_limit.to_string(),
        "--cpus",
        &policy.cpus,
        "--memory",
        &policy.memory,
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "-v",
    ]);
    c.arg(format!("{}:/workspace:ro", workspace.display()));
    c.args(["-w", "/workspace"]);
    match network {
        Network::Off => {
            c.args(["--network", "none"]);
        }
        Network::Full => {}
        Network::Dependencies | Network::Allowlist => {
            return Err(Error::Replay(
                "DEPENDENCIES and ALLOWLIST require a runtime-specific network adapter".into(),
            ));
        }
    }
    c.arg(&policy.image)
        .arg(&trigger.executable)
        .args(&trigger.args);
    let child = c
        .spawn()
        .map_err(|e| Error::Replay(format!("Docker trigger could not start: {e}")))?;
    Ok(!wait_with_timeout(child, timeout_seconds)?)
}

/// Runs a process without a shell and terminates it once its configured deadline expires.
/// `true` is a failing trigger; timeout is surfaced separately so it cannot be reported as reproduction.
pub fn run_trigger(command: &CommandSpec, cwd: &Path, timeout_seconds: u64) -> Result<bool> {
    let child = Command::new(&command.executable)
        .args(&command.args)
        .current_dir(cwd)
        .spawn()
        .map_err(|e| Error::Replay(format!("trigger could not start: {e}")))?;
    Ok(!wait_with_timeout(child, timeout_seconds)?)
}

fn wait_with_timeout(mut child: Child, timeout_seconds: u64) -> Result<bool> {
    let deadline = Instant::now() + Duration::from_secs(timeout_seconds.max(1));
    loop {
        if let Some(status) = child.try_wait().map_err(|e| Error::Replay(e.to_string()))? {
            return Ok(status.success());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::Replay("trigger timed out".into()));
        }
        thread::sleep(Duration::from_millis(25));
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secret_never_survives() {
        let mut s = Sanitizer::new(Default::default());
        let o=s.sanitize("Authorization: Bearer abcdefghijklmnopqrst\na@b.com 10.1.2.3 ghp_123456789012345678901234567890");
        assert!(!o.contains("abcdefghijkl"));
        assert!(!o.contains("a@b.com"));
        assert!(!o.contains("10.1.2.3"));
    }
    #[test]
    fn traversal_is_rejected() {
        assert!(safe_name("../bad").is_err());
    }
    #[test]
    fn capture_never_persists_known_secret() {
        let d = tempfile::tempdir().unwrap();
        fs::write(
            d.path().join("app.log"),
            "Bearer abcdefghijklmnopqrst a@b.com 10.0.0.1",
        )
        .unwrap();
        fs::write(
            d.path().join("request.json"),
            "Authorization: Bearer abcdefghijklmnopqrst",
        )
        .unwrap();
        let config = Config {
            version: 1,
            application: Application {
                name: "test".into(),
                version: None,
            },
            capture: Capture {
                logs: vec![LogSpec {
                    path: "app.log".into(),
                    tail_lines: 10,
                    tail_bytes: None,
                }],
                ..Default::default()
            },
            environment: Environment::default(),
            redaction: Redaction::default(),
            replay: Replay {
                command: CommandSpec {
                    name: "test".into(),
                    executable: "echo".into(),
                    args: vec![],
                },
                network: Network::Off,
                timeout_seconds: 1,
                container: None,
            },
        };
        let bundle = d.path().join("test.faultnest");
        capture(
            d.path(),
            &config,
            &bundle,
            Some(&d.path().join("request.json")),
        )
        .unwrap();
        let out = d.path().join("out");
        extract(&bundle, &out).unwrap();
        let mut combined = String::new();
        for e in walkdir::WalkDir::new(&out)
            .into_iter()
            .flatten()
            .filter(|e| e.file_type().is_file())
        {
            combined.push_str(&fs::read_to_string(e.path()).unwrap_or_default());
        }
        assert!(!combined.contains("abcdefghijklmnopqrst"));
        assert!(!combined.contains("a@b.com"));
        assert!(!combined.contains("10.0.0.1"));
    }
}
