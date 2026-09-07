use anyhow::Result;
use chrono::{Local, Utc};
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};

pub fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub fn now_stamp() -> String {
    Local::now().format("%Y%m%d_%H%M%S").to_string()
}

pub fn ensure_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    Ok(())
}

pub fn case_db_path(case_dir: &Path) -> PathBuf {
    case_dir.join("warden11.db")
}

pub fn reports_dir(case_dir: &Path) -> PathBuf {
    case_dir.join("reports")
}

pub fn scope_path(case_dir: &Path) -> PathBuf {
    case_dir.join("scope.json")
}

pub fn exports_dir(case_dir: &Path) -> PathBuf {
    case_dir.join("exports")
}

pub fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn mask_secret(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() <= 8 {
        return "********".to_string();
    }
    let start = &trimmed[..4.min(trimmed.len())];
    let end = &trimmed[trimmed.len().saturating_sub(4)..];
    format!("{}...{}", start, end)
}

pub fn clean_line(line: &str, max_len: usize) -> String {
    let mut s = line.replace('\t', " ").replace('\r', " ").replace('\n', " ");
    if s.len() > max_len {
        s.truncate(max_len);
        s.push_str("...");
    }
    s
}

/// Builds a display-safe context line for a secret match: the surrounding
/// line with the matched secret substring itself replaced by its masked
/// form. `clean_line` alone only strips whitespace and truncates -- it
/// still contains the full, unredacted secret, which defeats masking the
/// moment `context` is rendered next to `masked_value` in a report or
/// stored in the case database. Masking must happen on the exact matched
/// span, not the whole line, so surrounding context (variable name,
/// structure) stays useful for triage.
pub fn clean_line_masked(line: &str, matched: &str, max_len: usize) -> String {
    let redacted = if matched.is_empty() {
        line.to_string()
    } else {
        line.replacen(matched, &mask_secret(matched), 1)
    };
    clean_line(&redacted, max_len)
}

pub fn write_default_rules(output: &Path) -> Result<()> {
    let text = r#"# WARDEN-11 rules
# Defensive triage rules for authorized cyber patrol.
#
# Keep this file human-readable.

WEB_COMMON_PATHS = /robots.txt, /sitemap.xml, /.well-known/security.txt, /security.txt, /.env, /.git/config, /backup.zip, /config.json, /phpinfo.php
SECRET_FILE_EXTENSIONS = env, json, yaml, yml, toml, ini, conf, config, txt, md, py, js, ts, php, java, kt, rs, go, cs
MAX_FILE_MB = 8
WEB_TIMEOUT_SECONDS = 10
WEB_RATE_LIMIT_MS = 650
"#;
    fs::write(output, text)?;
    println!("rules written: {}", output.display());
    Ok(())
}

pub fn regexes() -> Vec<(&'static str, Regex)> {
    vec![
        ("generic_api_key", Regex::new(r#"(?i)(api[_-]?key|apikey|secret|token)\s*[:=]\s*['"]?([a-z0-9_\-]{20,})"#).unwrap()),
        ("bearer_token", Regex::new(r#"(?i)bearer\s+([a-z0-9_\-\.=]{20,})"#).unwrap()),
        ("aws_access_key", Regex::new(r#"AKIA[0-9A-Z]{16}"#).unwrap()),
        ("private_key", Regex::new(r#"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"#).unwrap()),
        ("slack_token", Regex::new(r#"xox[baprs]-[A-Za-z0-9\-]{10,}"#).unwrap()),
        ("discord_webhook", Regex::new(r#"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+"#).unwrap()),
        ("github_token", Regex::new(r#"gh[pousr]_[A-Za-z0-9_]{30,}"#).unwrap()),
        ("password_assignment", Regex::new(r#"(?i)(password|passwd|pwd)\s*[:=]\s*['"]?([^'"\s]{6,})"#).unwrap()),
    ]
}
