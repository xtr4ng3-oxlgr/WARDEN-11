use crate::models::*;
use anyhow::Result;
use rusqlite::{params, Connection};
use std::path::Path;

pub fn open(case_dir: &Path) -> Result<Connection> {
    let conn = Connection::open(crate::util::case_db_path(case_dir))?;
    migrate(&conn)?;
    Ok(conn)
}

pub fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS case_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            severity TEXT NOT NULL,
            module TEXT NOT NULL,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            detail TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            evidence TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS web_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            status INTEGER NOT NULL,
            final_url TEXT NOT NULL,
            https INTEGER NOT NULL,
            header_summary TEXT NOT NULL,
            cookies TEXT NOT NULL,
            forms TEXT NOT NULL,
            notes TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS secret_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT NOT NULL,
            line INTEGER NOT NULL,
            kind TEXT NOT NULL,
            masked_value TEXT NOT NULL,
            context TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS password_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            idx INTEGER NOT NULL,
            score INTEGER NOT NULL,
            label TEXT NOT NULL,
            issues TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS hash_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT NOT NULL,
            kind TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
        CREATE INDEX IF NOT EXISTS idx_findings_module ON findings(module);
        CREATE INDEX IF NOT EXISTS idx_web_url ON web_observations(url);
        CREATE INDEX IF NOT EXISTS idx_secret_file ON secret_observations(file_path);
        "#
    )?;
    Ok(())
}

pub fn save_meta(conn: &Connection, meta: &CaseMeta) -> Result<()> {
    let pairs = [
        ("name", meta.name.as_str()),
        ("title", meta.title.as_str()),
        ("created_at", meta.created_at.as_str()),
        ("tool", meta.tool.as_str()),
        ("version", meta.version.as_str()),
        ("author", meta.author.as_str()),
    ];

    for (k, v) in pairs {
        conn.execute("INSERT OR REPLACE INTO case_meta (key, value) VALUES (?1, ?2)", params![k, v])?;
    }
    Ok(())
}

pub fn read_meta(conn: &Connection) -> Result<CaseMeta> {
    let get = |key: &str| -> Result<String> {
        Ok(conn.query_row("SELECT value FROM case_meta WHERE key = ?1", params![key], |row| row.get(0))?)
    };

    Ok(CaseMeta {
        name: get("name")?,
        title: get("title")?,
        created_at: get("created_at")?,
        tool: get("tool")?,
        version: get("version")?,
        author: get("author")?,
    })
}

pub fn insert_finding(conn: &Connection, f: &Finding) -> Result<()> {
    conn.execute(
        "INSERT INTO findings (severity, module, category, title, detail, recommendation, evidence, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![f.severity, f.module, f.category, f.title, f.detail, f.recommendation, f.evidence, crate::util::now_iso()],
    )?;
    Ok(())
}

pub fn insert_web(conn: &Connection, w: &WebObservation) -> Result<()> {
    conn.execute(
        "INSERT INTO web_observations (url, status, final_url, https, header_summary, cookies, forms, notes, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![w.url, w.status, w.final_url, if w.https {1} else {0}, w.header_summary, w.cookies, w.forms, w.notes, crate::util::now_iso()],
    )?;
    Ok(())
}

pub fn insert_secret(conn: &Connection, s: &SecretObservation) -> Result<()> {
    conn.execute(
        "INSERT INTO secret_observations (file_path, line, kind, masked_value, context, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![s.file_path, s.line as i64, s.kind, s.masked_value, s.context, crate::util::now_iso()],
    )?;
    Ok(())
}

pub fn insert_password(conn: &Connection, p: &PasswordObservation) -> Result<()> {
    conn.execute(
        "INSERT INTO password_observations (idx, score, label, issues, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![p.index as i64, p.score as i64, p.label, serde_json::to_string(&p.issues)?, crate::util::now_iso()],
    )?;
    Ok(())
}

pub fn insert_hash(conn: &Connection, h: &HashObservation) -> Result<()> {
    conn.execute(
        "INSERT INTO hash_observations (value, kind, recommendation, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![h.value, h.kind, h.recommendation, crate::util::now_iso()],
    )?;
    Ok(())
}

pub fn read_findings(conn: &Connection) -> Result<Vec<Finding>> {
    let mut stmt = conn.prepare("SELECT severity, module, category, title, detail, recommendation, evidence FROM findings ORDER BY id ASC")?;
    let rows = stmt.query_map([], |row| Ok(Finding {
        severity: row.get(0)?,
        module: row.get(1)?,
        category: row.get(2)?,
        title: row.get(3)?,
        detail: row.get(4)?,
        recommendation: row.get(5)?,
        evidence: row.get(6)?,
    }))?;
    collect_rows(rows)
}

pub fn read_web(conn: &Connection) -> Result<Vec<WebObservation>> {
    let mut stmt = conn.prepare("SELECT url, status, final_url, https, header_summary, cookies, forms, notes FROM web_observations ORDER BY id ASC")?;
    let rows = stmt.query_map([], |row| Ok(WebObservation {
        url: row.get(0)?,
        status: row.get(1)?,
        final_url: row.get(2)?,
        https: row.get::<_, i64>(3)? == 1,
        header_summary: row.get(4)?,
        cookies: row.get(5)?,
        forms: row.get(6)?,
        notes: row.get(7)?,
    }))?;
    collect_rows(rows)
}

pub fn read_secrets(conn: &Connection) -> Result<Vec<SecretObservation>> {
    let mut stmt = conn.prepare("SELECT file_path, line, kind, masked_value, context FROM secret_observations ORDER BY id ASC")?;
    let rows = stmt.query_map([], |row| Ok(SecretObservation {
        file_path: row.get(0)?,
        line: row.get::<_, i64>(1)? as usize,
        kind: row.get(2)?,
        masked_value: row.get(3)?,
        context: row.get(4)?,
    }))?;
    collect_rows(rows)
}

pub fn read_passwords(conn: &Connection) -> Result<Vec<PasswordObservation>> {
    let mut stmt = conn.prepare("SELECT idx, score, label, issues FROM password_observations ORDER BY id ASC")?;
    let rows = stmt.query_map([], |row| {
        let issues_text: String = row.get(3)?;
        let issues: Vec<String> = serde_json::from_str(&issues_text).unwrap_or_default();
        Ok(PasswordObservation {
            index: row.get::<_, i64>(0)? as usize,
            score: row.get::<_, i64>(1)? as u32,
            label: row.get(2)?,
            issues,
        })
    })?;
    collect_rows(rows)
}

pub fn read_hashes(conn: &Connection) -> Result<Vec<HashObservation>> {
    let mut stmt = conn.prepare("SELECT value, kind, recommendation FROM hash_observations ORDER BY id ASC")?;
    let rows = stmt.query_map([], |row| Ok(HashObservation {
        value: row.get(0)?,
        kind: row.get(1)?,
        recommendation: row.get(2)?,
    }))?;
    collect_rows(rows)
}

fn collect_rows<T>(rows: rusqlite::MappedRows<'_, impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>>) -> Result<Vec<T>> {
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}
