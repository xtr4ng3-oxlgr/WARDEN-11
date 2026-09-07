use crate::models::{Finding, ReportSummary};
use anyhow::Result;
use std::fs;
use std::path::Path;

pub fn generate_reports(case_dir: &Path) -> Result<()> {
    crate::util::ensure_dir(&crate::util::reports_dir(case_dir))?;

    let conn = crate::db::open(case_dir)?;
    let meta = crate::db::read_meta(&conn)?;
    let findings = crate::db::read_findings(&conn)?;
    let web = crate::db::read_web(&conn)?;
    let secrets = crate::db::read_secrets(&conn)?;
    let passwords = crate::db::read_passwords(&conn)?;
    let hashes = crate::db::read_hashes(&conn)?;

    let score = score_findings(&findings);
    let summary = ReportSummary {
        case_name: meta.name.clone(),
        generated_at: crate::util::now_iso(),
        score,
        verdict: verdict(score),
        findings: findings.len(),
        web_observations: web.len(),
        secret_observations: secrets.len(),
        password_observations: passwords.len(),
        hash_observations: hashes.len(),
    };

    let report = serde_json::json!({
        "summary": summary,
        "case": meta,
        "findings": findings,
        "web": web,
        "secrets": secrets,
        "passwords": passwords,
        "hashes": hashes,
    });

    let stamp = crate::util::now_stamp();
    let dir = crate::util::reports_dir(case_dir);
    let json_path = dir.join(format!("warden11_{}.json", stamp));
    let html_path = dir.join(format!("warden11_{}.html", stamp));
    let sarif_path = dir.join(format!("warden11_{}.sarif", stamp));

    fs::write(&json_path, serde_json::to_string_pretty(&report)?)?;
    write_html(&html_path, &report)?;
    write_sarif(&sarif_path, &report)?;

    println!("reports:");
    println!("  HTML : {}", html_path.display());
    println!("  JSON : {}", json_path.display());
    println!("  SARIF: {}", sarif_path.display());

    Ok(())
}

fn score_findings(findings: &[Finding]) -> u32 {
    let mut score = 0u32;
    let mut high = 0usize;
    let mut medium = 0usize;

    for f in findings {
        match f.severity.as_str() {
            "critical" => score = score.max(100),
            "high" => { score = score.max(75); high += 1; }
            "medium" => { score = score.max(45); medium += 1; }
            "low" => score = score.max(20),
            _ => {}
        }
    }

    if high >= 5 {
        score = score.max(90);
    } else if high >= 2 {
        score = score.max(80);
    } else if medium >= 10 {
        score = score.max(65);
    }

    score.min(100)
}

fn verdict(score: u32) -> String {
    if score >= 90 {
        "critical".to_string()
    } else if score >= 70 {
        "high".to_string()
    } else if score >= 40 {
        "medium".to_string()
    } else if score > 0 {
        "low".to_string()
    } else {
        "clean".to_string()
    }
}

fn write_html(path: &Path, report: &serde_json::Value) -> Result<()> {
    let summary = &report["summary"];
    let findings = report["findings"].as_array().cloned().unwrap_or_default();
    let web = report["web"].as_array().cloned().unwrap_or_default();
    let secrets = report["secrets"].as_array().cloned().unwrap_or_default();
    let passwords = report["passwords"].as_array().cloned().unwrap_or_default();
    let hashes = report["hashes"].as_array().cloned().unwrap_or_default();

    let finding_rows = findings.iter().map(|f| format!(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td><b>{}</b><br>{}</td><td>{}</td></tr>",
        esc(&f["severity"]), esc(&f["module"]), esc(&f["category"]), esc(&f["title"]), esc(&f["detail"]), esc(&f["recommendation"])
    )).collect::<Vec<_>>().join("\n");

    let web_rows = web.iter().map(|w| format!(
        "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
        esc(&w["url"]), w["status"].as_i64().unwrap_or(0), esc(&w["final_url"]), esc(&w["header_summary"]), esc(&w["forms"])
    )).collect::<Vec<_>>().join("\n");

    let secret_rows = secrets.iter().map(|s| format!(
        "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>",
        esc(&s["file_path"]), s["line"].as_u64().unwrap_or(0), esc(&s["kind"]), esc(&s["masked_value"]), esc(&s["context"])
    )).collect::<Vec<_>>().join("\n");

    let password_rows = passwords.iter().take(200).map(|p| format!(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
        p["index"].as_u64().unwrap_or(0), p["score"].as_u64().unwrap_or(0), esc(&p["label"]), esc(&p["issues"])
    )).collect::<Vec<_>>().join("\n");

    let hash_rows = hashes.iter().map(|h| format!(
        "<tr><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
        esc(&h["value"]), esc(&h["kind"]), esc(&h["recommendation"])
    )).collect::<Vec<_>>().join("\n");

    let score = summary["score"].as_u64().unwrap_or(0);
    let color = if score >= 90 { "#ff4d4d" } else if score >= 70 { "#ff8a3d" } else if score >= 40 { "#e8c14d" } else { "#3d8bfd" };

    let html = format!(r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WARDEN-11 Report</title>
<style>
body{{background:#070a10;color:#dbe4ec;font-family:Consolas,Segoe UI,Arial;padding:30px}}
h1,h2{{color:#3d8bfd}}
.card{{background:#0c1119;border:1px solid #1f2b3a;border-radius:10px;padding:18px;margin:18px 0;box-shadow:0 0 24px rgba(61,139,253,.08)}}
table{{width:100%;border-collapse:collapse;margin-top:12px}}
td,th{{border-bottom:1px solid #1a2430;padding:9px;text-align:left;vertical-align:top}}
th{{color:#7fa8d9}}
code{{color:#bcd4ea}}
.score{{font-size:58px;font-weight:900;color:{color}}}
.small{{color:#93a5b8}}
</style>
</head>
<body>
<h1>WARDEN-11</h1>
<p class="small">Authorized Cyber Patrol Workbench · xtr4ng3 · {generated}</p>
<div class="card"><h2>Verdict</h2><div class="score">{score}/100</div><p><b>{verdict}</b></p>
<p>Findings: {findings_count} · Web: {web_count} · Secrets: {secret_count} · Passwords: {pw_count} · Hashes: {hash_count}</p></div>
<div class="card"><h2>Findings</h2><table><tr><th>Severity</th><th>Module</th><th>Category</th><th>Finding</th><th>Recommendation</th></tr>{finding_rows}</table></div>
<div class="card"><h2>Web Surface</h2><table><tr><th>URL</th><th>Status</th><th>Final URL</th><th>Headers</th><th>Forms</th></tr>{web_rows}</table></div>
<div class="card"><h2>Secrets Patrol</h2><table><tr><th>File</th><th>Line</th><th>Kind</th><th>Masked</th><th>Context</th></tr>{secret_rows}</table></div>
<div class="card"><h2>Password Hygiene</h2><table><tr><th>#</th><th>Score</th><th>Label</th><th>Issues</th></tr>{password_rows}</table></div>
<div class="card"><h2>Hash Inventory</h2><table><tr><th>Value</th><th>Kind</th><th>Recommendation</th></tr>{hash_rows}</table></div>
<p class="small">WARDEN-11 is defensive and authorized-only. No brute force, no exploitation, no credential theft.</p>
</body></html>"#,
        color=color,
        generated=esc(&summary["generated_at"]),
        score=score,
        verdict=esc(&summary["verdict"]).to_uppercase(),
        findings_count=summary["findings"].as_u64().unwrap_or(0),
        web_count=summary["web_observations"].as_u64().unwrap_or(0),
        secret_count=summary["secret_observations"].as_u64().unwrap_or(0),
        pw_count=summary["password_observations"].as_u64().unwrap_or(0),
        hash_count=summary["hash_observations"].as_u64().unwrap_or(0),
        finding_rows=finding_rows,
        web_rows=web_rows,
        secret_rows=secret_rows,
        password_rows=password_rows,
        hash_rows=hash_rows,
    );

    fs::write(path, html)?;
    Ok(())
}

fn write_sarif(path: &Path, report: &serde_json::Value) -> Result<()> {
    let findings = report["findings"].as_array().cloned().unwrap_or_default();
    let mut results = Vec::new();

    for f in findings {
        let sev = f["severity"].as_str().unwrap_or("note");
        let level = match sev {
            "critical" | "high" => "error",
            "medium" => "warning",
            _ => "note",
        };

        results.push(serde_json::json!({
            "ruleId": format!("{}.{}", f["module"].as_str().unwrap_or("warden11"), f["category"].as_str().unwrap_or("finding")),
            "level": level,
            "message": {
                "text": format!("{} - {}", f["title"].as_str().unwrap_or("finding"), f["detail"].as_str().unwrap_or(""))
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f["evidence"].as_str().unwrap_or("")
                    }
                }
            }]
        }));
    }

    let sarif = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "WARDEN-11",
                    "version": crate::VERSION,
                    "informationUri": "https://github.com/xtr4ng3/warden-11"
                }
            },
            "results": results
        }]
    });

    fs::write(path, serde_json::to_string_pretty(&sarif)?)?;
    Ok(())
}

fn esc(value: &serde_json::Value) -> String {
    if let Some(s) = value.as_str() {
        crate::util::html_escape(s)
    } else {
        crate::util::html_escape(&value.to_string())
    }
}
