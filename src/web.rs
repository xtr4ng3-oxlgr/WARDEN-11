use crate::models::{Finding, WebObservation};
use anyhow::{anyhow, Result};
use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderMap, SET_COOKIE};
use std::path::Path;
use std::thread;
use std::time::Duration;
use url::Url;

const COMMON_PATHS: &[&str] = &[
    "/robots.txt",
    "/sitemap.xml",
    "/security.txt",
    "/.well-known/security.txt",
    "/.env",
    "/.git/config",
    "/backup.zip",
    "/config.json",
    "/phpinfo.php",
];

pub fn run_web_audit(case_dir: &Path, yes_authorized: bool) -> Result<()> {
    if !yes_authorized {
        return Err(anyhow!("web audit requires --yes-authorized for authorized targets"));
    }

    let scope = crate::scope::read_scope(case_dir)?;
    if scope.is_empty() {
        return Err(anyhow!("scope is empty. Use: warden11 scope-add <case> https://example.com"));
    }

    let conn = crate::db::open(case_dir)?;
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("WARDEN-11 Authorized Cyber Patrol/1.0")
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?;

    for target in scope {
        println!("web audit: {}", target);
        audit_url(&conn, &client, &target)?;
        for path in COMMON_PATHS {
            if let Ok(mut u) = Url::parse(&target) {
                u.set_path(path);
                u.set_query(None);
                u.set_fragment(None);
                let candidate = u.to_string();
                if crate::scope::same_origin(&target, &candidate) {
                    thread::sleep(Duration::from_millis(650));
                    audit_common_path(&conn, &client, &candidate)?;
                }
            }
        }
    }

    Ok(())
}

fn audit_url(conn: &rusqlite::Connection, client: &Client, url: &str) -> Result<()> {
    let resp = client.get(url).send();
    match resp {
        Ok(r) => {
            let status = r.status().as_u16() as i64;
            let final_url = r.url().to_string();
            let https = final_url.starts_with("https://");
            let headers = r.headers().clone();
            let body = safe_body(r);

            let header_summary = summarize_headers(&headers);
            let cookies = summarize_cookies(&headers);
            let forms = summarize_forms(&body);
            let notes = String::new();

            let obs = WebObservation {
                url: url.to_string(),
                status,
                final_url: final_url.clone(),
                https,
                header_summary,
                cookies: cookies.clone(),
                forms: forms.clone(),
                notes,
            };
            crate::db::insert_web(conn, &obs)?;

            evaluate_headers(conn, url, &headers, https)?;
            evaluate_cookies(conn, url, &headers)?;
            evaluate_forms(conn, url, &body)?;
        }
        Err(e) => {
            crate::db::insert_finding(conn, &Finding {
                severity: "low".to_string(),
                module: "web".to_string(),
                category: "connectivity".to_string(),
                title: "Target could not be requested".to_string(),
                detail: format!("{} -> {}", url, e),
                recommendation: "Verify scope, DNS, TLS and connectivity.".to_string(),
                evidence: url.to_string(),
            })?;
        }
    }
    Ok(())
}

fn audit_common_path(conn: &rusqlite::Connection, client: &Client, url: &str) -> Result<()> {
    let resp = client.get(url).send();
    if let Ok(r) = resp {
        let status = r.status().as_u16();
        if status >= 200 && status < 300 {
            let content_type = r.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            crate::db::insert_finding(conn, &Finding {
                severity: if url.ends_with("/.env") || url.ends_with("/.git/config") { "high" } else { "medium" }.to_string(),
                module: "web".to_string(),
                category: "exposed_path".to_string(),
                title: "Common sensitive path responded successfully".to_string(),
                detail: format!("{} returned HTTP {} ({})", url, status, content_type),
                recommendation: "Review whether this endpoint should be public. Restrict or remove if unintended.".to_string(),
                evidence: url.to_string(),
            })?;
        }
    }
    Ok(())
}

fn safe_body(resp: Response) -> String {
    match resp.text() {
        Ok(mut text) => {
            if text.len() > 64_000 {
                text.truncate(64_000);
            }
            text
        }
        Err(_) => String::new(),
    }
}

fn summarize_headers(headers: &HeaderMap) -> String {
    let wanted = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "server",
        "x-powered-by",
    ];
    let mut out = Vec::new();
    for h in wanted {
        if let Some(v) = headers.get(h) {
            out.push(format!("{}={}", h, v.to_str().unwrap_or("[binary]")));
        }
    }
    out.join("; ")
}

fn summarize_cookies(headers: &HeaderMap) -> String {
    let mut out = Vec::new();
    for v in headers.get_all(SET_COOKIE).iter() {
        if let Ok(s) = v.to_str() {
            out.push(s.to_string());
        }
    }
    out.join(" | ")
}

fn summarize_forms(body: &str) -> String {
    let lower = body.to_lowercase();
    let forms = lower.matches("<form").count();
    let password = lower.matches("type=\"password\"").count() + lower.matches("type='password'").count();
    format!("forms={} password_inputs={}", forms, password)
}

fn evaluate_headers(conn: &rusqlite::Connection, url: &str, headers: &HeaderMap, https: bool) -> Result<()> {
    if !https {
        insert_web_finding(conn, "high", "transport", "HTTPS not enforced on final URL", url, "Use HTTPS and redirect HTTP to HTTPS.")?;
    }

    let required = [
        ("strict-transport-security", "medium", "Missing HSTS header", "Enable Strict-Transport-Security on HTTPS sites."),
        ("content-security-policy", "medium", "Missing Content-Security-Policy", "Add a CSP adapted to the application."),
        ("x-content-type-options", "low", "Missing X-Content-Type-Options", "Set X-Content-Type-Options: nosniff."),
        ("referrer-policy", "low", "Missing Referrer-Policy", "Set a privacy-aware Referrer-Policy."),
    ];

    for (h, sev, title, rec) in required {
        if headers.get(h).is_none() {
            insert_web_finding(conn, sev, "headers", title, url, rec)?;
        }
    }

    if headers.get("x-powered-by").is_some() {
        insert_web_finding(conn, "low", "headers", "Technology disclosure header", url, "Remove unnecessary X-Powered-By headers.")?;
    }

    if let Some(csp) = headers.get("content-security-policy").and_then(|v| v.to_str().ok()) {
        if csp.contains("unsafe-inline") || csp.contains("*") {
            insert_web_finding(conn, "medium", "headers", "Weak CSP pattern", url, "Review wildcard and unsafe-inline usage.")?;
        }
    }

    Ok(())
}

fn evaluate_cookies(conn: &rusqlite::Connection, url: &str, headers: &HeaderMap) -> Result<()> {
    for v in headers.get_all(SET_COOKIE).iter() {
        if let Ok(cookie) = v.to_str() {
            let lower = cookie.to_lowercase();
            if !lower.contains("secure") {
                insert_web_finding(conn, "medium", "cookies", "Cookie missing Secure", url, "Set Secure on sensitive cookies.")?;
            }
            if !lower.contains("httponly") {
                insert_web_finding(conn, "medium", "cookies", "Cookie missing HttpOnly", url, "Set HttpOnly on session cookies.")?;
            }
            if !lower.contains("samesite") {
                insert_web_finding(conn, "low", "cookies", "Cookie missing SameSite", url, "Set SameSite=Lax or Strict where appropriate.")?;
            }
        }
    }
    Ok(())
}

fn evaluate_forms(conn: &rusqlite::Connection, url: &str, body: &str) -> Result<()> {
    let lower = body.to_lowercase();
    if lower.contains("<form") && (lower.contains("type=\"password\"") || lower.contains("type='password'")) && !url.starts_with("https://") {
        insert_web_finding(conn, "high", "forms", "Password form on non-HTTPS URL", url, "Password forms must be served over HTTPS.")?;
    }
    Ok(())
}

fn insert_web_finding(conn: &rusqlite::Connection, severity: &str, category: &str, title: &str, evidence: &str, rec: &str) -> Result<()> {
    crate::db::insert_finding(conn, &Finding {
        severity: severity.to_string(),
        module: "web".to_string(),
        category: category.to_string(),
        title: title.to_string(),
        detail: evidence.to_string(),
        recommendation: rec.to_string(),
        evidence: evidence.to_string(),
    })
}
