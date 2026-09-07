use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseMeta {
    pub name: String,
    pub title: String,
    pub created_at: String,
    pub tool: String,
    pub version: String,
    pub author: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: String,
    pub module: String,
    pub category: String,
    pub title: String,
    pub detail: String,
    pub recommendation: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebObservation {
    pub url: String,
    pub status: i64,
    pub final_url: String,
    pub https: bool,
    pub header_summary: String,
    pub cookies: String,
    pub forms: String,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretObservation {
    pub file_path: String,
    pub line: usize,
    pub kind: String,
    pub masked_value: String,
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordObservation {
    pub index: usize,
    pub score: u32,
    pub label: String,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashObservation {
    pub value: String,
    pub kind: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub case_name: String,
    pub generated_at: String,
    pub score: u32,
    pub verdict: String,
    pub findings: usize,
    pub web_observations: usize,
    pub secret_observations: usize,
    pub password_observations: usize,
    pub hash_observations: usize,
}
