use crate::context::detect_context;
use crate::patterns::rules_for_language;
use crate::recommendations::{compute_severity, recommend};
use crate::types::{
    Finding, Language, LanguageStat, PrimitiveStat, ReportSummary, ScanConfig, ScanReport,
    Severity,
};

use anyhow::Result;
use ignore::WalkBuilder;
use rayon::prelude::*;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

/// Scan a directory tree for quantum-vulnerable cryptographic primitives.
pub fn scan(config: &ScanConfig) -> Result<ScanReport> {
    let start = Instant::now();

    // Configure thread pool
    if config.threads > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(config.threads)
            .build_global()
            .ok(); // Ignore if already initialized
    }

    // Phase 1: Collect files to scan
    let files = collect_files(config)?;
    let files_scanned = AtomicUsize::new(0);

    // Phase 2: Parallel regex scanning
    let findings: Vec<Finding> = files
        .par_iter()
        .flat_map(|path| {
            files_scanned.fetch_add(1, Ordering::Relaxed);
            scan_file(path, config).unwrap_or_default()
        })
        .collect();

    // Apply minimum severity filter
    let findings: Vec<Finding> = findings
        .into_iter()
        .filter(|f| f.severity >= config.min_severity)
        .collect();

    // Deduplicate findings (same file + line + primitive)
    let findings = deduplicate(findings);

    let duration = start.elapsed();
    let summary = build_summary(&findings);

    Ok(ScanReport {
        version: env!("CARGO_PKG_VERSION").to_string(),
        scan_target: config.target.display().to_string(),
        scan_timestamp: chrono::Utc::now().to_rfc3339(),
        scan_duration_ms: duration.as_millis() as u64,
        total_files_scanned: files_scanned.load(Ordering::Relaxed),
        total_findings: findings.len(),
        findings,
        summary,
    })
}

/// Collect files to scan using the `ignore` crate (respects .gitignore).
fn collect_files(config: &ScanConfig) -> Result<Vec<PathBuf>> {
    let mut builder = WalkBuilder::new(&config.target);
    builder
        .hidden(true) // skip hidden files/dirs
        .git_ignore(config.respect_gitignore)
        .git_global(config.respect_gitignore)
        .follow_links(config.follow_symlinks)
        .max_depth(Some(256));

    // Add exclude patterns
    for pattern in &config.exclude {
        builder.add_custom_ignore_filename(pattern);
    }

    let mut files = Vec::new();

    for entry in builder.build().flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        // Skip binary files by extension
        if is_binary_extension(path) {
            continue;
        }

        // Filter by language if specified
        let lang = language_from_path(path);
        if lang == Language::Unknown {
            continue;
        }

        if !config.languages.is_empty() && !config.languages.contains(&lang) {
            continue;
        }

        files.push(path.to_path_buf());
    }

    Ok(files)
}

/// Scan a single file for crypto patterns.
fn scan_file(path: &Path, config: &ScanConfig) -> Result<Vec<Finding>> {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    if content.is_empty() {
        return Ok(vec![]);
    }

    let language = language_from_path(path);
    let rules = rules_for_language(language);

    let lines: Vec<&str> = content.lines().collect();
    let mut findings = Vec::new();

    for (line_idx, line_text) in lines.iter().enumerate() {
        for rule in &rules {
            if let Some(mat) = rule.pattern.find(line_text) {
                // Get surrounding lines for context detection (±5 lines)
                let start = line_idx.saturating_sub(5);
                let end = (line_idx + 6).min(lines.len());
                let surrounding: Vec<&str> = lines[start..end].to_vec();

                let context = detect_context(path, language, line_text, &surrounding);

                // Skip test findings if not included
                if context == crate::types::UsageContext::Test && !config.include_tests {
                    continue;
                }

                let severity = compute_severity(rule.primitive, context);
                let recommendation = recommend(rule.primitive, context, config.cnsa_mode);

                findings.push(Finding {
                    file_path: path.to_path_buf(),
                    line: line_idx + 1,
                    column: mat.start() + 1,
                    primitive: rule.primitive,
                    severity,
                    context,
                    language,
                    matched_text: mat.as_str().to_string(),
                    description: rule.description.to_string(),
                    recommendation,
                });
            }
        }
    }

    Ok(findings)
}

/// Deduplicate findings: keep highest severity for same file + line + primitive.
fn deduplicate(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(|a, b| {
        a.file_path
            .cmp(&b.file_path)
            .then(a.line.cmp(&b.line))
            .then(b.severity.cmp(&a.severity))
    });

    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| {
        let key = (f.file_path.clone(), f.line, f.primitive);
        seen.insert(key)
    });

    // Final sort: critical first, then by file
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.file_path.cmp(&b.file_path))
            .then(a.line.cmp(&b.line))
    });

    findings
}

/// Build summary statistics.
fn build_summary(findings: &[Finding]) -> ReportSummary {
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;

    let mut by_primitive: HashMap<crate::types::CryptoPrimitive, usize> = HashMap::new();
    let mut by_language: HashMap<Language, usize> = HashMap::new();

    for f in findings {
        match f.severity {
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
        }
        *by_primitive.entry(f.primitive).or_default() += 1;
        *by_language.entry(f.language).or_default() += 1;
    }

    let mut prim_stats: Vec<PrimitiveStat> = by_primitive
        .into_iter()
        .map(|(primitive, count)| PrimitiveStat { primitive, count })
        .collect();
    prim_stats.sort_by(|a, b| b.count.cmp(&a.count));

    let mut lang_stats: Vec<LanguageStat> = by_language
        .into_iter()
        .map(|(language, count)| LanguageStat { language, count })
        .collect();
    lang_stats.sort_by(|a, b| b.count.cmp(&a.count));

    ReportSummary {
        critical,
        high,
        medium,
        low,
        by_primitive: prim_stats,
        by_language: lang_stats,
    }
}

/// Determine language from file extension.
fn language_from_path(path: &Path) -> Language {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(Language::from_extension)
        .unwrap_or(Language::Unknown)
}

/// Check if a file extension indicates a binary file.
fn is_binary_extension(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    matches!(
        ext,
        "exe" | "dll" | "so" | "dylib" | "o" | "a" | "lib"
            | "bin" | "img" | "iso"
            | "png" | "jpg" | "jpeg" | "gif" | "bmp" | "ico" | "svg"
            | "mp3" | "mp4" | "avi" | "mov" | "mkv" | "wav"
            | "zip" | "tar" | "gz" | "bz2" | "xz" | "7z" | "rar"
            | "pdf" | "doc" | "docx" | "xls" | "xlsx"
            | "wasm" | "class"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_file(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn test_scan_rust_rsa() {
        let tmp = TempDir::new().unwrap();
        create_test_file(
            tmp.path(),
            "crypto.rs",
            r#"
use rsa::RsaPrivateKey;

fn generate() {
    let key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
}
"#,
        );

        let config = ScanConfig {
            target: tmp.path().to_path_buf(),
            ..Default::default()
        };

        let report = scan(&config).unwrap();
        assert!(!report.findings.is_empty());

        let rsa_finding = report
            .findings
            .iter()
            .find(|f| f.primitive == crate::types::CryptoPrimitive::RsaGeneric
                || f.primitive == crate::types::CryptoPrimitive::Rsa2048);
        assert!(rsa_finding.is_some());
    }

    #[test]
    fn test_scan_solidity_ecrecover() {
        let tmp = TempDir::new().unwrap();
        create_test_file(
            tmp.path(),
            "Token.sol",
            r#"
pragma solidity ^0.8.0;

contract Token {
    function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public pure returns (address) {
        return ecrecover(hash, v, r, s);
    }
}
"#,
        );

        let config = ScanConfig {
            target: tmp.path().to_path_buf(),
            ..Default::default()
        };

        let report = scan(&config).unwrap();
        let sol_finding = report
            .findings
            .iter()
            .find(|f| f.language == Language::Solidity);
        assert!(sol_finding.is_some());

        let f = sol_finding.unwrap();
        assert_eq!(f.context, crate::types::UsageContext::BlockchainSigning);
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn test_scan_python_ed25519() {
        let tmp = TempDir::new().unwrap();
        create_test_file(
            tmp.path(),
            "auth.py",
            r#"
from cryptography.hazmat.primitives.asymmetric import ed25519

private_key = ed25519.Ed25519PrivateKey.generate()
"#,
        );

        let config = ScanConfig {
            target: tmp.path().to_path_buf(),
            ..Default::default()
        };

        let report = scan(&config).unwrap();
        let ed_finding = report
            .findings
            .iter()
            .find(|f| f.primitive == crate::types::CryptoPrimitive::Ed25519);
        assert!(ed_finding.is_some());
    }

    #[test]
    fn test_scan_pem_file() {
        let tmp = TempDir::new().unwrap();
        create_test_file(
            tmp.path(),
            "server.pem",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n",
        );

        let config = ScanConfig {
            target: tmp.path().to_path_buf(),
            ..Default::default()
        };

        let report = scan(&config).unwrap();
        let pem_finding = report
            .findings
            .iter()
            .find(|f| f.language == Language::Pem);
        assert!(pem_finding.is_some());
    }

    #[test]
    fn test_scan_go_crypto() {
        let tmp = TempDir::new().unwrap();
        create_test_file(
            tmp.path(),
            "main.go",
            r#"
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
)

func main() {
    key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    _ = key
}
"#,
        );

        let config = ScanConfig {
            target: tmp.path().to_path_buf(),
            ..Default::default()
        };

        let report = scan(&config).unwrap();
        assert!(!report.findings.is_empty());
    }

    #[test]
    fn test_scan_test_context_reduced_severity() {
        let tmp = TempDir::new().unwrap();
        create_test_file(
            tmp.path(),
            "tests/crypto_test.rs",
            r#"
#[test]
fn test_rsa() {
    let bits = 2048;
    let key_size = 2048;
}
"#,
        );

        let config = ScanConfig {
            target: tmp.path().to_path_buf(),
            include_tests: true,
            ..Default::default()
        };

        let report = scan(&config).unwrap();
        for f in &report.findings {
            assert!(
                f.severity <= Severity::Medium,
                "Test findings should be Medium or lower, got {:?}",
                f.severity
            );
        }
    }

    #[test]
    fn test_scan_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let config = ScanConfig {
            target: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let report = scan(&config).unwrap();
        assert_eq!(report.total_findings, 0);
    }

    #[test]
    fn test_summary_stats() {
        let tmp = TempDir::new().unwrap();
        create_test_file(
            tmp.path(),
            "crypto.rs",
            "use rsa::RsaPrivateKey;\nlet key_size = 2048;\n",
        );
        create_test_file(
            tmp.path(),
            "sign.py",
            "from cryptography.hazmat.primitives.asymmetric import ed25519\nEd25519PrivateKey.generate()\n",
        );

        let config = ScanConfig {
            target: tmp.path().to_path_buf(),
            ..Default::default()
        };

        let report = scan(&config).unwrap();
        assert!(report.summary.by_language.len() >= 1);
        assert!(report.summary.by_primitive.len() >= 1);
    }

    #[test]
    fn test_cnsa_mode() {
        let tmp = TempDir::new().unwrap();
        create_test_file(
            tmp.path(),
            "main.rs",
            "let key_size = 2048; // RSA\n",
        );

        let config = ScanConfig {
            target: tmp.path().to_path_buf(),
            cnsa_mode: true,
            ..Default::default()
        };

        let report = scan(&config).unwrap();
        for f in &report.findings {
            if f.primitive == crate::types::CryptoPrimitive::Rsa2048 {
                assert!(f.recommendation.replacement.contains("ML-KEM-1024"));
            }
        }
    }
}
