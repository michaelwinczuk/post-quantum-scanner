use crate::types::{ScanReport, Severity};
use colored::Colorize;
use std::io::Write;

/// Output the scan report as pretty-printed JSON.
pub fn output_json<W: Write>(report: &ScanReport, writer: &mut W) -> anyhow::Result<()> {
    serde_json::to_writer_pretty(&mut *writer, report)?;
    writeln!(writer)?;
    Ok(())
}

/// Output a human-readable summary to the terminal.
pub fn output_summary<W: Write>(report: &ScanReport, writer: &mut W) -> anyhow::Result<()> {
    writeln!(writer)?;
    writeln!(
        writer,
        "{}",
        "╔══════════════════════════════════════════════════════════════╗"
            .bold()
    )?;
    writeln!(
        writer,
        "{}",
        "║           pq-discovery — Post-Quantum Scanner              ║"
            .bold()
    )?;
    writeln!(
        writer,
        "{}",
        "╚══════════════════════════════════════════════════════════════╝"
            .bold()
    )?;
    writeln!(writer)?;

    writeln!(writer, "  Target:    {}", report.scan_target)?;
    writeln!(writer, "  Files:     {}", report.total_files_scanned)?;
    writeln!(writer, "  Duration:  {}ms", report.scan_duration_ms)?;
    writeln!(writer, "  Findings:  {}", report.total_findings)?;
    writeln!(writer)?;

    // Severity breakdown
    writeln!(writer, "  {}", "Severity Breakdown".bold().underline())?;
    if report.summary.critical > 0 {
        writeln!(
            writer,
            "    {} CRITICAL: {}",
            "●".red().bold(),
            report.summary.critical
        )?;
    }
    if report.summary.high > 0 {
        writeln!(
            writer,
            "    {} HIGH:     {}",
            "●".red(),
            report.summary.high
        )?;
    }
    if report.summary.medium > 0 {
        writeln!(
            writer,
            "    {} MEDIUM:   {}",
            "●".yellow(),
            report.summary.medium
        )?;
    }
    if report.summary.low > 0 {
        writeln!(
            writer,
            "    {} LOW:      {}",
            "●".blue(),
            report.summary.low
        )?;
    }
    writeln!(writer)?;

    // Top primitives
    if !report.summary.by_primitive.is_empty() {
        writeln!(writer, "  {}", "Detected Primitives".bold().underline())?;
        for stat in &report.summary.by_primitive {
            writeln!(
                writer,
                "    {:30} {}",
                stat.primitive.display_name(),
                stat.count
            )?;
        }
        writeln!(writer)?;
    }

    // By language
    if !report.summary.by_language.is_empty() {
        writeln!(writer, "  {}", "By Language".bold().underline())?;
        for stat in &report.summary.by_language {
            writeln!(
                writer,
                "    {:30} {}",
                stat.language.display_name(),
                stat.count
            )?;
        }
        writeln!(writer)?;
    }

    // Individual findings (top 50)
    if !report.findings.is_empty() {
        writeln!(writer, "  {}", "Findings".bold().underline())?;
        writeln!(writer)?;

        let limit = report.findings.len().min(50);
        for f in &report.findings[..limit] {
            let severity_str = match f.severity {
                Severity::Critical => "CRITICAL".red().bold().to_string(),
                Severity::High => "HIGH".red().to_string(),
                Severity::Medium => "MEDIUM".yellow().to_string(),
                Severity::Low => "LOW".blue().to_string(),
            };

            writeln!(
                writer,
                "  [{severity_str}] {}:{}",
                f.file_path.display(),
                f.line,
            )?;
            writeln!(
                writer,
                "    {} — {}",
                f.primitive.display_name().bold(),
                f.description,
            )?;
            writeln!(
                writer,
                "    {} {}",
                "Replace with:".dimmed(),
                f.recommendation.replacement,
            )?;
            if let Some(ref hybrid) = f.recommendation.hybrid {
                writeln!(writer, "    {} {}", "Hybrid:".dimmed(), hybrid)?;
            }
            if let Some(ref compliance) = f.recommendation.compliance {
                writeln!(writer, "    {} {}", "Compliance:".dimmed(), compliance)?;
            }
            writeln!(writer)?;
        }

        if report.findings.len() > limit {
            writeln!(
                writer,
                "  ... and {} more findings (use --output json for full report)",
                report.findings.len() - limit
            )?;
            writeln!(writer)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use std::path::PathBuf;

    fn sample_report() -> ScanReport {
        ScanReport {
            version: "0.1.0".into(),
            scan_target: "/tmp/test".into(),
            scan_timestamp: "2026-02-26T00:00:00Z".into(),
            scan_duration_ms: 42,
            total_files_scanned: 10,
            total_findings: 2,
            findings: vec![
                Finding {
                    file_path: PathBuf::from("src/main.rs"),
                    line: 10,
                    column: 5,
                    primitive: CryptoPrimitive::Rsa2048,
                    severity: Severity::High,
                    context: UsageContext::General,
                    language: Language::Rust,
                    matched_text: "key_size = 2048".into(),
                    description: "RSA-2048 key size detected".into(),
                    recommendation: Recommendation {
                        replacement: "ML-KEM-768 + ML-DSA-65".into(),
                        guidance: "Migrate to ML-KEM-768".into(),
                        hybrid: Some("RSA-2048 + ML-KEM-768 hybrid".into()),
                        compliance: Some("CNSA 2.0: non-compliant by 2030".into()),
                    },
                },
                Finding {
                    file_path: PathBuf::from("contracts/Token.sol"),
                    line: 15,
                    column: 12,
                    primitive: CryptoPrimitive::EcdsaSecp256k1,
                    severity: Severity::Critical,
                    context: UsageContext::BlockchainSigning,
                    language: Language::Solidity,
                    matched_text: "ecrecover(hash, v, r, s)".into(),
                    description: "ecrecover precompile".into(),
                    recommendation: Recommendation {
                        replacement: "ML-DSA-65 via ERC-4337".into(),
                        guidance: "Migrate to account abstraction".into(),
                        hybrid: None,
                        compliance: None,
                    },
                },
            ],
            summary: ReportSummary {
                critical: 1,
                high: 1,
                medium: 0,
                low: 0,
                by_primitive: vec![
                    PrimitiveStat {
                        primitive: CryptoPrimitive::EcdsaSecp256k1,
                        count: 1,
                    },
                    PrimitiveStat {
                        primitive: CryptoPrimitive::Rsa2048,
                        count: 1,
                    },
                ],
                by_language: vec![
                    LanguageStat {
                        language: Language::Rust,
                        count: 1,
                    },
                    LanguageStat {
                        language: Language::Solidity,
                        count: 1,
                    },
                ],
            },
        }
    }

    #[test]
    fn test_json_output() {
        let report = sample_report();
        let mut buf = Vec::new();
        output_json(&report, &mut buf).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(json["total_findings"], 2);
        assert_eq!(json["findings"][0]["severity"], "HIGH");
    }

    #[test]
    fn test_summary_output() {
        let report = sample_report();
        let mut buf = Vec::new();
        output_summary(&report, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("pq-discovery"));
        assert!(output.contains("Findings"));
    }
}
