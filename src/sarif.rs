use crate::types::{CryptoPrimitive, Finding, ScanReport};
use serde::Serialize;
use std::collections::HashMap;
use std::io::Write;

/// SARIF 2.1.0 log format.
#[derive(Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: String,
    #[serde(rename = "informationUri")]
    information_uri: String,
    version: String,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
struct SarifRule {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
    #[serde(rename = "fullDescription")]
    full_description: SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: SarifDefaultConfig,
    help: SarifMessage,
    properties: SarifRuleProperties,
}

#[derive(Serialize)]
struct SarifDefaultConfig {
    level: String,
}

#[derive(Serialize)]
struct SarifRuleProperties {
    tags: Vec<String>,
    #[serde(rename = "security-severity")]
    security_severity: String,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fixes: Option<Vec<SarifFix>>,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: usize,
    #[serde(rename = "startColumn")]
    start_column: usize,
}

#[derive(Serialize)]
struct SarifFix {
    description: SarifMessage,
}

/// Output the scan report as SARIF 2.1.0.
pub fn output_sarif<W: Write>(report: &ScanReport, writer: &mut W) -> anyhow::Result<()> {
    // Build unique rules from findings
    let mut rule_map: HashMap<String, SarifRule> = HashMap::new();

    for finding in &report.findings {
        let rule_id = rule_id_for(finding);
        rule_map.entry(rule_id.clone()).or_insert_with(|| {
            build_rule(&rule_id, finding)
        });
    }

    let mut rules: Vec<SarifRule> = rule_map.into_values().collect();
    rules.sort_by(|a, b| a.id.cmp(&b.id));

    // Build results
    let results: Vec<SarifResult> = report
        .findings
        .iter()
        .map(build_result)
        .collect();

    let sarif = SarifLog {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json".into(),
        version: "2.1.0".into(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "pq-discovery".into(),
                    information_uri: "https://github.com/michaelwinczuk/post-quantum-scanner".into(),
                    version: report.version.clone(),
                    rules,
                },
            },
            results,
        }],
    };

    serde_json::to_writer_pretty(&mut *writer, &sarif)?;
    writeln!(writer)?;
    Ok(())
}

/// Generate a rule ID for a finding.
fn rule_id_for(finding: &Finding) -> String {
    let prim = match finding.primitive {
        CryptoPrimitive::Rsa2048 => "RSA-2048",
        CryptoPrimitive::Rsa4096 => "RSA-4096",
        CryptoPrimitive::RsaGeneric => "RSA",
        CryptoPrimitive::RsaPkcs1v15 => "RSA-PKCS1",
        CryptoPrimitive::EcdsaP256 => "ECDSA-P256",
        CryptoPrimitive::EcdsaP384 => "ECDSA-P384",
        CryptoPrimitive::EcdsaSecp256k1 => "ECDSA-SECP256K1",
        CryptoPrimitive::EcdsaGeneric => "ECDSA",
        CryptoPrimitive::Ed25519 => "ED25519",
        CryptoPrimitive::X25519 => "X25519",
        CryptoPrimitive::EcdhP256 => "ECDH-P256",
        CryptoPrimitive::EcdhP384 => "ECDH-P384",
        CryptoPrimitive::Dsa => "DSA",
        CryptoPrimitive::Dh => "DH",
        CryptoPrimitive::TripleDes => "3DES",
        CryptoPrimitive::Blowfish => "BLOWFISH",
        CryptoPrimitive::Rc4 => "RC4",
        CryptoPrimitive::Bls12381 => "BLS12-381",
        CryptoPrimitive::Sha1Signing => "SHA1-SIGN",
        CryptoPrimitive::Md5 => "MD5",
    };
    format!("PQC-{prim}")
}

fn build_rule(rule_id: &str, finding: &Finding) -> SarifRule {
    let severity_score = match finding.severity {
        crate::types::Severity::Critical => "9.5",
        crate::types::Severity::High => "8.0",
        crate::types::Severity::Medium => "5.5",
        crate::types::Severity::Low => "3.0",
    };

    SarifRule {
        id: rule_id.into(),
        name: format!("Quantum-Vulnerable: {}", finding.primitive.display_name()),
        short_description: SarifMessage {
            text: format!(
                "{} is vulnerable to quantum computing attacks (Shor's algorithm)",
                finding.primitive.display_name()
            ),
        },
        full_description: SarifMessage {
            text: format!(
                "{} detected. Quantum computers running Shor's algorithm can break this \
                 primitive. Recommended replacement: {}",
                finding.primitive.display_name(),
                finding.recommendation.replacement,
            ),
        },
        default_configuration: SarifDefaultConfig {
            level: finding.severity.sarif_level().into(),
        },
        help: SarifMessage {
            text: format!(
                "Migration guidance: {}\n{}",
                finding.recommendation.guidance,
                finding
                    .recommendation
                    .compliance
                    .as_deref()
                    .unwrap_or(""),
            ),
        },
        properties: SarifRuleProperties {
            tags: vec![
                "security".into(),
                "post-quantum".into(),
                "cryptography".into(),
            ],
            security_severity: severity_score.into(),
        },
    }
}

fn build_result(finding: &Finding) -> SarifResult {
    let rule_id = rule_id_for(finding);

    let fix = finding.recommendation.hybrid.as_ref().map(|hybrid| {
        vec![SarifFix {
            description: SarifMessage {
                text: format!(
                    "Replace with {}. Hybrid transition: {}",
                    finding.recommendation.replacement, hybrid,
                ),
            },
        }]
    });

    SarifResult {
        rule_id,
        level: finding.severity.sarif_level().into(),
        message: SarifMessage {
            text: format!(
                "{}: {} — Replace with {}",
                finding.primitive.display_name(),
                finding.description,
                finding.recommendation.replacement,
            ),
        },
        locations: vec![SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    uri: finding.file_path.display().to_string(),
                },
                region: SarifRegion {
                    start_line: finding.line,
                    start_column: finding.column,
                },
            },
        }],
        fixes: fix,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use std::path::PathBuf;

    #[test]
    fn test_sarif_output_valid_json() {
        let report = ScanReport {
            version: "0.1.0".into(),
            scan_target: ".".into(),
            scan_timestamp: "2026-02-26T00:00:00Z".into(),
            scan_duration_ms: 10,
            total_files_scanned: 1,
            total_findings: 1,
            findings: vec![Finding {
                file_path: PathBuf::from("main.rs"),
                line: 5,
                column: 1,
                primitive: CryptoPrimitive::Rsa2048,
                severity: Severity::High,
                context: UsageContext::General,
                language: Language::Rust,
                matched_text: "key_size = 2048".into(),
                description: "RSA-2048 detected".into(),
                recommendation: Recommendation {
                    replacement: "ML-KEM-768".into(),
                    guidance: "Migrate to ML-KEM-768".into(),
                    hybrid: Some("RSA + ML-KEM hybrid".into()),
                    compliance: None,
                },
            }],
            summary: ReportSummary {
                critical: 0,
                high: 1,
                medium: 0,
                low: 0,
                by_primitive: vec![],
                by_language: vec![],
            },
        };

        let mut buf = Vec::new();
        output_sarif(&report, &mut buf).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(json["version"], "2.1.0");
        assert_eq!(
            json["runs"][0]["tool"]["driver"]["name"],
            "pq-discovery"
        );
        assert_eq!(json["runs"][0]["results"][0]["ruleId"], "PQC-RSA-2048");
        assert_eq!(json["runs"][0]["results"][0]["level"], "error");
    }

    #[test]
    fn test_sarif_rule_ids() {
        let finding = Finding {
            file_path: PathBuf::from("test.sol"),
            line: 1,
            column: 1,
            primitive: CryptoPrimitive::EcdsaSecp256k1,
            severity: Severity::Critical,
            context: UsageContext::BlockchainSigning,
            language: Language::Solidity,
            matched_text: "ecrecover".into(),
            description: "ecrecover".into(),
            recommendation: Recommendation {
                replacement: "ML-DSA-65".into(),
                guidance: "Migrate".into(),
                hybrid: None,
                compliance: None,
            },
        };

        assert_eq!(rule_id_for(&finding), "PQC-ECDSA-SECP256K1");
    }
}
