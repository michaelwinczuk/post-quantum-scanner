use crate::types::{CryptoPrimitive, Language};
use regex::Regex;
use std::sync::LazyLock;

/// A detection rule: regex pattern → crypto primitive + description.
#[derive(Debug)]
pub struct DetectionRule {
    pub pattern: &'static LazyLock<Regex>,
    pub primitive: CryptoPrimitive,
    pub description: &'static str,
    pub languages: &'static [Language],
}

// ─── RSA patterns ────────────────────────────────────────────────────────────

static RSA_2048_KEY_SIZE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:key[_\-]?size|bits|modulus[_\-]?(?:size|len|length))\s*[:=]\s*2048").unwrap()
});

static RSA_4096_KEY_SIZE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:key[_\-]?size|bits|modulus[_\-]?(?:size|len|length))\s*[:=]\s*4096").unwrap()
});

static RSA_GENERATE_2048: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:RSA\.generate|rsa\.generate_private_key|GenerateKey|generate_key|RSAKeyGenParameterSpec)\s*\(\s*(?:\w+\s*,\s*)?2048").unwrap()
});

static RSA_GENERATE_4096: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:RSA\.generate|rsa\.generate_private_key|GenerateKey|generate_key|RSAKeyGenParameterSpec)\s*\(\s*(?:\w+\s*,\s*)?4096").unwrap()
});

static RSA_GENERIC_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:from\s+(?:cryptography\.hazmat\.primitives\.asymmetric|Crypto\.PublicKey)\s+import\s+rsa|use\s+(?:ring::signature::RSA|rsa::)|import\s+"crypto/rsa"|require\s*\(\s*['"](?:node-rsa|crypto)['"]|EVP_PKEY_RSA|TYPE_RSA)"#).unwrap()
});

static RSA_PKCS1_SIGN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:PKCS1v15|pkcs1v15|RSA_PKCS1_PADDING|RSASSA.PKCS1|SignatureAlgorithm\.RSA)").unwrap()
});

// ─── ECDSA / ECC patterns ────────────────────────────────────────────────────

static ECDSA_P256: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:P.256|prime256v1|secp256r1|NIST\s*P-256|ECDSA_P256|ec\.SECP256R1|elliptic\.P256|CKM_ECDSA.*P.256|NID_X9_62_prime256v1)").unwrap()
});

static ECDSA_P384: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:P.384|secp384r1|NIST\s*P-384|ECDSA_P384|ec\.SECP384R1|elliptic\.P384|NID_secp384r1)").unwrap()
});

static ECDSA_SECP256K1: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:secp256k1|Secp256k1|SECP256K1|NID_secp256k1|ec\.SECP256K1)").unwrap()
});

static ECDSA_GENERIC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:ECDSA|ecdsa|ECDsa|EC_KEY_new|ec\.generate_private_key|ecdsa\.GenerateKey|SigningKey::random|crypto\.createSign.*EC|KeyPairGenerator\.getInstance\s*\(\s*['"]EC['"])"#).unwrap()
});

// ─── Ed25519 / X25519 ───────────────────────────────────────────────────────

static ED25519_USAGE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:Ed25519|ed25519|ED25519|Ed25519PrivateKey|ed25519.dalek|crypto/ed25519|nacl\.sign|tweetnacl.*sign|SigningKey.*Ed25519|EdDSA)").unwrap()
});

static X25519_USAGE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:X25519|x25519|Curve25519|curve25519|nacl\.box|nacl\.secretbox|crypto_box|agreement\.X25519|x25519.dalek)").unwrap()
});

// ─── ECDH patterns ──────────────────────────────────────────────────────────

static ECDH_P256: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:ECDH.*P.256|P.256.*ECDH|KeyAgreement.*EC.*P.256|ecdh.*prime256v1|agreement::ECDH_P256)").unwrap()
});

static ECDH_P384: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:ECDH.*P.384|P.384.*ECDH|KeyAgreement.*EC.*P.384|ecdh.*secp384r1|agreement::ECDH_P384)").unwrap()
});

// ─── DSA / DH ────────────────────────────────────────────────────────────────

static DSA_USAGE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:DSA\.generate|dsa\.generate_private_key|KeyPairGenerator\.getInstance\s*\(\s*['"]DSA['"]|EVP_PKEY_DSA|crypto/dsa)"#).unwrap()
});

static DH_USAGE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:DiffieHellman|diffie.hellman|DH\.generate|dh\.generate_parameters|KeyAgreement\.getInstance\s*\(\s*['"]DH['"]|EVP_PKEY_DH|crypto\.createDiffieHellman)"#).unwrap()
});

// ─── Weak symmetric ciphers ──────────────────────────────────────────────────

static TRIPLE_DES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:3DES|TripleDES|Triple.DES|DESede|des.ede3|DES3|des3|TRIPLE_DES|EVP_des_ede3)").unwrap()
});

static BLOWFISH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:Blowfish|blowfish|BLOWFISH|EVP_bf_|BF_encrypt|BF_decrypt|algorithms\.Blowfish|Cipher\.getInstance\s*\(\s*['"]Blowfish)"#).unwrap()
});

static RC4: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:RC4|rc4|ARC4|arc4|ARCFOUR|arcfour|EVP_rc4|ARC4\.new)").unwrap()
});

// ─── BLS12-381 ───────────────────────────────────────────────────────────────

static BLS12_381: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:BLS12.381|bls12.381|blst|bls_signatures|bls::.*sign|eth2.*bls|beacon.*bls|sync_committee|SyncCommittee|aggregate_signature|AggregateSignature)").unwrap()
});

// ─── Hash function weaknesses ────────────────────────────────────────────────

static SHA1_SIGNING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:SHA1withRSA|SHA1withECDSA|sha1.*sign|sign.*sha1|RSASSA.*SHA1|SHA1_RSA|NID_sha1.*RSA|hashlib\.sha1|Digest::SHA1)").unwrap()
});

static MD5_USAGE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:MD5withRSA|md5.*sign|sign.*md5|MD5_CTX|EVP_md5|hashlib\.md5\s*\(|Digest::MD5|MessageDigest.*MD5|createHash\s*\(\s*['"]md5)"#).unwrap()
});

// ─── Blockchain-specific patterns ────────────────────────────────────────────

static BLOCKCHAIN_TX_SIGN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:signTransaction|sign_transaction|signrawtransaction|eth_signTransaction|personal_sign|eth_sign|wallet\.signMessage|signer\.sign|Wallet\.createRandom|privateKeyToAccount)").unwrap()
});

static ECRECOVER_PRECOMPILE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:ecrecover|ECDSA\.recover|ECDSA\.tryRecover|SignatureChecker|isValidSignatureNow)").unwrap()
});

static GOVERNANCE_CONTRACT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:Governor|GovernorBravo|GovernorAlpha|TimelockController|Timelock|GnosisSafe|Safe\s*\{|MultiSig|multisig|ProxyAdmin|AccessControl.*onlyRole|Ownable.*onlyOwner)").unwrap()
});

static LIGHT_CLIENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:light_client|LightClient|sync_committee|SyncCommittee|beacon.*light|eth/v1/beacon/light_client|light_client_update|LightClientUpdate)").unwrap()
});

// ─── Rust-specific patterns ──────────────────────────────────────────────────

static RUST_RING_RSA: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"ring::signature::RSA|ring::rsa|RsaKeyPair|RSA_PSS|RSA_PKCS1").unwrap()
});

static RUST_RING_ECDSA: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"ring::signature::ECDSA|ECDSA_P256_SHA256|ECDSA_P384_SHA384").unwrap()
});

static RUST_CRYPTO_RSA: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"rsa::(?:RsaPrivateKey|RsaPublicKey|Pkcs1v15|Oaep|pss)").unwrap()
});

static RUST_K256: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"k256::(?:ecdsa|SecretKey|PublicKey|Secp256k1)").unwrap()
});

static RUST_P256: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"p256::(?:ecdsa|SecretKey|PublicKey|NistP256)").unwrap()
});

static RUST_ED25519_DALEK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"ed25519_dalek::(?:SigningKey|VerifyingKey|Signature|Keypair)").unwrap()
});

static RUST_X25519_DALEK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"x25519_dalek::(?:StaticSecret|PublicKey|EphemeralSecret)").unwrap()
});

// ─── Go-specific patterns ────────────────────────────────────────────────────

static GO_RSA_GENERATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"rsa\.GenerateKey\s*\(\s*\w+\s*,\s*(\d+)").unwrap()
});

static GO_ECDSA: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"ecdsa\.GenerateKey\s*\(|ecdsa\.Sign\s*\(|ecdsa\.Verify\s*\(").unwrap()
});

static GO_ED25519: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"ed25519\.GenerateKey|ed25519\.Sign|ed25519\.Verify|ed25519\.NewKeyFromSeed").unwrap()
});

static GO_TLS_CONFIG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"tls\.Config\s*\{|CipherSuites\s*:\s*\[|MinVersion\s*:\s*tls\.").unwrap()
});

// ─── Python-specific patterns ────────────────────────────────────────────────

static PYTHON_RSA_GENERATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"rsa\.generate_private_key\s*\(|RSA\.generate\s*\(|generate_key\s*\(\s*crypto\.TYPE_RSA").unwrap()
});

static PYTHON_EC_GENERATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"ec\.generate_private_key\s*\(|ECC\.generate\s*\(").unwrap()
});

static PYTHON_ED25519: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Ed25519PrivateKey\.generate|ed25519\.Ed25519PrivateKey|nacl\.signing\.SigningKey").unwrap()
});

// ─── Java-specific patterns ──────────────────────────────────────────────────

static JAVA_KEYPAIR_RSA: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"KeyPairGenerator\.getInstance\s*\(\s*"RSA""#).unwrap()
});

static JAVA_KEYPAIR_EC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"KeyPairGenerator\.getInstance\s*\(\s*"EC""#).unwrap()
});

static JAVA_CIPHER_DES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"Cipher\.getInstance\s*\(\s*"(?:DESede|DES)"#).unwrap()
});

static JAVA_KEY_AGREEMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"KeyAgreement\.getInstance\s*\(\s*"(?:ECDH|DH)""#).unwrap()
});

// ─── JavaScript / TypeScript patterns ────────────────────────────────────────

static JS_CRYPTO_CREATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"crypto\.create(?:Sign|Verify|Cipher|Decipher|DiffieHellman|ECDH)\s*\(").unwrap()
});

static JS_WEBCRYPTO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:subtle\.generateKey|subtle\.importKey|subtle\.sign|subtle\.verify)\s*\(\s*\{?\s*name\s*:\s*['"](?:RSASSA-PKCS1-v1_5|RSA-PSS|RSA-OAEP|ECDSA|ECDH)['"]"#).unwrap()
});

static JS_NODE_RSA: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:new\s+NodeRSA|generateKeyPairSync\s*\(\s*['"]rsa['"])"#).unwrap()
});

// ─── Solidity-specific patterns ──────────────────────────────────────────────

static SOL_ECRECOVER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"ecrecover\s*\(|ECDSA\.recover\s*\(|ECDSA\.tryRecover\s*\(|SignatureChecker\.isValidSignatureNow").unwrap()
});

static SOL_PRECOMPILE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:address\s*\(\s*(?:0x01|0x08|0x0[aA])\s*\)|staticcall\s*\(\s*(?:gas\s*\(\s*\)\s*,\s*)?(?:0x01|0x08|0x0[aA]))").unwrap()
});

// ─── OpenSSL / config patterns ───────────────────────────────────────────────

static OPENSSL_CIPHER_STRING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:CipherString|Ciphersuites|ssl_cipher|SSLCipherSuite)\s*[=:]\s*(.+)").unwrap()
});

static OPENSSL_RSA_KEYGEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:EVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_RSA|RSA_generate_key_ex|EVP_PKEY_CTX_set_rsa_keygen_bits)").unwrap()
});

static OPENSSL_EC_KEYGEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:EVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_EC|EC_KEY_new_by_curve_name|EVP_PKEY_CTX_set_ec_paramgen_curve_nid)").unwrap()
});

// ─── PEM header patterns ─────────────────────────────────────────────────────

static PEM_RSA_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN\s+RSA\s+(?:PRIVATE|PUBLIC)\s+KEY-----").unwrap()
});

static PEM_EC_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN\s+EC\s+(?:PRIVATE|PUBLIC)?\s*(?:KEY|PARAMETERS)-----").unwrap()
});

static PEM_DSA_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN\s+DSA\s+(?:PRIVATE|PUBLIC)\s+KEY-----").unwrap()
});

static PEM_CERTIFICATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN\s+CERTIFICATE-----").unwrap()
});

// ─── Language-scoped rule sets ───────────────────────────────────────────────

/// All detection rules. Each rule specifies which languages it applies to.
/// An empty languages slice means it applies to all languages.
pub static ALL_RULES: LazyLock<Vec<DetectionRule>> = LazyLock::new(|| {
    vec![
        // ── RSA ──
        DetectionRule {
            pattern: &RSA_2048_KEY_SIZE,
            primitive: CryptoPrimitive::Rsa2048,
            description: "RSA-2048 key size detected",
            languages: &[],
        },
        DetectionRule {
            pattern: &RSA_4096_KEY_SIZE,
            primitive: CryptoPrimitive::Rsa4096,
            description: "RSA-4096 key size detected",
            languages: &[],
        },
        DetectionRule {
            pattern: &RSA_GENERATE_2048,
            primitive: CryptoPrimitive::Rsa2048,
            description: "RSA-2048 key generation",
            languages: &[],
        },
        DetectionRule {
            pattern: &RSA_GENERATE_4096,
            primitive: CryptoPrimitive::Rsa4096,
            description: "RSA-4096 key generation",
            languages: &[],
        },
        DetectionRule {
            pattern: &RSA_GENERIC_IMPORT,
            primitive: CryptoPrimitive::RsaGeneric,
            description: "RSA cryptography import/usage",
            languages: &[],
        },
        DetectionRule {
            pattern: &RSA_PKCS1_SIGN,
            primitive: CryptoPrimitive::RsaPkcs1v15,
            description: "RSA PKCS#1 v1.5 signature scheme",
            languages: &[],
        },
        // ── ECDSA / ECC ──
        DetectionRule {
            pattern: &ECDSA_P256,
            primitive: CryptoPrimitive::EcdsaP256,
            description: "ECDSA P-256 / prime256v1 curve usage",
            languages: &[],
        },
        DetectionRule {
            pattern: &ECDSA_P384,
            primitive: CryptoPrimitive::EcdsaP384,
            description: "ECDSA P-384 curve usage",
            languages: &[],
        },
        DetectionRule {
            pattern: &ECDSA_SECP256K1,
            primitive: CryptoPrimitive::EcdsaSecp256k1,
            description: "ECDSA secp256k1 curve usage (blockchain)",
            languages: &[],
        },
        DetectionRule {
            pattern: &ECDSA_GENERIC,
            primitive: CryptoPrimitive::EcdsaGeneric,
            description: "ECDSA usage (unspecified curve)",
            languages: &[],
        },
        // ── Ed25519 / X25519 ──
        DetectionRule {
            pattern: &ED25519_USAGE,
            primitive: CryptoPrimitive::Ed25519,
            description: "Ed25519 signature scheme usage",
            languages: &[],
        },
        DetectionRule {
            pattern: &X25519_USAGE,
            primitive: CryptoPrimitive::X25519,
            description: "X25519 / Curve25519 key exchange",
            languages: &[],
        },
        // ── ECDH ──
        DetectionRule {
            pattern: &ECDH_P256,
            primitive: CryptoPrimitive::EcdhP256,
            description: "ECDH P-256 key agreement",
            languages: &[],
        },
        DetectionRule {
            pattern: &ECDH_P384,
            primitive: CryptoPrimitive::EcdhP384,
            description: "ECDH P-384 key agreement",
            languages: &[],
        },
        // ── DSA / DH ──
        DetectionRule {
            pattern: &DSA_USAGE,
            primitive: CryptoPrimitive::Dsa,
            description: "DSA signature algorithm usage",
            languages: &[],
        },
        DetectionRule {
            pattern: &DH_USAGE,
            primitive: CryptoPrimitive::Dh,
            description: "Diffie-Hellman key exchange",
            languages: &[],
        },
        // ── Weak symmetric ──
        DetectionRule {
            pattern: &TRIPLE_DES,
            primitive: CryptoPrimitive::TripleDes,
            description: "3DES / Triple DES symmetric cipher",
            languages: &[],
        },
        DetectionRule {
            pattern: &BLOWFISH,
            primitive: CryptoPrimitive::Blowfish,
            description: "Blowfish symmetric cipher",
            languages: &[],
        },
        DetectionRule {
            pattern: &RC4,
            primitive: CryptoPrimitive::Rc4,
            description: "RC4 stream cipher",
            languages: &[],
        },
        // ── BLS12-381 ──
        DetectionRule {
            pattern: &BLS12_381,
            primitive: CryptoPrimitive::Bls12381,
            description: "BLS12-381 aggregate signature scheme",
            languages: &[],
        },
        // ── Weak hashes in signing ──
        DetectionRule {
            pattern: &SHA1_SIGNING,
            primitive: CryptoPrimitive::Sha1Signing,
            description: "SHA-1 used in digital signatures",
            languages: &[],
        },
        DetectionRule {
            pattern: &MD5_USAGE,
            primitive: CryptoPrimitive::Md5,
            description: "MD5 hash function usage",
            languages: &[],
        },
        // ── Blockchain-specific ──
        DetectionRule {
            pattern: &BLOCKCHAIN_TX_SIGN,
            primitive: CryptoPrimitive::EcdsaSecp256k1,
            description: "Blockchain transaction signing (secp256k1)",
            languages: &[Language::JavaScript, Language::TypeScript, Language::Python, Language::Go, Language::Rust],
        },
        DetectionRule {
            pattern: &ECRECOVER_PRECOMPILE,
            primitive: CryptoPrimitive::EcdsaSecp256k1,
            description: "ecrecover precompile — on-chain ECDSA signature verification",
            languages: &[Language::Solidity, Language::JavaScript, Language::TypeScript],
        },
        DetectionRule {
            pattern: &GOVERNANCE_CONTRACT,
            primitive: CryptoPrimitive::EcdsaSecp256k1,
            description: "Governance/multisig contract — systemic quantum risk",
            languages: &[Language::Solidity],
        },
        DetectionRule {
            pattern: &LIGHT_CLIENT,
            primitive: CryptoPrimitive::Bls12381,
            description: "Light client / sync committee — BLS12-381 aggregate signatures",
            languages: &[Language::Rust, Language::Go, Language::TypeScript, Language::JavaScript, Language::Python],
        },
        // ── Rust-specific ──
        DetectionRule {
            pattern: &RUST_RING_RSA,
            primitive: CryptoPrimitive::RsaGeneric,
            description: "ring RSA usage",
            languages: &[Language::Rust],
        },
        DetectionRule {
            pattern: &RUST_RING_ECDSA,
            primitive: CryptoPrimitive::EcdsaP256,
            description: "ring ECDSA usage",
            languages: &[Language::Rust],
        },
        DetectionRule {
            pattern: &RUST_CRYPTO_RSA,
            primitive: CryptoPrimitive::RsaGeneric,
            description: "RustCrypto rsa crate usage",
            languages: &[Language::Rust],
        },
        DetectionRule {
            pattern: &RUST_K256,
            primitive: CryptoPrimitive::EcdsaSecp256k1,
            description: "k256 (secp256k1) crate usage",
            languages: &[Language::Rust],
        },
        DetectionRule {
            pattern: &RUST_P256,
            primitive: CryptoPrimitive::EcdsaP256,
            description: "p256 (NIST P-256) crate usage",
            languages: &[Language::Rust],
        },
        DetectionRule {
            pattern: &RUST_ED25519_DALEK,
            primitive: CryptoPrimitive::Ed25519,
            description: "ed25519-dalek crate usage",
            languages: &[Language::Rust],
        },
        DetectionRule {
            pattern: &RUST_X25519_DALEK,
            primitive: CryptoPrimitive::X25519,
            description: "x25519-dalek crate usage",
            languages: &[Language::Rust],
        },
        // ── Go-specific ──
        DetectionRule {
            pattern: &GO_RSA_GENERATE,
            primitive: CryptoPrimitive::RsaGeneric,
            description: "Go crypto/rsa key generation",
            languages: &[Language::Go],
        },
        DetectionRule {
            pattern: &GO_ECDSA,
            primitive: CryptoPrimitive::EcdsaGeneric,
            description: "Go crypto/ecdsa usage",
            languages: &[Language::Go],
        },
        DetectionRule {
            pattern: &GO_ED25519,
            primitive: CryptoPrimitive::Ed25519,
            description: "Go crypto/ed25519 usage",
            languages: &[Language::Go],
        },
        DetectionRule {
            pattern: &GO_TLS_CONFIG,
            primitive: CryptoPrimitive::RsaGeneric,
            description: "Go TLS configuration (may use RSA/ECDSA cipher suites)",
            languages: &[Language::Go],
        },
        // ── Python-specific ──
        DetectionRule {
            pattern: &PYTHON_RSA_GENERATE,
            primitive: CryptoPrimitive::RsaGeneric,
            description: "Python RSA key generation",
            languages: &[Language::Python],
        },
        DetectionRule {
            pattern: &PYTHON_EC_GENERATE,
            primitive: CryptoPrimitive::EcdsaGeneric,
            description: "Python EC key generation",
            languages: &[Language::Python],
        },
        DetectionRule {
            pattern: &PYTHON_ED25519,
            primitive: CryptoPrimitive::Ed25519,
            description: "Python Ed25519 key generation",
            languages: &[Language::Python],
        },
        // ── Java-specific ──
        DetectionRule {
            pattern: &JAVA_KEYPAIR_RSA,
            primitive: CryptoPrimitive::RsaGeneric,
            description: "Java RSA KeyPairGenerator",
            languages: &[Language::Java],
        },
        DetectionRule {
            pattern: &JAVA_KEYPAIR_EC,
            primitive: CryptoPrimitive::EcdsaGeneric,
            description: "Java EC KeyPairGenerator",
            languages: &[Language::Java],
        },
        DetectionRule {
            pattern: &JAVA_CIPHER_DES,
            primitive: CryptoPrimitive::TripleDes,
            description: "Java DES/DESede Cipher",
            languages: &[Language::Java],
        },
        DetectionRule {
            pattern: &JAVA_KEY_AGREEMENT,
            primitive: CryptoPrimitive::Dh,
            description: "Java ECDH/DH KeyAgreement",
            languages: &[Language::Java],
        },
        // ── JavaScript / TypeScript ──
        DetectionRule {
            pattern: &JS_CRYPTO_CREATE,
            primitive: CryptoPrimitive::RsaGeneric,
            description: "Node.js crypto module sign/verify/cipher",
            languages: &[Language::JavaScript, Language::TypeScript],
        },
        DetectionRule {
            pattern: &JS_WEBCRYPTO,
            primitive: CryptoPrimitive::RsaGeneric,
            description: "WebCrypto API key generation / signing",
            languages: &[Language::JavaScript, Language::TypeScript],
        },
        DetectionRule {
            pattern: &JS_NODE_RSA,
            primitive: CryptoPrimitive::RsaGeneric,
            description: "Node RSA key generation",
            languages: &[Language::JavaScript, Language::TypeScript],
        },
        // ── Solidity ──
        DetectionRule {
            pattern: &SOL_ECRECOVER,
            primitive: CryptoPrimitive::EcdsaSecp256k1,
            description: "Solidity ecrecover / ECDSA.recover",
            languages: &[Language::Solidity],
        },
        DetectionRule {
            pattern: &SOL_PRECOMPILE,
            primitive: CryptoPrimitive::EcdsaSecp256k1,
            description: "EVM precompile call (ecrecover/BN254/KZG)",
            languages: &[Language::Solidity],
        },
        // ── OpenSSL / config ──
        DetectionRule {
            pattern: &OPENSSL_CIPHER_STRING,
            primitive: CryptoPrimitive::RsaGeneric,
            description: "OpenSSL cipher suite configuration",
            languages: &[Language::OpenSslConfig, Language::C, Language::Cpp],
        },
        DetectionRule {
            pattern: &OPENSSL_RSA_KEYGEN,
            primitive: CryptoPrimitive::RsaGeneric,
            description: "OpenSSL EVP RSA key generation",
            languages: &[Language::C, Language::Cpp],
        },
        DetectionRule {
            pattern: &OPENSSL_EC_KEYGEN,
            primitive: CryptoPrimitive::EcdsaGeneric,
            description: "OpenSSL EVP EC key generation",
            languages: &[Language::C, Language::Cpp],
        },
        // ── PEM headers ──
        DetectionRule {
            pattern: &PEM_RSA_KEY,
            primitive: CryptoPrimitive::RsaGeneric,
            description: "PEM-encoded RSA key",
            languages: &[],
        },
        DetectionRule {
            pattern: &PEM_EC_KEY,
            primitive: CryptoPrimitive::EcdsaGeneric,
            description: "PEM-encoded EC key",
            languages: &[],
        },
        DetectionRule {
            pattern: &PEM_DSA_KEY,
            primitive: CryptoPrimitive::Dsa,
            description: "PEM-encoded DSA key",
            languages: &[],
        },
        DetectionRule {
            pattern: &PEM_CERTIFICATE,
            primitive: CryptoPrimitive::RsaGeneric,
            description: "PEM-encoded X.509 certificate (algorithm unknown without parsing)",
            languages: &[],
        },
    ]
});

/// Get rules applicable to a given language.
pub fn rules_for_language(lang: Language) -> Vec<&'static DetectionRule> {
    ALL_RULES
        .iter()
        .filter(|rule| rule.languages.is_empty() || rule.languages.contains(&lang))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_2048_patterns() {
        let re = &*RSA_2048_KEY_SIZE;
        assert!(re.is_match("key_size = 2048"));
        assert!(re.is_match("bits: 2048"));
        assert!(re.is_match("modulus_size=2048"));
        assert!(!re.is_match("key_size = 4096"));
    }

    #[test]
    fn test_secp256k1_pattern() {
        let re = &*ECDSA_SECP256K1;
        assert!(re.is_match("use k256::Secp256k1;"));
        assert!(re.is_match("ec.SECP256K1()"));
        assert!(re.is_match("NID_secp256k1"));
    }

    #[test]
    fn test_ed25519_pattern() {
        let re = &*ED25519_USAGE;
        assert!(re.is_match("Ed25519PrivateKey.generate()"));
        assert!(re.is_match("use ed25519_dalek::SigningKey;"));
        assert!(re.is_match("import \"crypto/ed25519\""));
    }

    #[test]
    fn test_blockchain_tx_sign() {
        let re = &*BLOCKCHAIN_TX_SIGN;
        assert!(re.is_match("web3.eth.accounts.signTransaction(tx)"));
        assert!(re.is_match("wallet.signMessage(msg)"));
        assert!(re.is_match("signer.sign(data)"));
    }

    #[test]
    fn test_governance_contract() {
        let re = &*GOVERNANCE_CONTRACT;
        assert!(re.is_match("contract MyGovernor is Governor {"));
        assert!(re.is_match("contract GnosisSafe {"));
        assert!(re.is_match("TimelockController"));
    }

    #[test]
    fn test_pem_headers() {
        let re = &*PEM_RSA_KEY;
        assert!(re.is_match("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(re.is_match("-----BEGIN RSA PUBLIC KEY-----"));
    }

    #[test]
    fn test_rules_for_language() {
        let rust_rules = rules_for_language(Language::Rust);
        // Should include universal rules + Rust-specific rules
        assert!(rust_rules.len() > 20);

        let sol_rules = rules_for_language(Language::Solidity);
        // Solidity has fewer but includes universal + solidity-specific
        assert!(sol_rules.len() > 15);
    }

    #[test]
    fn test_all_rules_compile() {
        // Force lazy initialization of all patterns
        let count = ALL_RULES.len();
        assert!(count > 50, "Expected 50+ rules, got {count}");
    }

    #[test]
    fn test_openssl_config_pattern() {
        let re = &*OPENSSL_CIPHER_STRING;
        assert!(re.is_match("CipherString = ECDHE-RSA-AES128-GCM-SHA256"));
        assert!(re.is_match("Ciphersuites = TLS_AES_256_GCM_SHA384"));
    }

    #[test]
    fn test_java_patterns() {
        assert!(JAVA_KEYPAIR_RSA.is_match(r#"KeyPairGenerator.getInstance("RSA")"#));
        assert!(JAVA_KEYPAIR_EC.is_match(r#"KeyPairGenerator.getInstance("EC")"#));
        assert!(JAVA_CIPHER_DES.is_match(r#"Cipher.getInstance("DESede")"#));
    }
}
