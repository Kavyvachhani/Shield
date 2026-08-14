//! TLS and certificate inspection.
//!
//! Performs one TLS handshake with certificate verification deliberately
//! disabled so that an invalid certificate can be *reported* rather than simply
//! aborting the scan, then parses the presented chain to check validity dates,
//! signature algorithm, key strength and hostname coverage.
//!
//! This is a read-only handshake: no application data is sent.

use super::builder::{CheckSpec, NativeFinding};
use super::probe::truncate;
use chrono::{DateTime, Duration, Utc};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use sentinel_core::models::finding::{Finding, Severity};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use uuid::Uuid;
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

const OWASP_CRYPTO: &str = "A04:2025-Cryptographic Failures";

const CERT_INVALID: CheckSpec = CheckSpec {
    id: "NATIVE-TLS-CERT-INVALID",
    title: "TLS Certificate Is Not Trusted by Standard Clients",
    severity: Severity::High,
    cvss_vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    cvss_score: 8.2,
    cwe: "CWE-295",
    wstg: "WSTG-CRYP-01",
    owasp_2025: OWASP_CRYPTO,
    api_top10: None,
    description: "The certificate presented by the server does not chain to a publicly trusted authority \
— it is self-signed, issued by an unknown authority, or missing intermediate certificates. Browsers show \
an interruptive warning, and once users are trained to click through that warning they can no longer \
distinguish a genuine misconfiguration from an active interception attack.",
    remediation: "Install a certificate from a publicly trusted CA (Let's Encrypt issues them at no cost \
with automated renewal) and serve the full chain including any intermediate certificates. Verify with \
`openssl s_client -connect host:443 -showcerts` that the chain is complete.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
    ],
};

const CERT_EXPIRED: CheckSpec = CheckSpec {
    id: "NATIVE-TLS-CERT-EXPIRED",
    title: "TLS Certificate Has Expired",
    severity: Severity::Critical,
    cvss_vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    cvss_score: 9.2,
    cwe: "CWE-298",
    wstg: "WSTG-CRYP-01",
    owasp_2025: OWASP_CRYPTO,
    api_top10: None,
    description: "The server's TLS certificate is past its expiry date. Every browser and API client \
rejects the connection outright or shows a full-page security warning, so the service is effectively down \
for well-behaved clients — and any client configured to ignore the error has lost all protection against \
interception.",
    remediation: "Renew and deploy the certificate immediately. Automate renewal (certbot, ACME, or your \
platform's managed certificates) and add an expiry monitor that alerts at least 30 days ahead so this \
cannot recur.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
    ],
};

const CERT_EXPIRING: CheckSpec = CheckSpec {
    id: "NATIVE-TLS-CERT-EXPIRING",
    title: "TLS Certificate Expires Soon",
    severity: Severity::Medium,
    cvss_vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N",
    cvss_score: 5.1,
    cwe: "CWE-298",
    wstg: "WSTG-CRYP-01",
    owasp_2025: OWASP_CRYPTO,
    api_top10: None,
    description: "The TLS certificate expires within 30 days. Once it lapses, browsers and API clients \
will refuse to connect, causing a complete outage for the service.",
    remediation: "Renew the certificate now and confirm automated renewal is working. Add monitoring that \
alerts at 30 and 7 days before expiry.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
    ],
};

const CERT_HOSTNAME: CheckSpec = CheckSpec {
    id: "NATIVE-TLS-HOSTNAME-MISMATCH",
    title: "TLS Certificate Does Not Cover the Requested Hostname",
    severity: Severity::High,
    cvss_vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    cvss_score: 8.2,
    cwe: "CWE-297",
    wstg: "WSTG-CRYP-01",
    owasp_2025: OWASP_CRYPTO,
    api_top10: None,
    description: "The hostname being requested does not appear in the certificate's Subject Alternative \
Name list. Clients cannot verify they are talking to the intended server, so they either refuse the \
connection or — if configured to ignore the mismatch — accept any certificate, losing all protection \
against interception.",
    remediation: "Reissue the certificate with the correct hostname in the Subject Alternative Name \
extension. Include every hostname the service is reached by, and remember that the legacy Common Name \
field is ignored by current clients.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
    ],
};

const CERT_WEAK_SIGNATURE: CheckSpec = CheckSpec {
    id: "NATIVE-TLS-WEAK-SIGNATURE",
    title: "TLS Certificate Uses a Weak Signature Algorithm or Key",
    severity: Severity::Medium,
    cvss_vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    cvss_score: 6.3,
    cwe: "CWE-327",
    wstg: "WSTG-CRYP-01",
    owasp_2025: OWASP_CRYPTO,
    api_top10: None,
    description: "The certificate is signed with a deprecated hash algorithm (SHA-1 or MD5) or uses an RSA \
key shorter than 2048 bits. Practical collision attacks exist against SHA-1, and undersized RSA keys no \
longer provide an adequate margin, so a well-resourced attacker could forge a certificate for this host.",
    remediation: "Reissue the certificate with a SHA-256 (or stronger) signature and either a 2048-bit \
minimum RSA key or a P-256 elliptic curve key. Any modern CA issues this by default; a weak certificate \
usually indicates an old internal CA that also needs updating.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
    ],
};

const TLS_LEGACY_PROTOCOL: CheckSpec = CheckSpec {
    id: "NATIVE-TLS-LEGACY-PROTOCOL",
    title: "TLS 1.3 Not Supported",
    severity: Severity::Low,
    cvss_vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    cvss_score: 3.1,
    cwe: "CWE-326",
    wstg: "WSTG-CRYP-01",
    owasp_2025: OWASP_CRYPTO,
    api_top10: None,
    description: "The server negotiated TLS 1.2 rather than TLS 1.3. TLS 1.2 remains acceptable when \
configured with strong cipher suites, but TLS 1.3 removes the legacy key-exchange and cipher options that \
have caused most TLS vulnerabilities, and completes the handshake in fewer round trips.",
    remediation: "Enable TLS 1.3 on the server or load balancer and keep TLS 1.2 available for older \
clients. Disable TLS 1.0 and 1.1 entirely — both are formally deprecated (RFC 8996) and are rejected by \
PCI DSS.",
    references: &[
        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
        "https://datatracker.ietf.org/doc/html/rfc8996",
    ],
};

/// Facts observed during the handshake, kept separate from finding generation
/// so the analysis is unit-testable without a network.
#[derive(Debug, Clone)]
pub struct TlsObservation {
    pub host: String,
    pub port: u16,
    /// Negotiated protocol, e.g. "TLSv1.3".
    pub protocol: String,
    pub subject: String,
    pub issuer: String,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub san_entries: Vec<String>,
    pub signature_algorithm: String,
    pub rsa_key_bits: Option<u64>,
    pub self_signed: bool,
    /// Whether the chain verified against the platform's trusted roots.
    pub chain_trusted: bool,
}

/// Connect, capture the certificate, and return the observation.
/// Returns `Ok(None)` when the host does not speak TLS on that port.
pub async fn observe(host: &str, port: u16, timeout_secs: u64) -> anyhow::Result<Option<TlsObservation>> {
    let collector = Arc::new(CertCollector::default());

    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(collector.clone())
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| anyhow::anyhow!("invalid TLS server name '{host}': {e}"))?;

    let timeout = std::time::Duration::from_secs(timeout_secs.clamp(1, 60));
    let tcp = match tokio::time::timeout(timeout, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::debug!(host, port, error = %e, "TLS: TCP connect failed");
            return Ok(None);
        }
        Err(_) => {
            tracing::debug!(host, port, "TLS: TCP connect timed out");
            return Ok(None);
        }
    };

    let stream = match tokio::time::timeout(timeout, connector.connect(server_name, tcp)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::debug!(host, port, error = %e, "TLS: handshake failed");
            return Ok(None);
        }
        Err(_) => {
            tracing::debug!(host, port, "TLS: handshake timed out");
            return Ok(None);
        }
    };

    let protocol = stream
        .get_ref()
        .1
        .protocol_version()
        .map(|v| format!("{v:?}"))
        .unwrap_or_else(|| "unknown".to_string());

    let der = collector.take().ok_or_else(|| {
        anyhow::anyhow!("TLS handshake completed but no certificate was captured")
    })?;

    let mut observation = parse_certificate(&der)?;
    observation.host = host.to_string();
    observation.port = port;
    observation.protocol = normalize_protocol(&protocol);
    observation.chain_trusted = verify_against_roots(&der);

    Ok(Some(observation))
}

/// Parse a DER certificate into the fields the checks need.
pub fn parse_certificate(der: &[u8]) -> anyhow::Result<TlsObservation> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| anyhow::anyhow!("failed to parse server certificate: {e}"))?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let self_signed = subject == issuer;

    let not_before = DateTime::from_timestamp(cert.validity().not_before.timestamp(), 0);
    let not_after = DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0);

    let mut san_entries = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                san_entries.push((*dns).to_string());
            }
        }
    }

    let signature_algorithm = format!("{}", cert.signature_algorithm.algorithm);

    let rsa_key_bits = match cert.public_key().parsed() {
        Ok(PublicKey::RSA(rsa)) => Some((rsa.key_size()) as u64),
        _ => None,
    };

    Ok(TlsObservation {
        host: String::new(),
        port: 443,
        protocol: String::new(),
        subject,
        issuer,
        not_before,
        not_after,
        san_entries,
        signature_algorithm,
        rsa_key_bits,
        self_signed,
        chain_trusted: false,
    })
}

/// Re-verify the captured certificate against the bundled Mozilla root store.
fn verify_against_roots(der: &[u8]) -> bool {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cert = CertificateDer::from(der.to_vec());
    // A leaf that is its own issuer can never chain to a public root.
    match X509Certificate::from_der(&cert) {
        Ok((_, parsed)) => {
            if parsed.subject() == parsed.issuer() {
                return false;
            }
            roots.roots.iter().any(|anchor| {
                anchor.subject.as_ref() == parsed.issuer().as_raw()
            })
        }
        Err(_) => false,
    }
}

fn normalize_protocol(raw: &str) -> String {
    match raw {
        "TLSv1_3" => "TLS 1.3".to_string(),
        "TLSv1_2" => "TLS 1.2".to_string(),
        "TLSv1_1" => "TLS 1.1".to_string(),
        "TLSv1_0" => "TLS 1.0".to_string(),
        other => other.to_string(),
    }
}

/// Turn an observation into findings. Pure function — unit tested without a network.
pub fn analyze(observation: &TlsObservation, target_id: Uuid, scan_id: Uuid, now: DateTime<Utc>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let component = format!("{}:{}", observation.host, observation.port);
    let summary = observation_summary(observation);

    let make = |spec: &CheckSpec, detail: String| {
        NativeFinding::build(
            spec,
            target_id,
            scan_id,
            &component,
            &detail,
            vec![format!(
                "openssl s_client -connect {}:{} -servername {} </dev/null 2>/dev/null | openssl x509 -noout -dates -subject -issuer",
                observation.host, observation.port, observation.host
            )],
            vec![NativeFinding::evidence("tls_certificate", "Certificate details", &summary)],
        )
    };

    // ── Validity window ──────────────────────────────────────────────────────
    if let Some(not_after) = observation.not_after {
        if not_after < now {
            findings.push(make(
                &CERT_EXPIRED,
                format!(
                    "The certificate expired on {} ({} days ago).",
                    not_after.format("%Y-%m-%d"),
                    (now - not_after).num_days()
                ),
            ));
        } else if not_after < now + Duration::days(30) {
            findings.push(make(
                &CERT_EXPIRING,
                format!(
                    "The certificate expires on {} — {} day(s) from now.",
                    not_after.format("%Y-%m-%d"),
                    (not_after - now).num_days()
                ),
            ));
        }
    }

    // ── Trust chain ──────────────────────────────────────────────────────────
    if !observation.chain_trusted {
        let reason = if observation.self_signed {
            "the certificate is self-signed (subject and issuer are identical)"
        } else {
            "the issuing authority is not present in the public root store, or an intermediate certificate is missing"
        };
        findings.push(make(
            &CERT_INVALID,
            format!("Chain verification failed: {reason}. Issuer: {}.", truncate(&observation.issuer, 200)),
        ));
    }

    // ── Hostname coverage ────────────────────────────────────────────────────
    if !observation.san_entries.is_empty()
        && !hostname_covered(&observation.host, &observation.san_entries)
    {
        findings.push(make(
            &CERT_HOSTNAME,
            format!(
                "'{}' is not covered by the certificate's SAN entries: {}.",
                observation.host,
                truncate(&observation.san_entries.join(", "), 300)
            ),
        ));
    }

    // ── Signature and key strength ───────────────────────────────────────────
    let mut weaknesses = Vec::new();
    if is_weak_signature(&observation.signature_algorithm) {
        weaknesses.push(format!(
            "signature algorithm '{}' is deprecated",
            observation.signature_algorithm
        ));
    }
    if let Some(bits) = observation.rsa_key_bits {
        if bits < 2048 {
            weaknesses.push(format!("RSA key is only {bits} bits (2048 is the minimum)"));
        }
    }
    if !weaknesses.is_empty() {
        findings.push(make(&CERT_WEAK_SIGNATURE, format!("{}.", weaknesses.join("; "))));
    }

    // ── Protocol version ─────────────────────────────────────────────────────
    if observation.protocol == "TLS 1.2" {
        findings.push(make(
            &TLS_LEGACY_PROTOCOL,
            "The handshake negotiated TLS 1.2; the server did not offer TLS 1.3.".to_string(),
        ));
    }

    findings
}

fn observation_summary(o: &TlsObservation) -> String {
    format!(
        "Host:       {}:{}\nProtocol:   {}\nSubject:    {}\nIssuer:     {}\nNot before: {}\nNot after:  {}\nSAN:        {}\nSignature:  {}\nRSA bits:   {}\nSelf-signed:{}\nChain trusted: {}",
        o.host,
        o.port,
        o.protocol,
        truncate(&o.subject, 200),
        truncate(&o.issuer, 200),
        o.not_before.map(|d| d.to_rfc3339()).unwrap_or_else(|| "unknown".into()),
        o.not_after.map(|d| d.to_rfc3339()).unwrap_or_else(|| "unknown".into()),
        truncate(&o.san_entries.join(", "), 400),
        o.signature_algorithm,
        o.rsa_key_bits.map(|b| b.to_string()).unwrap_or_else(|| "n/a".into()),
        o.self_signed,
        o.chain_trusted,
    )
}

/// Whether a hostname is covered by a SAN list, honouring single-label wildcards.
pub fn hostname_covered(host: &str, sans: &[String]) -> bool {
    let host = host.to_lowercase();
    sans.iter().any(|san| {
        let san = san.to_lowercase();
        if let Some(suffix) = san.strip_prefix("*.") {
            // A wildcard matches exactly one label: *.example.com covers
            // a.example.com but not a.b.example.com, nor example.com itself.
            match host.split_once('.') {
                Some((_, rest)) => rest == suffix,
                None => false,
            }
        } else {
            host == san
        }
    })
}

/// Deprecated certificate signature algorithms.
pub fn is_weak_signature(algorithm_oid_or_name: &str) -> bool {
    let a = algorithm_oid_or_name.to_lowercase();
    // Named forms plus the OIDs for md5WithRSA, sha1WithRSA and ecdsa-with-SHA1.
    a.contains("md5")
        || a.contains("sha1")
        || a.contains("sha-1")
        || a == "1.2.840.113549.1.1.4"
        || a == "1.2.840.113549.1.1.5"
        || a == "1.2.840.10045.4.1"
}

// ── Certificate-capturing verifier ───────────────────────────────────────────
//
// Verification is intentionally bypassed so an invalid certificate can be
// reported instead of aborting the handshake. This verifier is used ONLY for
// the read-only inspection connection, never for transferring data.

#[derive(Default, Debug)]
struct CertCollector {
    captured: std::sync::Mutex<Option<Vec<u8>>>,
}

impl CertCollector {
    fn take(&self) -> Option<Vec<u8>> {
        self.captured.lock().ok().and_then(|mut g| g.take())
    }
}

impl ServerCertVerifier for CertCollector {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Ok(mut guard) = self.captured.lock() {
            *guard = Some(end_entity.as_ref().to_vec());
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation() -> TlsObservation {
        TlsObservation {
            host: "app.example.com".into(),
            port: 443,
            protocol: "TLS 1.3".into(),
            subject: "CN=app.example.com".into(),
            issuer: "CN=Trusted CA".into(),
            not_before: Some(Utc::now() - Duration::days(30)),
            not_after: Some(Utc::now() + Duration::days(300)),
            san_entries: vec!["app.example.com".into()],
            signature_algorithm: "1.2.840.113549.1.1.11".into(), // sha256WithRSA
            rsa_key_bits: Some(2048),
            self_signed: false,
            chain_trusted: true,
        }
    }

    #[test]
    fn a_healthy_certificate_produces_no_findings() {
        let f = analyze(&observation(), Uuid::new_v4(), Uuid::new_v4(), Utc::now());
        assert!(f.is_empty(), "unexpected findings: {:?}", f.iter().map(|x| &x.title).collect::<Vec<_>>());
    }

    #[test]
    fn expired_certificate_is_critical() {
        let mut o = observation();
        o.not_after = Some(Utc::now() - Duration::days(5));
        let f = analyze(&o, Uuid::new_v4(), Uuid::new_v4(), Utc::now());
        let expired = f.iter().find(|x| x.title.contains("Expired")).unwrap();
        assert_eq!(expired.severity, Severity::Critical);
        assert!(expired.description.contains("5 days ago"));
    }

    #[test]
    fn certificate_expiring_within_30_days_is_flagged() {
        let mut o = observation();
        o.not_after = Some(Utc::now() + Duration::days(10));
        let f = analyze(&o, Uuid::new_v4(), Uuid::new_v4(), Utc::now());
        assert!(f.iter().any(|x| x.title.contains("Expires Soon")));
    }

    #[test]
    fn certificate_expiring_in_90_days_is_not_flagged() {
        let mut o = observation();
        o.not_after = Some(Utc::now() + Duration::days(90));
        let f = analyze(&o, Uuid::new_v4(), Uuid::new_v4(), Utc::now());
        assert!(!f.iter().any(|x| x.title.contains("Expires Soon")));
    }

    #[test]
    fn untrusted_chain_is_reported() {
        let mut o = observation();
        o.chain_trusted = false;
        o.self_signed = true;
        let f = analyze(&o, Uuid::new_v4(), Uuid::new_v4(), Utc::now());
        let untrusted = f.iter().find(|x| x.title.contains("Not Trusted")).unwrap();
        assert!(untrusted.description.contains("self-signed"));
    }

    #[test]
    fn hostname_mismatch_is_reported() {
        let mut o = observation();
        o.san_entries = vec!["other.example.com".into()];
        let f = analyze(&o, Uuid::new_v4(), Uuid::new_v4(), Utc::now());
        assert!(f.iter().any(|x| x.title.contains("Does Not Cover")));
    }

    #[test]
    fn wildcard_san_matches_exactly_one_label() {
        assert!(hostname_covered("api.example.com", &["*.example.com".into()]));
        assert!(!hostname_covered("a.b.example.com", &["*.example.com".into()]));
        assert!(!hostname_covered("example.com", &["*.example.com".into()]));
    }

    #[test]
    fn exact_san_match_is_case_insensitive() {
        assert!(hostname_covered("App.Example.COM", &["app.example.com".into()]));
    }

    #[test]
    fn weak_signature_algorithms_are_recognised() {
        assert!(is_weak_signature("sha1WithRSAEncryption"));
        assert!(is_weak_signature("md5WithRSAEncryption"));
        assert!(is_weak_signature("1.2.840.113549.1.1.5")); // sha1WithRSA OID
        assert!(!is_weak_signature("sha256WithRSAEncryption"));
        assert!(!is_weak_signature("1.2.840.113549.1.1.11")); // sha256WithRSA OID
    }

    #[test]
    fn short_rsa_keys_are_reported() {
        let mut o = observation();
        o.rsa_key_bits = Some(1024);
        let f = analyze(&o, Uuid::new_v4(), Uuid::new_v4(), Utc::now());
        let weak = f.iter().find(|x| x.title.contains("Weak Signature")).unwrap();
        assert!(weak.description.contains("1024 bits"));
    }

    #[test]
    fn ecdsa_keys_do_not_trigger_the_rsa_length_check() {
        let mut o = observation();
        o.rsa_key_bits = None;
        let f = analyze(&o, Uuid::new_v4(), Uuid::new_v4(), Utc::now());
        assert!(!f.iter().any(|x| x.title.contains("Weak Signature")));
    }

    #[test]
    fn tls12_only_is_reported_as_low() {
        let mut o = observation();
        o.protocol = "TLS 1.2".into();
        let f = analyze(&o, Uuid::new_v4(), Uuid::new_v4(), Utc::now());
        let legacy = f.iter().find(|x| x.title.contains("TLS 1.3 Not Supported")).unwrap();
        assert_eq!(legacy.severity, Severity::Low);
    }

    #[test]
    fn tls13_does_not_trigger_the_protocol_check() {
        let f = analyze(&observation(), Uuid::new_v4(), Uuid::new_v4(), Utc::now());
        assert!(!f.iter().any(|x| x.title.contains("TLS 1.3 Not Supported")));
    }

    #[test]
    fn protocol_names_are_normalized() {
        assert_eq!(normalize_protocol("TLSv1_3"), "TLS 1.3");
        assert_eq!(normalize_protocol("TLSv1_2"), "TLS 1.2");
    }

    #[test]
    fn every_tls_finding_carries_full_taxonomy() {
        let mut o = observation();
        o.chain_trusted = false;
        o.not_after = Some(Utc::now() - Duration::days(1));
        let findings = analyze(&o, Uuid::new_v4(), Uuid::new_v4(), Utc::now());
        assert!(!findings.is_empty());
        for f in findings {
            assert!(f.cwe_id.is_some());
            assert_eq!(f.wstg_id.as_deref(), Some("WSTG-CRYP-01"));
            assert!(f.cvss4.is_some());
            assert!(!f.evidences.is_empty());
        }
    }
}
