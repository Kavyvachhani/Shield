//! What a leaked credential looks like.
//!
//! Two detection strategies, and the difference between them decides how a
//! finding is reported.
//!
//! **Provider patterns** match a token whose issuer publishes a distinctive
//! shape — `AKIA` followed by sixteen uppercase characters is an AWS access key
//! identifier and nothing else. A match is close to proof: the value is a
//! credential, the provider is known, and the revocation procedure is known
//! too, which is what makes the remediation actionable rather than generic.
//!
//! **Entropy detection** catches everything else — the bespoke API key, the
//! database password, the signing secret with no published format. It cannot
//! be proof, because a long random-looking string is also what a content hash,
//! a UUID, a minified identifier and a base64-encoded image look like. So it is
//! gated hard: the variable has to be named like a credential, the value has to
//! be long enough and random enough to be one, and it must not match any of the
//! shapes that are random-looking for innocent reasons.
//!
//! The gate is deliberately tight. A secret scanner that reports every hash in
//! a lockfile is one an analyst turns off, and a scanner that is turned off
//! finds nothing at all.

use regex::Regex;
use std::sync::OnceLock;

/// How urgently a leaked credential of this kind needs handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Impact {
    /// Grants access to infrastructure, data or money directly.
    Critical,
    /// Grants access to a service account or a third-party API.
    High,
    /// Identifies a principal but needs a paired secret, or is scoped narrowly.
    Moderate,
}

/// One provider-specific credential shape.
pub struct SecretPattern {
    pub id: &'static str,
    /// What the credential is, in the words the provider uses.
    pub name: &'static str,
    pub pattern: &'static str,
    pub impact: Impact,
    /// How to revoke it. The single most useful sentence in the finding: a
    /// leaked key is not fixed by deleting the line, it is fixed by rotation,
    /// and the person reading the report needs to know where to go.
    pub revocation: &'static str,
    /// Substrings that mean this match is a documented example, not a leak.
    pub not_if: &'static [&'static str],
}

/// Every provider pattern the engine ships.
pub fn all() -> &'static [SecretPattern] {
    PATTERNS
}

const PATTERNS: &[SecretPattern] = &[

// ── Cloud providers ─────────────────────────────────────────────────────────
SecretPattern {
    id: "SECRET-AWS-ACCESS-KEY",
    name: "AWS access key identifier",
    pattern: r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b",
    impact: Impact::Critical,
    revocation: "Deactivate the key in IAM immediately (`aws iam update-access-key --status \
                 Inactive`), then delete it. Before deleting, pull CloudTrail for that access \
                 key id to establish whether it was used from an address you do not recognise. \
                 Replace it with a role assumed by the workload — an IAM role or IRSA has no \
                 long-lived secret to leak next time.",
    not_if: &["AKIAIOSFODNN7EXAMPLE", "EXAMPLE", "example"],
},
SecretPattern {
    id: "SECRET-AWS-SECRET-KEY",
    name: "AWS secret access key",
    pattern: r#"(?i)aws.{0,20}?(?:secret|private).{0,20}?['"\s:=]+([A-Za-z0-9/+=]{40})\b"#,
    impact: Impact::Critical,
    revocation: "This is the half of an AWS credential pair that cannot be recovered from the \
                 console, so treat it as fully disclosed. Deactivate and delete the key pair in \
                 IAM, review CloudTrail for use, and move the workload to an assumed role.",
    not_if: &["wJalrXUtnFEMI/K7MDENG", "EXAMPLE"],
},
SecretPattern {
    id: "SECRET-AZURE-STORAGE",
    name: "Azure storage account connection string",
    pattern: r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=([A-Za-z0-9+/=]{60,})",
    impact: Impact::Critical,
    revocation: "Rotate both storage account keys in the Azure portal (Access keys → Rotate), \
                 rotating the unused one first so live traffic is not interrupted. Then move \
                 clients to a user-delegation SAS or Entra ID authentication, which are \
                 time-bounded and revocable.",
    not_if: &["AccountKey=<", "youraccountkey", "AccountKey=abc"],
},
SecretPattern {
    id: "SECRET-GCP-SERVICE-ACCOUNT",
    name: "Google Cloud service account private key",
    pattern: r#"(?s)"type"\s*:\s*"service_account".{0,400}?"private_key"\s*:\s*"(-----BEGIN)"#,
    impact: Impact::Critical,
    revocation: "Delete the key from the service account in IAM & Admin → Service Accounts → \
                 Keys, and check Cloud Audit Logs for use of that key id. Replace it with \
                 Workload Identity Federation so the workload authenticates without a key file \
                 at all.",
    not_if: &["your-project-id", "PRIVATE_KEY_HERE"],
},
SecretPattern {
    id: "SECRET-GOOGLE-API-KEY",
    name: "Google API key",
    pattern: r"\b(AIza[0-9A-Za-z_\-]{35})\b",
    impact: Impact::High,
    revocation: "Regenerate the key in the Google Cloud console (APIs & Services → \
                 Credentials). Before that, check whether it carries application and API \
                 restrictions — an unrestricted key found in a public repository is billed to \
                 you until it is rotated.",
    not_if: &["AIzaSyExample", "YOUR_API_KEY"],
},

// ── Source hosting and package registries ───────────────────────────────────
SecretPattern {
    id: "SECRET-GITHUB-TOKEN",
    name: "GitHub access token",
    pattern: r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})\b",
    impact: Impact::Critical,
    revocation: "Revoke it at github.com/settings/tokens (or, for an app token, in the app's \
                 settings) — GitHub also revokes tokens it detects in public repositories \
                 automatically, but a private repository gets no such help. Review the \
                 account's security log for use, and check whether any repository was cloned \
                 or any workflow was triggered.",
    not_if: &["ghp_xxxxxxxx", "EXAMPLE"],
},
SecretPattern {
    id: "SECRET-GITLAB-TOKEN",
    name: "GitLab personal access token",
    pattern: r"\b(glpat-[A-Za-z0-9_\-]{20,})\b",
    impact: Impact::Critical,
    revocation: "Revoke it under User Settings → Access Tokens, and review the audit events \
                 for the account. Where the token was used by CI, replace it with a job token \
                 or a project access token scoped to exactly what the job needs.",
    not_if: &["glpat-xxxxxxxx", "EXAMPLE"],
},
SecretPattern {
    id: "SECRET-NPM-TOKEN",
    name: "npm registry token",
    pattern: r"\b(npm_[A-Za-z0-9]{36})\b",
    impact: Impact::Critical,
    revocation: "Revoke it with `npm token revoke <id>` and check `npm token list` for others. \
                 A publish-scoped npm token is a supply-chain credential: check the package's \
                 version history for a release you did not make, and enable publishing with \
                 trusted provenance so a token alone cannot publish.",
    not_if: &["npm_xxxxxxxx"],
},
SecretPattern {
    id: "SECRET-PYPI-TOKEN",
    name: "PyPI upload token",
    pattern: r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})",
    impact: Impact::Critical,
    revocation: "Delete the token in your PyPI account settings and review the project's \
                 release history for an upload you did not make. Move publishing to a Trusted \
                 Publisher so no long-lived token exists.",
    not_if: &[],
},

// ── Payments and communications ─────────────────────────────────────────────
SecretPattern {
    id: "SECRET-STRIPE-KEY",
    name: "Stripe live secret key",
    pattern: r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b",
    impact: Impact::Critical,
    revocation: "Roll the key in the Stripe dashboard (Developers → API keys) — Stripe supports \
                 rolling with a grace period so live traffic is not dropped. Then review \
                 recent charges, refunds and payouts for activity you did not initiate: a live \
                 secret key can move money.",
    not_if: &["sk_live_xxx", "sk_test_"],
},
SecretPattern {
    id: "SECRET-SLACK-TOKEN",
    name: "Slack API token",
    pattern: r"\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b",
    impact: Impact::High,
    revocation: "Revoke it in the Slack app's OAuth settings, or with `auth.revoke`. Depending \
                 on the scopes it carries this token can read message history across the \
                 workspace, so review the app's audit logs before assuming the exposure was \
                 limited.",
    not_if: &["xoxb-your-token", "xoxb-1234"],
},
SecretPattern {
    id: "SECRET-SLACK-WEBHOOK",
    name: "Slack incoming webhook URL",
    pattern: r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9]{20,})",
    impact: Impact::Moderate,
    revocation: "Delete the webhook in the Slack app configuration and create a new one. \
                 Anyone holding this URL can post into the channel as the app, which is a \
                 credible phishing surface inside an organisation that trusts its own \
                 channels.",
    not_if: &["T00000000"],
},
SecretPattern {
    id: "SECRET-SENDGRID-KEY",
    name: "SendGrid API key",
    pattern: r"\b(SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{40,})\b",
    impact: Impact::High,
    revocation: "Delete the key in SendGrid (Settings → API Keys) and review the Activity feed \
                 for mail you did not send — a stolen sending credential is used to send \
                 phishing from your authenticated domain, which damages the domain's \
                 reputation as well as its recipients.",
    not_if: &[],
},
SecretPattern {
    id: "SECRET-TWILIO-KEY",
    name: "Twilio API key or account SID",
    pattern: r"\b((?:SK|AC)[0-9a-fA-F]{32})\b",
    impact: Impact::High,
    revocation: "Delete the API key in the Twilio console and review the usage log. Twilio \
                 credentials are used to send messages billed to your account, so check the \
                 balance and the message log as well as revoking.",
    not_if: &["ACxxxxxxxx", "AC00000000"],
},
SecretPattern {
    id: "SECRET-TELEGRAM-BOT",
    name: "Telegram bot token",
    pattern: r"\b([0-9]{8,10}:AA[A-Za-z0-9_\-]{33})\b",
    impact: Impact::Moderate,
    revocation: "Revoke the token with BotFather's `/revoke`, which issues a new one and \
                 invalidates this immediately.",
    not_if: &[],
},
SecretPattern {
    id: "SECRET-DISCORD-BOT",
    name: "Discord bot token",
    pattern: r"\b([MNO][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27})\b",
    impact: Impact::Moderate,
    revocation: "Regenerate the token in the Discord developer portal. The bot's permissions \
                 in every guild it has joined are exercisable by anyone holding it.",
    not_if: &[],
},

// ── AI and SaaS ─────────────────────────────────────────────────────────────
SecretPattern {
    id: "SECRET-OPENAI-KEY",
    name: "OpenAI API key",
    pattern: r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{32,})\b",
    impact: Impact::High,
    revocation: "Revoke it at platform.openai.com/api-keys and check the usage dashboard for \
                 spend you did not incur. These keys are billed per token and are actively \
                 harvested from public repositories.",
    not_if: &["sk-xxxxxxxx", "sk-YOUR", "sk-...", "sk-abc123"],
},
SecretPattern {
    id: "SECRET-ANTHROPIC-KEY",
    name: "Anthropic API key",
    pattern: r"\b(sk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_\-]{80,})\b",
    impact: Impact::High,
    revocation: "Revoke it in the Anthropic console under API keys, and review usage for the \
                 period since it was committed.",
    not_if: &["sk-ant-xxxx"],
},
SecretPattern {
    id: "SECRET-SHOPIFY-TOKEN",
    name: "Shopify access token",
    pattern: r"\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b",
    impact: Impact::Critical,
    revocation: "Uninstall and reinstall the app to rotate the token, or rotate it in the \
                 Shopify admin. These tokens read order and customer data, so treat the \
                 exposure as a possible personal-data breach and check the notification \
                 obligations that follow.",
    not_if: &[],
},
SecretPattern {
    id: "SECRET-SQUARE-TOKEN",
    name: "Square access token",
    pattern: r"\b(sq0(?:atp|csp)-[A-Za-z0-9_\-]{22,})\b",
    impact: Impact::Critical,
    revocation: "Rotate the access token in the Square developer dashboard (Credentials → \
                 Replace) and revoke the old one. Review the transaction and refund history \
                 for the period since it was committed: a Square access token can read \
                 customer and payment data and, depending on its permissions, move money.",
    not_if: &[],
},
SecretPattern {
    id: "SECRET-DIGITALOCEAN-TOKEN",
    name: "DigitalOcean personal access token",
    pattern: r"\b(dop_v1_[a-f0-9]{64})\b",
    impact: Impact::Critical,
    revocation: "Revoke it in the DigitalOcean control panel under API → Tokens. A read/write \
                 token controls every droplet, database and space on the account.",
    not_if: &[],
},
SecretPattern {
    id: "SECRET-VAULT-TOKEN",
    name: "HashiCorp Vault service token",
    pattern: r"\b(hvs\.[A-Za-z0-9_\-]{60,}|hvb\.[A-Za-z0-9_\-]{60,})\b",
    impact: Impact::Critical,
    revocation: "Revoke it with `vault token revoke`, and check the audit device for what it \
                 read. A Vault token is a key to the other keys, so treat every secret its \
                 policy could reach as also disclosed.",
    not_if: &[],
},
SecretPattern {
    id: "SECRET-TERRAFORM-TOKEN",
    name: "Terraform Cloud API token",
    pattern: r"\b([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{50,})\b",
    impact: Impact::Critical,
    revocation: "Revoke it in Terraform Cloud under User Settings → Tokens. This token can read \
                 state files, which routinely contain every other credential the \
                 infrastructure uses.",
    not_if: &[],
},
SecretPattern {
    id: "SECRET-MAILGUN-KEY",
    name: "Mailgun API key",
    pattern: r"\b(key-[0-9a-zA-Z]{32})\b",
    impact: Impact::High,
    revocation: "Rotate it in the Mailgun dashboard and review the sending log for messages \
                 you did not send.",
    not_if: &[],
},
SecretPattern {
    id: "SECRET-MAILCHIMP-KEY",
    name: "Mailchimp API key",
    pattern: r"\b([0-9a-f]{32}-us[0-9]{1,2})\b",
    impact: Impact::High,
    revocation: "Disable the key in Mailchimp under Account → Extras → API keys. It reads the \
                 whole audience list, so treat this as an exposure of subscriber personal \
                 data.",
    not_if: &[],
},

// ── Key material and generic transports ─────────────────────────────────────
SecretPattern {
    id: "SECRET-PRIVATE-KEY",
    name: "Private key block",
    pattern: r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
    impact: Impact::Critical,
    revocation: "Treat the key as compromised regardless of whether it is passphrase-protected: \
                 a passphrase buys time against an offline attack, it does not undo the \
                 disclosure. Generate a replacement, deploy it, revoke the old one everywhere \
                 it is trusted — authorized_keys, certificate authorities, signing \
                 configurations — and re-issue any certificate it signed.",
    not_if: &["EXAMPLE", "your-private-key", "REDACTED"],
},
SecretPattern {
    id: "SECRET-URL-CREDENTIALS",
    name: "Credentials embedded in a URL",
    pattern: r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[A-Za-z0-9_.\-]{2,}:([^@\s'\x22/<>]{6,})@[A-Za-z0-9.\-]+",
    impact: Impact::High,
    revocation: "Rotate the credential at the service it authenticates to, then move it out of \
                 the URL entirely: a credential in a URL is logged by every proxy, every \
                 access log and every error report on the path, so it leaks continuously even \
                 when the source is private.",
    not_if: &["user:pass@", "username:password@", "<user>:<pass>", "${", "%s", "user:secret@", "changeme"],
},
SecretPattern {
    id: "SECRET-JWT",
    name: "JSON Web Token",
    pattern: r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b",
    impact: Impact::Moderate,
    revocation: "Decode it before acting: the payload is readable without the key, so read the \
                 claims to see whose session it is and when it expires. If it is a live \
                 session token, invalidate the session and rotate the signing key — rotating \
                 the key invalidates every token signed with it, which is the point.",
    not_if: &["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9l"],
},
SecretPattern {
    id: "SECRET-BASIC-AUTH-HEADER",
    name: "Hardcoded HTTP Basic credentials",
    pattern: r#"(?i)authorization['"\s:=]+(?:Basic\s+)([A-Za-z0-9+/]{16,}={0,2})"#,
    impact: Impact::High,
    revocation: "Base64 is an encoding, not encryption: decode the value to identify the \
                 account, then rotate that account's password and move the credential into the \
                 environment or a secret manager.",
    not_if: &["dXNlcjpwYXNz", "Basic <", "${"],
},
];

// ── Entropy detection ────────────────────────────────────────────────────────

/// Variable names that mean the value beside them is meant to be secret.
const CREDENTIAL_NAMES: &[&str] = &[
    "password", "passwd", "pwd", "secret", "token", "apikey", "api_key",
    "access_key", "secret_key", "private_key", "client_secret", "auth_token",
    "credential", "passphrase", "encryption_key", "signing_key", "session_key",
    "master_key", "app_secret", "consumer_secret", "refresh_token", "bearer",
];

/// Values that look random but are not credentials, or are deliberate examples.
const NEVER_A_SECRET: &[&str] = &[
    "example", "sample", "placeholder", "changeme", "change_me", "your_", "yours",
    "dummy", "test", "fake", "mock", "todo", "fixme", "redacted", "xxxxx",
    "insert", "replace", "notreal", "abcdef123456", "0000000", "1111111",
    "aaaaaaa", "process.env", "os.environ", "getenv", "${", "<%=", "{{", "$(",
];

/// The Shannon entropy of a string, in bits per character.
///
/// A base64 credential lands near 5.0; English prose sits near 4.0 measured
/// this way but over a much smaller alphabet, which is why the thresholds below
/// are paired with a character-class check rather than used alone.
pub fn shannon_entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    let mut total = 0usize;
    for b in value.bytes() {
        counts[b as usize] += 1;
        total += 1;
    }
    let total = total as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / total;
            -p * p.log2()
        })
        .sum()
}

/// What a credential-shaped assignment actually is.
///
/// The distinction matters because the two are different findings with
/// different evidence. A high-entropy value in an `apiKey` field is a generated
/// credential that was almost certainly issued by a service and is almost
/// certainly live. A low-entropy value in a `password` field is a password
/// somebody chose and typed — still a hardcoded credential, still CWE-798,
/// still needing rotation, but the engine knows it by a different route and
/// should say so rather than describing it as a leaked key.
///
/// Collapsing them was a real gap: `dbPassword = "super_secret_password_123!"`
/// fails every entropy threshold worth setting, because it is a phrase rather
/// than a generated token, and an engine that only measures entropy reports
/// nothing at all for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    /// Long and random: issued by a system, not chosen by a person.
    GeneratedCredential,
    /// A literal password or passphrase written into the source.
    HardcodedPassword,
}

/// Field names that specifically mean "a password a human chose".
///
/// Narrower than [`CREDENTIAL_NAMES`]: a low-entropy value in a `token` field
/// is usually a placeholder, whereas a low-entropy value in a `password` field
/// is usually a password.
const PASSWORD_NAMES: &[&str] = &[
    "password", "passwd", "pwd", "passphrase", "secret", "credential",
];

/// Whether `value`, assigned to a variable called `name`, looks like a secret.
///
/// Every condition here exists because of a specific class of false positive
/// that would otherwise dominate the output.
pub fn looks_like_a_secret(name: &str, value: &str) -> bool {
    classify_secret(name, value).is_some()
}

/// Classify a credential-shaped assignment, or `None` if it is not one.
pub fn classify_secret(name: &str, value: &str) -> Option<SecretKind> {
    let lower_name = name.to_ascii_lowercase();
    if !CREDENTIAL_NAMES.iter().any(|n| lower_name.contains(n)) {
        return None;
    }
    let len = value.chars().count();
    if !(6..=200).contains(&len) {
        return None;
    }
    let lower_value = value.to_ascii_lowercase();
    if NEVER_A_SECRET.iter().any(|p| lower_value.contains(p)) {
        return None;
    }
    // An interpolation or a reference to configuration is the *correct*
    // pattern, and reporting it would penalise doing the right thing.
    if value.contains("${") || value.contains("#{") || value.starts_with('$') {
        return None;
    }
    // Whitespace means prose, not a credential.
    if value.contains(char::is_whitespace) {
        return None;
    }
    // A path, a URL or a MIME type in a field that happens to be named
    // `auth_endpoint` or `token_url`.
    if value.contains("://") || value.starts_with('/') || value.starts_with('.') {
        return None;
    }

    let alphabet = classify_alphabet(value);
    let entropy = shannon_entropy(value);
    let generated = match alphabet {
        // Hex has only sixteen symbols, so its maximum entropy is 4.0; a real
        // 32-character hex secret sits above 3.5. This also catches most
        // content hashes, which is why the caller additionally excludes
        // lockfiles and integrity fields.
        Alphabet::Hex => len >= 24 && entropy > 3.4,
        // Base64 and the URL-safe variant: a genuine key is near 5.0.
        Alphabet::Base64 => len >= 16 && entropy > 4.0,
        // Mixed printable: the loosest case, so the strictest threshold.
        Alphabet::Mixed => len >= 16 && entropy > 4.2,
        // A word or a phrase — not a generated secret, but possibly a chosen
        // one, which the branch below decides.
        Alphabet::Word => false,
    };
    if generated {
        return Some(SecretKind::GeneratedCredential);
    }

    // Not random enough to be issued by a system. It is still a hardcoded
    // credential if the field says so and the value is a plausible password
    // rather than a flag, an identifier or an enum member.
    let password_field = PASSWORD_NAMES.iter().any(|n| lower_name.contains(n));
    let plausible_password = len >= 8
        && !matches!(lower_value.as_str(), "true" | "false" | "null" | "none" | "undefined")
        // A value that is only lowercase letters and dashes is far more often
        // an identifier — `client-credentials`, `password-grant` — than a
        // password somebody typed.
        && (value.chars().any(|c| c.is_ascii_digit())
            || value.chars().any(|c| !c.is_ascii_alphanumeric() && c != '-')
            || value.chars().any(|c| c.is_ascii_uppercase()));

    (password_field && plausible_password).then_some(SecretKind::HardcodedPassword)
}

#[derive(Debug, PartialEq)]
enum Alphabet {
    Hex,
    Base64,
    Mixed,
    Word,
}

fn classify_alphabet(value: &str) -> Alphabet {
    let all_hex = value.chars().all(|c| c.is_ascii_hexdigit());
    if all_hex {
        return Alphabet::Hex;
    }
    let base64ish = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_');
    let has_digit = value.chars().any(|c| c.is_ascii_digit());
    let has_upper = value.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = value.chars().any(|c| c.is_ascii_lowercase());

    // A value with no digits and no case variation is a word or a path, however
    // long it is: `supersecretpasswordphrase` is a bad password, not a
    // generated key, and reporting it as a leaked credential misdescribes it.
    if !has_digit && !(has_upper && has_lower) {
        return Alphabet::Word;
    }
    if base64ish {
        Alphabet::Base64
    } else {
        Alphabet::Mixed
    }
}

/// Compiled provider patterns, built once per process.
pub struct CompiledPattern {
    pub spec: &'static SecretPattern,
    pub regex: Regex,
}

pub fn compiled() -> &'static [CompiledPattern] {
    static CACHE: OnceLock<Vec<CompiledPattern>> = OnceLock::new();
    CACHE.get_or_init(|| {
        all()
            .iter()
            .filter_map(|spec| {
                Regex::new(spec.pattern)
                    .map_err(|e| tracing::error!(id = spec.id, error = %e, "secret pattern dropped"))
                    .ok()
                    .map(|regex| CompiledPattern { spec, regex })
            })
            .collect()
    })
}

/// Mask a matched credential for a report.
///
/// Enough of the value survives that the holder can identify *which* key it is
/// — which matters when an account has nine — and not enough that the report
/// becomes a second copy of the secret.
pub fn mask(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 8 {
        return "•".repeat(chars.len().max(4));
    }
    let head: String = chars.iter().take(4).collect();
    let tail: String = chars.iter().skip(chars.len() - 2).collect();
    format!("{head}{}{tail}", "•".repeat(12))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(id: &str, text: &str) -> bool {
        compiled()
            .iter()
            .find(|c| c.spec.id == id)
            .expect("pattern exists")
            .regex
            .is_match(text)
    }

    #[test]
    fn every_provider_pattern_compiles() {
        assert_eq!(compiled().len(), all().len(), "a pattern failed to compile");
    }

    #[test]
    fn pattern_ids_are_unique_and_carry_revocation_guidance() {
        let mut seen = std::collections::HashSet::new();
        for p in all() {
            assert!(seen.insert(p.id), "duplicate pattern id {}", p.id);
            assert!(
                p.revocation.len() > 80,
                "{} does not say how to revoke the credential, which is the only \
                 remediation that matters",
                p.id
            );
        }
    }

    #[test]
    fn aws_access_keys_are_recognised() {
        assert!(matches("SECRET-AWS-ACCESS-KEY", "AKIAIOSFODNN7REALKEY"));
        assert!(matches("SECRET-AWS-ACCESS-KEY", "ASIA234567890ABCDEF1"));
        assert!(!matches("SECRET-AWS-ACCESS-KEY", "AKIA123"), "too short to be a key id");
    }

    #[test]
    fn github_tokens_of_every_prefix_are_recognised() {
        assert!(matches("SECRET-GITHUB-TOKEN", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"));
        assert!(matches("SECRET-GITHUB-TOKEN", "ghs_abcdefghijklmnopqrstuvwxyz0123456789"));
        assert!(matches(
            "SECRET-GITHUB-TOKEN",
            "github_pat_11ABCDEFG0abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN"
        ));
    }

    #[test]
    fn a_private_key_header_is_matched_in_every_common_form() {
        for header in [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        ] {
            assert!(matches("SECRET-PRIVATE-KEY", header), "{header} not matched");
        }
    }

    #[test]
    fn a_live_stripe_key_is_matched_and_a_test_key_is_not() {
        let live_key = format!("sk_{}_51H8xQ2eZvKYlo2C0abcdefgh", "live");
        let test_key = format!("sk_{}_51H8xQ2eZvKYlo2C0abcdefgh", "test");
        assert!(matches("SECRET-STRIPE-KEY", &live_key));
        assert!(!matches("SECRET-STRIPE-KEY", &test_key));
    }

    #[test]
    fn credentials_in_a_url_are_matched_but_documentation_placeholders_are_excluded() {
        assert!(matches(
            "SECRET-URL-CREDENTIALS",
            "postgres://admin:Xq9rT2vLp0zW@db.internal:5432/app"
        ));
        let spec = all().iter().find(|p| p.id == "SECRET-URL-CREDENTIALS").unwrap();
        assert!(spec.not_if.contains(&"user:pass@"));
    }

    #[test]
    fn azure_connection_strings_are_matched() {
        assert!(matches(
            "SECRET-AZURE-STORAGE",
            "DefaultEndpointsProtocol=https;AccountName=store;AccountKey=Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9v=;"
        ));
    }

    // ── Entropy gate ────────────────────────────────────────────────────────

    #[test]
    fn entropy_rises_with_randomness() {
        assert!(shannon_entropy("aaaaaaaaaaaaaaaa") < 1.0);
        assert!(shannon_entropy("Xq9rT2vLp0zWmK4d") > 3.5);
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn a_high_entropy_value_in_a_credential_field_is_reported() {
        assert!(looks_like_a_secret("apiKey", "Xq9rT2vLp0zWmK4dN7bH3sG6"));
        assert!(looks_like_a_secret("DB_PASSWORD", "9fK2mQ7xR4tZ8vB1nL6y"));
    }

    /// The gate that stops the engine reporting every hash in the repository.
    #[test]
    fn a_random_value_in_a_field_that_is_not_a_credential_is_ignored() {
        assert!(!looks_like_a_secret("requestId", "Xq9rT2vLp0zWmK4dN7bH3sG6"));
        assert!(!looks_like_a_secret("integrity", "sha512-abc123def456ghi789jkl"));
        assert!(!looks_like_a_secret("commitHash", "a3f1c9e8b2d4f6a8c0e2b4d6f8a0c2e4"));
    }

    #[test]
    fn documentation_placeholders_are_never_reported() {
        assert!(!looks_like_a_secret("password", "your_password_here_xyz"));
        assert!(!looks_like_a_secret("apiKey", "REPLACE_WITH_YOUR_KEY_123"));
        assert!(!looks_like_a_secret("token", "example_token_abcdef123"));
        assert!(!looks_like_a_secret("secret", "changeme123456789"));
    }

    /// Reading the credential from configuration is the recommended pattern;
    /// flagging it would punish the fix.
    #[test]
    fn a_reference_to_configuration_is_not_a_leaked_secret() {
        assert!(!looks_like_a_secret("password", "${DB_PASSWORD}"));
        assert!(!looks_like_a_secret("apiKey", "process.env.API_KEY"));
        assert!(!looks_like_a_secret("token", "#{ENV['TOKEN']}"));
        assert!(!looks_like_a_secret("secret", "$SECRET_FROM_VAULT"));
    }

    #[test]
    fn a_short_value_is_below_the_floor_however_it_is_named() {
        assert!(!looks_like_a_secret("password", "hunter"));
        assert!(!looks_like_a_secret("apiKey", "abc"));
    }

    /// A password a person chose fails every entropy threshold worth setting,
    /// and is still a hardcoded credential.
    #[test]
    fn a_low_entropy_password_literal_is_caught_as_a_hardcoded_password() {
        assert_eq!(
            classify_secret("dbPassword", "super_secret_password_123!"),
            Some(SecretKind::HardcodedPassword)
        );
        assert_eq!(
            classify_secret("DB_PASSWORD", "Winter2024!"),
            Some(SecretKind::HardcodedPassword)
        );
    }

    #[test]
    fn a_generated_key_is_classified_apart_from_a_chosen_password() {
        assert_eq!(
            classify_secret("apiKey", "Xq9rT2vLp0zWmK4dN7bH3sG6"),
            Some(SecretKind::GeneratedCredential)
        );
    }

    /// An identifier in a field that happens to be named like a credential is
    /// the most common false positive this branch could introduce.
    #[test]
    fn an_identifier_in_a_credential_named_field_is_not_a_password() {
        assert_eq!(classify_secret("grant_type_secret", "client-credentials"), None);
        assert_eq!(classify_secret("password_policy", "strict"), None);
        assert_eq!(classify_secret("secret_enabled", "true"), None);
        assert_eq!(classify_secret("token_url", "https://auth.example.com/token"), None);
        assert_eq!(classify_secret("secret_path", "/run/secrets/db"), None);
    }

    /// A low-entropy value in a `token` field is far more often a placeholder
    /// than a credential, so only the password-shaped names take this branch.
    #[test]
    fn the_hardcoded_password_branch_is_narrower_than_the_entropy_branch() {
        assert_eq!(classify_secret("access_token", "shortish1"), None);
        assert_eq!(
            classify_secret("password", "shortish1"),
            Some(SecretKind::HardcodedPassword)
        );
    }

    /// A weak passphrase is a different finding from a leaked generated key,
    /// and describing one as the other misleads the reader.
    #[test]
    fn a_lowercase_phrase_is_not_classified_as_a_generated_key() {
        assert!(!looks_like_a_secret("password", "correcthorsebatterystaple"));
    }

    #[test]
    fn a_value_containing_whitespace_is_prose_not_a_token() {
        assert!(!looks_like_a_secret("secret", "this is not a token value"));
    }

    // ── Masking ─────────────────────────────────────────────────────────────

    #[test]
    fn a_masked_credential_is_identifiable_but_not_usable() {
        let masked = mask("AKIAIOSFODNN7REALKEY");
        assert!(masked.starts_with("AKIA"), "the holder must be able to tell which key");
        assert!(masked.ends_with("EY"));
        assert!(!masked.contains("IOSFODNN7REALK"), "the body must not survive");
    }

    #[test]
    fn a_short_value_is_masked_completely() {
        assert!(!mask("abc123").contains('a'));
    }
}
