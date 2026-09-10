//! Sentinel Infrastructure — the built-in infrastructure-as-code scanner.
//!
//! An application assessment that reads the application and stops there answers
//! half the question. A security group open to the world, a container running
//! as root with a writable filesystem, a storage bucket with public read, a CI
//! workflow that hands its secrets to a pull request from a fork — none of
//! these is fixed by anything in the application's own source, and every one of
//! them is decided in a file sitting next to it.
//!
//! Five file kinds, recognised by name and by content:
//!
//! * Dockerfiles — what the container runs as, and what it ships
//! * Docker Compose — privilege, host mounts and exposed ports
//! * Kubernetes manifests — security context, capabilities, host namespaces
//! * Terraform — the cloud resources themselves
//! * CI workflows — the most privileged automation most organisations run
//!
//! SAFETY: reads files. Renders no template, resolves no module, contacts no
//! cloud provider and evaluates no expression.

use crate::adapter_trait::ScannerAdapter;
use crate::static_engine::codebase::{self, Codebase, SourceFile, WalkLimits};
use crate::static_engine::engine::INFRASTRUCTURE;
use crate::static_engine::finding::{self as fb, CodeMatch, CodeSpec, Confidence};
use anyhow::Result;
use async_trait::async_trait;
use regex::Regex;
use sentinel_core::checklist::catalog::owasp;
use sentinel_core::models::finding::Finding;
use sentinel_core::models::target::Target;
use std::sync::OnceLock;
use uuid::Uuid;

/// Which kind of infrastructure file a rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Dockerfile,
    Compose,
    Kubernetes,
    Terraform,
    Workflow,
}

impl Kind {
    /// Identify a file by its name, and — for YAML, where the name says almost
    /// nothing — by what is inside it.
    pub fn of(file: &SourceFile) -> Option<Kind> {
        let name = file.file_name().to_ascii_lowercase();
        let path = file.relative.to_ascii_lowercase();

        if name == "dockerfile" || name.starts_with("dockerfile.") || name.ends_with(".dockerfile") {
            return Some(Kind::Dockerfile);
        }
        if name.starts_with("docker-compose") || name == "compose.yml" || name == "compose.yaml" {
            return Some(Kind::Compose);
        }
        if file.extension == "tf" || file.extension == "tfvars" || name.ends_with(".tf.json") {
            return Some(Kind::Terraform);
        }
        if path.contains(".github/workflows/") || path.contains(".gitlab-ci") || name == "bitbucket-pipelines.yml" {
            return Some(Kind::Workflow);
        }
        if matches!(file.extension.as_str(), "yaml" | "yml") {
            // A Kubernetes manifest is identifiable by its two mandatory
            // top-level keys, which nothing else uses together.
            let head: String = file.content.chars().take(4000).collect();
            if head.contains("apiVersion:") && head.contains("kind:") {
                return Some(Kind::Kubernetes);
            }
        }
        None
    }

    pub fn label(self) -> &'static str {
        match self {
            Kind::Dockerfile => "Dockerfile",
            Kind::Compose => "Docker Compose",
            Kind::Kubernetes => "Kubernetes manifest",
            Kind::Terraform => "Terraform",
            Kind::Workflow => "CI workflow",
        }
    }
}

/// How a rule decides a file is affected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// The pattern matched a line — that line is the finding.
    Present,
    /// The pattern did *not* match anywhere in a file of this kind, and its
    /// absence is the weakness. This is how "no USER instruction" is expressed.
    Absent,
}

pub struct IacRule {
    pub spec: CodeSpec,
    pub kinds: &'static [Kind],
    pub pattern: &'static str,
    pub trigger: Trigger,
    /// For an `Absent` rule, the pattern that must be present for the rule to
    /// apply at all — so "no USER" only fires on a file that builds an image.
    pub applies_if: Option<&'static str>,
    pub unless: &'static [&'static str],
}

// Vectors, calibrated the same way as the code engine's.
const V_CRITICAL: &str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
const V_HIGH_CONF: &str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N";
const V_HIGH_INTEG: &str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N";
const V_MED_INFO: &str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N";
const V_MED_LIMITED: &str = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N";
const V_LOCAL: &str = "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N";

const DOCKER: &[Kind] = &[Kind::Dockerfile];
const CONTAINER: &[Kind] = &[Kind::Dockerfile, Kind::Compose, Kind::Kubernetes];
const K8S: &[Kind] = &[Kind::Kubernetes];
const TF: &[Kind] = &[Kind::Terraform];
const CI: &[Kind] = &[Kind::Workflow];
const ANY: &[Kind] = &[
    Kind::Dockerfile, Kind::Compose, Kind::Kubernetes, Kind::Terraform, Kind::Workflow,
];

pub fn all() -> &'static [IacRule] {
    RULES
}

const RULES: &[IacRule] = &[

// ── Containers ──────────────────────────────────────────────────────────────
IacRule {
    spec: CodeSpec {
        id: "SENTINEL-IAC-CONTAINER-ROOT",
        title: "Container runs as root",
        cvss_vector: V_LOCAL,
        cwe: "CWE-250",
        wstg: "WSTG-CONF-11",
        owasp_2025: owasp::A02,
        api_top10: None,
        description:
            "The image declares no `USER`, so its processes run as uid 0. A container is not \
             a security boundary on its own — it is a set of namespaces and cgroups — and root \
             inside one starts every container-escape technique from the most favourable \
             position: it can write anywhere in the filesystem, load what the kernel permits, \
             and exploit any host mount it is given. Running as an unprivileged user does not \
             make an escape impossible, but it removes the easiest routes and turns several \
             others into local privilege escalations the attacker has to solve first.",
        remediation:
            "Create a user in the build and switch to it before the entrypoint:\n\n\
             ```\n\
             RUN adduser --system --uid 10001 --no-create-home app\n\
             USER 10001\n\
             ```\n\n\
             Use a numeric uid rather than a name: Kubernetes' `runAsNonRoot` check cannot \
             verify a username, and a pod with that policy will refuse to start an image that \
             only has one. Enforce it at the orchestration layer too, so an image without a \
             `USER` cannot be deployed by accident.",
        references: &[
            "https://cwe.mitre.org/data/definitions/250.html",
            "https://docs.docker.com/build/building/best-practices/#user",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "No USER instruction appears in this Dockerfile. A base image that already sets one \
             is inherited, so check the FROM image before treating this as unfixed.",
    },
    kinds: DOCKER,
    pattern: r"(?im)^\s*USER\s+\S+",
    trigger: Trigger::Absent,
    applies_if: Some(r"(?im)^\s*FROM\s+"),
    unless: &["scratch"],
},
IacRule {
    spec: CodeSpec {
        id: "SENTINEL-IAC-PRIVILEGED",
        title: "Container granted privileged mode",
        cvss_vector: V_CRITICAL,
        cwe: "CWE-250",
        wstg: "WSTG-CONF-11",
        owasp_2025: owasp::A02,
        api_top10: None,
        description:
            "A container is configured to run privileged. This is not an incremental \
             loosening: it hands the container all Linux capabilities, removes the seccomp and \
             AppArmor confinement, and gives it access to every host device. Escape from a \
             privileged container to the host is a documented, reliable, single-step \
             operation. Whatever the container was isolating, it is not isolated any more.",
        remediation:
            "Remove `privileged`. Where a specific capability is genuinely needed, grant that \
             one and drop everything else:\n\n\
             ```yaml\n\
             securityContext:\n\
             \x20 privileged: false\n\
             \x20 allowPrivilegeEscalation: false\n\
             \x20 readOnlyRootFilesystem: true\n\
             \x20 runAsNonRoot: true\n\
             \x20 capabilities:\n\
             \x20   drop: [\"ALL\"]\n\
             \x20   add: [\"NET_BIND_SERVICE\"]   # only if it truly binds below 1024\n\
             ```\n\n\
             Most privileged containers exist for a device mount or a sysctl that a device \
             plugin or an init container can provide instead. Enforce the constraint with Pod \
             Security Admission at `restricted`, so this cannot be reintroduced quietly.",
        references: &[
            "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
            "https://cwe.mitre.org/data/definitions/250.html",
        ],
        confidence: Confidence::Certain,
        triage_note:
            "Privileged mode is set explicitly in this manifest. There is no reading under \
             which the container remains isolated from the host.",
    },
    kinds: CONTAINER,
    pattern: r"(?i)privileged\s*[:=]\s*true",
    trigger: Trigger::Present,
    applies_if: None,
    unless: &[],
},
IacRule {
    spec: CodeSpec {
        id: "SENTINEL-IAC-HOST-NAMESPACE",
        title: "Container shares a host namespace",
        cvss_vector: V_HIGH_CONF,
        cwe: "CWE-653",
        wstg: "WSTG-CONF-11",
        owasp_2025: owasp::A02,
        api_top10: None,
        description:
            "The workload joins one of the host's namespaces — network, PID or IPC. Each one \
             removes a specific isolation guarantee. `hostNetwork` puts the container on the \
             node's network stack, so it reaches everything the node reaches, bypasses network \
             policy entirely, and can bind privileged ports on the host. `hostPID` lets it see \
             and signal every process on the node, and read their memory and command lines, \
             which routinely carry credentials.",
        remediation:
            "Remove the host namespace. For network access, use a Service; for node-level \
             metrics, use the node exporter pattern with a narrow, explicitly reviewed \
             exception rather than applying it to application workloads. Block it in admission \
             policy so it stays exceptional.",
        references: &[
            "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
            "https://cwe.mitre.org/data/definitions/653.html",
        ],
        confidence: Confidence::Certain,
        triage_note:
            "A host namespace is joined explicitly. Monitoring agents legitimately need this; \
             an application workload does not, so which this is decides the rating.",
    },
    kinds: &[Kind::Kubernetes, Kind::Compose],
    pattern: r"(?i)(?:hostNetwork|hostPID|hostIPC)\s*:\s*true|network_mode\s*:\s*[\x22']?host",
    trigger: Trigger::Present,
    applies_if: None,
    unless: &[],
},
IacRule {
    spec: CodeSpec {
        id: "SENTINEL-IAC-DOCKER-SOCKET",
        title: "Docker socket mounted into a container",
        cvss_vector: V_CRITICAL,
        cwe: "CWE-250",
        wstg: "WSTG-CONF-11",
        owasp_2025: owasp::A02,
        api_top10: None,
        description:
            "`/var/run/docker.sock` is mounted into a container. The Docker socket is the \
             daemon's full API, and the daemon runs as root on the host, so anything that can \
             write to that socket can start a new privileged container with the host \
             filesystem mounted — which is root on the host, in one step, with no exploit. \
             Mounting it is equivalent to granting host root to whatever runs in the container, \
             including anything an attacker gets to run there.",
        remediation:
            "Do not mount the socket. For builds, use a rootless builder — BuildKit in rootless \
             mode, Kaniko or Buildah — which needs no daemon. For container management, use a \
             proxy that exposes only the specific endpoints required (docker-socket-proxy), and \
             treat even that as a privileged component.",
        references: &[
            "https://docs.docker.com/engine/security/",
            "https://cwe.mitre.org/data/definitions/250.html",
        ],
        confidence: Confidence::Certain,
        triage_note:
            "The socket path appears as a mount. This is host root by design, whatever the \
             container is nominally for.",
    },
    kinds: CONTAINER,
    pattern: r"/var/run/docker\.sock",
    trigger: Trigger::Present,
    applies_if: None,
    unless: &[],
},
IacRule {
    spec: CodeSpec {
        id: "SENTINEL-IAC-MUTABLE-TAG",
        title: "Base image pinned to a mutable tag",
        cvss_vector: V_MED_LIMITED,
        cwe: "CWE-1357",
        wstg: "WSTG-CONF-02",
        owasp_2025: owasp::A08,
        api_top10: None,
        description:
            "The build pulls a base image by `latest` or by no tag at all. Tags are mutable \
             pointers: the same Dockerfile produces a different image tomorrow, so a build that \
             passed review is not the build that ships, a rebuild cannot reproduce an incident, \
             and a compromise of the upstream tag reaches production on the next deploy without \
             anything in this repository changing.",
        remediation:
            "Pin by digest, which is a content hash and cannot be moved:\n\n\
             ```\n\
             FROM node:20.11.1-alpine3.19@sha256:1a2b3c…\n\
             ```\n\n\
             Keep the human-readable tag alongside the digest so the line still says what it \
             is, and use an automated updater (Renovate, Dependabot) to raise the digest bump \
             as a reviewable change rather than letting it happen silently.",
        references: &[
            "https://cwe.mitre.org/data/definitions/1357.html",
            "https://slsa.dev/spec/v1.0/requirements",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "The FROM line carries a mutable reference. In a pipeline that rebuilds and \
             re-tests on every deploy the practical risk is lower, but reproducibility is lost \
             either way.",
    },
    kinds: DOCKER,
    pattern: r"(?im)^\s*FROM\s+(?:--platform=\S+\s+)?[^\s@]+(?::latest)?\s*(?:AS\s+\w+)?\s*$",
    trigger: Trigger::Present,
    applies_if: None,
    unless: &["@sha256:", "scratch", "$", "FROM builder", "FROM base"],
},
IacRule {
    spec: CodeSpec {
        id: "SENTINEL-IAC-SECRET-IN-BUILD",
        title: "Secret passed through a build argument or environment instruction",
        cvss_vector: V_HIGH_CONF,
        cwe: "CWE-798",
        wstg: "WSTG-ATHN-07",
        owasp_2025: owasp::A07,
        api_top10: None,
        description:
            "A credential is supplied as a build argument or written into an `ENV` \
             instruction. Both are recorded in the image's own metadata: `docker history` \
             prints them, and every layer is readable by anyone who can pull the image. \
             Deleting the file in a later layer does not help — the earlier layer still \
             contains it, which is the single most common way a private key ends up in a \
             public registry.",
        remediation:
            "Use BuildKit's secret mount, which makes the value available during one command \
             and never writes it into a layer:\n\n\
             ```\n\
             # syntax=docker/dockerfile:1\n\
             RUN --mount=type=secret,id=npmrc \\\n\
             \x20   npm ci --userconfig=/run/secrets/npmrc\n\
             ```\n\n\
             For runtime credentials, inject them at start-up from the orchestrator's secret \
             store rather than baking them in. If a secret has already shipped in an image, \
             rotate it: the image is the disclosure, and it may be cached in registries you do \
             not control.",
        references: &[
            "https://docs.docker.com/build/building/secrets/",
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "A credential-shaped name appears in an ARG or ENV instruction. Confirm the value \
             is a real secret rather than a variable name that merely reads like one.",
    },
    kinds: DOCKER,
    pattern: r"(?im)^\s*(?:ARG|ENV)\s+\w*(?:PASSWORD|SECRET|TOKEN|APIKEY|API_KEY|PRIVATE_KEY|CREDENTIAL)\w*\s*=?\s*\S+",
    trigger: Trigger::Present,
    applies_if: None,
    unless: &["=$", "=${", "_FILE", "_PATH"],
},
IacRule {
    spec: CodeSpec {
        id: "SENTINEL-IAC-CURL-PIPE-SHELL",
        title: "Remote script downloaded and executed during the build",
        cvss_vector: V_HIGH_INTEG,
        cwe: "CWE-494",
        wstg: "WSTG-CONF-02",
        owasp_2025: owasp::A08,
        api_top10: None,
        description:
            "The build downloads a script and pipes it straight into a shell. Nothing verifies \
             what arrives: not a signature, not a checksum, not even a look at the content. \
             Whoever controls that URL — or anyone who can intercept the connection, or who \
             compromises the host serving it — executes arbitrary code inside the build, which \
             then ships in the image. This is the shape of several real supply-chain \
             compromises, not a theoretical concern.",
        remediation:
            "Download to a file, verify it, then run it:\n\n\
             ```\n\
             RUN curl -fsSL -o install.sh https://example.com/install.sh \\\n\
             \x20 && echo \"<known-sha256>  install.sh\" | sha256sum -c - \\\n\
             \x20 && sh install.sh && rm install.sh\n\
             ```\n\n\
             Better still, install from the distribution's package manager with signature \
             verification on, or vendor the script into the repository where it can be \
             reviewed and diffed like any other code.",
        references: &[
            "https://cwe.mitre.org/data/definitions/494.html",
            "https://slsa.dev/",
        ],
        confidence: Confidence::Certain,
        triage_note:
            "A download is piped into an interpreter on this line. The risk scales with how \
             much you trust the host serving it and the transport reaching it.",
    },
    kinds: &[Kind::Dockerfile, Kind::Workflow],
    pattern: r"(?i)(?:curl|wget)[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|k|)sh\b",
    trigger: Trigger::Present,
    applies_if: None,
    unless: &["sha256sum", "gpg --verify"],
},

// ── Kubernetes ──────────────────────────────────────────────────────────────
IacRule {
    spec: CodeSpec {
        id: "SENTINEL-IAC-K8S-NO-SECURITY-CONTEXT",
        title: "Workload declares no security context",
        cvss_vector: V_LOCAL,
        cwe: "CWE-1188",
        wstg: "WSTG-CONF-11",
        owasp_2025: owasp::A02,
        api_top10: None,
        description:
            "The workload sets no `securityContext`, so it inherits Kubernetes' permissive \
             defaults: it may run as root, it may escalate privileges, its root filesystem is \
             writable, and it holds the default capability set. Each of those defaults exists \
             for compatibility with workloads written before the alternative existed, and each \
             makes a container compromise easier to turn into something worse.",
        remediation:
            "Set the constraints explicitly on every workload:\n\n\
             ```yaml\n\
             securityContext:\n\
             \x20 runAsNonRoot: true\n\
             \x20 runAsUser: 10001\n\
             \x20 allowPrivilegeEscalation: false\n\
             \x20 readOnlyRootFilesystem: true\n\
             \x20 capabilities: { drop: [\"ALL\"] }\n\
             \x20 seccompProfile: { type: RuntimeDefault }\n\
             ```\n\n\
             Then enforce it with Pod Security Admission at `restricted` on the namespace, so \
             a workload without it is rejected rather than merely noticed.",
        references: &[
            "https://kubernetes.io/docs/tasks/configure-pod-container/security-context/",
            "https://cwe.mitre.org/data/definitions/1188.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "No securityContext appears in this manifest. A namespace-level Pod Security \
             Standard or a mutating policy would supply the constraints without this file \
             showing them — check for one before reporting.",
    },
    kinds: K8S,
    pattern: r"(?i)securityContext\s*:",
    trigger: Trigger::Absent,
    applies_if: Some(r"(?im)^\s*kind\s*:\s*(?:Deployment|StatefulSet|DaemonSet|Pod|Job|CronJob|ReplicaSet)\b"),
    unless: &[],
},
IacRule {
    spec: CodeSpec {
        id: "SENTINEL-IAC-K8S-PRIVILEGE-ESCALATION",
        title: "Privilege escalation permitted in a container",
        cvss_vector: V_LOCAL,
        cwe: "CWE-250",
        wstg: "WSTG-CONF-11",
        owasp_2025: owasp::A02,
        api_top10: None,
        description:
            "`allowPrivilegeEscalation` is true, so a process in the container can gain more \
             privileges than its parent — through a setuid binary, or by acquiring file \
             capabilities. That undoes much of the benefit of running as a non-root user: an \
             attacker who lands as the unprivileged application user has a documented route \
             back to root inside the container.",
        remediation:
            "Set `allowPrivilegeEscalation: false` on every container, alongside \
             `capabilities: { drop: [\"ALL\"] }`. Almost nothing needs it; the exceptions are \
             images that genuinely rely on a setuid helper, and those are worth replacing.",
        references: &["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
        confidence: Confidence::Certain,
        triage_note: "Set explicitly to true in this manifest, so this is read rather than inferred.",
    },
    kinds: K8S,
    pattern: r"(?i)allowPrivilegeEscalation\s*:\s*true",
    trigger: Trigger::Present,
    applies_if: None,
    unless: &[],
},
IacRule {
    spec: CodeSpec {
        id: "SENTINEL-IAC-K8S-WILDCARD-RBAC",
        title: "RBAC rule grants every verb on every resource",
        cvss_vector: V_CRITICAL,
        cwe: "CWE-732",
        wstg: "WSTG-ATHZ-02",
        owasp_2025: owasp::A01,
        api_top10: None,
        description:
            "A Role or ClusterRole uses `*` for verbs, resources or API groups. At cluster \
             scope this is administrative access to everything, which means it is also the \
             ability to read every Secret in the cluster — every database password, every \
             token, every private key any workload uses. A service account bound to this does \
             not need to be exploited cleverly; it only needs to be reached.",
        remediation:
            "Enumerate the verbs and resources the workload actually uses and grant exactly \
             those:\n\n\
             ```yaml\n\
             rules:\n\
             \x20 - apiGroups: [\"\"]\n\
             \x20   resources: [\"configmaps\"]\n\
             \x20   resourceNames: [\"app-config\"]\n\
             \x20   verbs: [\"get\", \"watch\"]\n\
             ```\n\n\
             Audit logs are the quickest way to discover what a workload genuinely calls. Bind \
             roles to a dedicated ServiceAccount per workload, never to `default`.",
        references: &[
            "https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
            "https://cwe.mitre.org/data/definitions/732.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "A wildcard appears in an RBAC rule. A namespaced Role is materially less serious \
             than a ClusterRole — check `kind` before rating this.",
    },
    kinds: K8S,
    pattern: r#"(?i)(?:verbs|resources|apiGroups)\s*:\s*\[?\s*["']?\*["']?"#,
    trigger: Trigger::Present,
    applies_if: Some(r"(?im)^\s*kind\s*:\s*(?:Role|ClusterRole)\b"),
    unless: &[],
},

// ── Terraform ───────────────────────────────────────────────────────────────
IacRule {
    spec: CodeSpec {
        id: "SENTINEL-IAC-OPEN-SECURITY-GROUP",
        title: "Security group open to the entire internet",
        cvss_vector: V_CRITICAL,
        cwe: "CWE-284",
        wstg: "WSTG-CONF-05",
        owasp_2025: owasp::A01,
        api_top10: None,
        description:
            "An ingress rule allows `0.0.0.0/0` or `::/0`. Where the port is a management or \
             database service — 22, 3389, 3306, 5432, 6379, 27017, 9200 — this exposes it to \
             continuous automated scanning, and the time between a service appearing on a \
             public address and the first credential-stuffing attempt against it is measured \
             in minutes. Where the whole port range is opened, every service on the instance \
             is exposed, including the ones nobody remembers are running.",
        remediation:
            "Restrict the source to the addresses that genuinely need it — a prefix list, a \
             peered VPC CIDR, or another security group by id, which is better than a CIDR \
             because it follows instances as they change:\n\n\
             ```hcl\n\
             ingress {\n\
             \x20 from_port       = 5432\n\
             \x20 to_port         = 5432\n\
             \x20 protocol        = \"tcp\"\n\
             \x20 security_groups = [aws_security_group.app.id]\n\
             }\n\
             ```\n\n\
             For administrative access, remove the ingress rule entirely and use SSM Session \
             Manager or an equivalent, which needs no inbound port at all. Only 80 and 443 on \
             a load balancer belong open to the internet.",
        references: &[
            "https://cwe.mitre.org/data/definitions/284.html",
            "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-best-practices.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "An open CIDR appears in an ingress block. On a public load balancer serving 443 \
             this is correct and expected; on anything else it is exposure. Read the port range \
             in the same block before rating.",
    },
    kinds: TF,
    pattern: r#"(?i)cidr_blocks\s*=\s*\[[^\]]*["'](?:0\.0\.0\.0/0|::/0)["']"#,
    trigger: Trigger::Present,
    applies_if: None,
    unless: &["egress", "port = 443", "port = 80"],
},
IacRule {
    spec: CodeSpec {
        id: "SENTINEL-IAC-PUBLIC-STORAGE",
        title: "Object storage granted public access",
        cvss_vector: V_HIGH_CONF,
        cwe: "CWE-732",
        wstg: "WSTG-CONF-05",
        owasp_2025: owasp::A01,
        api_top10: None,
        description:
            "A storage bucket is configured for public read or write, or has its public-access \
             block disabled. Public read means anyone who guesses or discovers the name reads \
             everything in it — and bucket names are enumerable, and routinely enumerated. \
             Public write is worse: an attacker can place content that your users then download \
             from a hostname they trust.",
        remediation:
            "Enable the account-level and bucket-level public access blocks and serve public \
             content through a CDN with an origin access identity, so the bucket itself stays \
             private:\n\n\
             ```hcl\n\
             resource \"aws_s3_bucket_public_access_block\" \"this\" {\n\
             \x20 bucket                  = aws_s3_bucket.this.id\n\
             \x20 block_public_acls       = true\n\
             \x20 block_public_policy     = true\n\
             \x20 ignore_public_acls      = true\n\
             \x20 restrict_public_buckets = true\n\
             }\n\
             ```\n\n\
             If the bucket is already public, review its access logs before locking it down — \
             what has been read matters as much as closing it.",
        references: &[
            "https://cwe.mitre.org/data/definitions/732.html",
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "A public-access setting is declared here. A bucket that deliberately serves a \
             public website is a legitimate case — confirm what this one holds.",
    },
    kinds: TF,
    pattern: r#"(?i)(?:acl\s*=\s*["'](?:public-read|public-read-write)["']|block_public_(?:acls|policy)\s*=\s*false|restrict_public_buckets\s*=\s*false|ignore_public_acls\s*=\s*false)"#,
    trigger: Trigger::Present,
    applies_if: None,
    unless: &[],
},
IacRule {
    spec: CodeSpec {
        id: "SENTINEL-IAC-UNENCRYPTED-STORAGE",
        title: "Storage or database created without encryption at rest",
        cvss_vector: V_MED_INFO,
        cwe: "CWE-311",
        wstg: "WSTG-CRYP-04",
        owasp_2025: owasp::A04,
        api_top10: None,
        description:
            "A volume, bucket or database instance is declared with encryption explicitly \
             disabled. Encryption at rest is what makes a decommissioned disk, a copied \
             snapshot or a mis-shared backup a non-event rather than a disclosure, and on every \
             major cloud it is a single flag with no measurable performance cost.",
        remediation:
            "Set `encrypted = true` (or the provider's equivalent) and supply a customer-managed \
             key where the data warrants controlling its lifecycle:\n\n\
             ```hcl\n\
             storage_encrypted = true\n\
             kms_key_id        = aws_kms_key.db.arn\n\
             ```\n\n\
             A customer-managed key also means revoking the key revokes access to every copy of \
             the data, including snapshots you have lost track of.",
        references: &["https://cwe.mitre.org/data/definitions/311.html"],
        confidence: Confidence::Certain,
        triage_note:
            "Encryption is set to false explicitly. Read directly from the resource block; the \
             judgement is about what the store holds.",
    },
    kinds: TF,
    pattern: r"(?i)(?:encrypted|storage_encrypted|encryption_enabled|enable_encryption|at_rest_encryption_enabled)\s*=\s*false",
    trigger: Trigger::Present,
    applies_if: None,
    unless: &[],
},
IacRule {
    spec: CodeSpec {
        id: "SENTINEL-IAC-PUBLIC-DATABASE",
        title: "Managed database exposed with a public address",
        cvss_vector: V_CRITICAL,
        cwe: "CWE-284",
        wstg: "WSTG-CONF-05",
        owasp_2025: owasp::A01,
        api_top10: None,
        description:
            "A managed database instance is created with public accessibility enabled, which \
             gives it an internet-routable address. Its only remaining protection is the \
             security group and the database's own authentication — so a permissive group, a \
             weak password, or an authentication bypass in the engine is the whole distance \
             between the internet and the data.",
        remediation:
            "Set `publicly_accessible = false` and place the instance in private subnets. \
             Reach it from application workloads inside the VPC, and for human access use a \
             bastion with session recording or a VPN — not a public endpoint with an allow-list, \
             which drifts.",
        references: &["https://cwe.mitre.org/data/definitions/284.html"],
        confidence: Confidence::Certain,
        triage_note: "Set explicitly in the resource block. What it exposes depends on the paired security group.",
    },
    kinds: TF,
    pattern: r"(?i)publicly_accessible\s*=\s*true",
    trigger: Trigger::Present,
    applies_if: None,
    unless: &[],
},
IacRule {
    spec: CodeSpec {
        id: "SENTINEL-IAC-IAM-WILDCARD",
        title: "IAM policy grants every action on every resource",
        cvss_vector: V_CRITICAL,
        cwe: "CWE-732",
        wstg: "WSTG-ATHZ-02",
        owasp_2025: owasp::A01,
        api_top10: None,
        description:
            "An IAM policy allows `\"Action\": \"*\"` on `\"Resource\": \"*\"`. Whatever \
             principal holds it can do anything in the account: read every bucket, decrypt with \
             every key, create new users, and delete the audit trail that would show it \
             happened. Attached to a workload role, it means any compromise of that workload is \
             a compromise of the account.",
        remediation:
            "Grant the specific actions on the specific resources. Generate the starting point \
             from real usage — IAM Access Analyzer builds a policy from CloudTrail — then \
             tighten it, and add conditions (source VPC, MFA, tag match) where they apply. \
             Set a permissions boundary on roles that others can modify, so a future edit \
             cannot widen past the ceiling.",
        references: &[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
            "https://cwe.mitre.org/data/definitions/732.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "A wildcard action and resource appear in a policy document. Some service-linked \
             roles legitimately require breadth — check which principal this attaches to.",
    },
    kinds: TF,
    pattern: r#"(?s)"Action"\s*:\s*\[?\s*"\*"[^}]{0,200}?"Resource"\s*:\s*\[?\s*"\*""#,
    trigger: Trigger::Present,
    applies_if: None,
    unless: &[],
},
IacRule {
    spec: CodeSpec {
        id: "SENTINEL-IAC-NO-LOGGING",
        title: "Audit or access logging explicitly disabled",
        cvss_vector: V_MED_INFO,
        cwe: "CWE-778",
        wstg: "WSTG-CONF-02",
        owasp_2025: owasp::A09,
        api_top10: None,
        description:
            "Logging is turned off on a resource that would otherwise record who did what. \
             Nothing about this is exploitable on its own, and that is exactly why it matters: \
             it is the control that turns an incident into a bounded, answerable question. \
             Without it, \"what did they access\" has no answer, and the response has to assume \
             the worst about everything.",
        remediation:
            "Enable logging, ship it somewhere the workload's own credentials cannot delete, \
             and set a retention period that matches your obligations — 90 days is a common \
             floor and 400 days is what an intrusion investigation usually needs. Alert on the \
             logging configuration itself changing.",
        references: &["https://cwe.mitre.org/data/definitions/778.html"],
        confidence: Confidence::Firm,
        triage_note:
            "A logging flag is set to false. Logging supplied by a separate resource or an \
             organisation-wide trail would not appear here — check before reporting.",
    },
    kinds: TF,
    pattern: r"(?i)(?:enable_logging|logging_enabled|access_logs?[\s_]*\{?[^}]*enabled)\s*=\s*false|cloudwatch_logs_enabled\s*=\s*false",
    trigger: Trigger::Present,
    applies_if: None,
    unless: &[],
},

// ── CI/CD ───────────────────────────────────────────────────────────────────
IacRule {
    spec: CodeSpec {
        id: "SENTINEL-IAC-CI-UNTRUSTED-CHECKOUT",
        title: "Workflow runs untrusted code with access to secrets",
        cvss_vector: V_CRITICAL,
        cwe: "CWE-829",
        wstg: "WSTG-CONF-02",
        owasp_2025: owasp::A08,
        api_top10: None,
        description:
            "The workflow triggers on `pull_request_target`, which runs in the context of the \
             base repository with access to its secrets and a write-capable token, while \
             checking out the pull request's code. Anyone who can open a pull request — which \
             on a public repository is anyone at all — can therefore run code with the \
             repository's secrets in scope. This is among the most exploited CI \
             misconfigurations there is, and it is usually introduced to make a legitimate \
             workflow work on fork PRs.",
        remediation:
            "Split the workflow. Build and test untrusted code with `pull_request`, which has \
             no secrets and a read-only token. Do the privileged part in a separate \
             `workflow_run` that consumes the first one's artifacts and never checks out the \
             contributor's code.\n\n\
             If `pull_request_target` genuinely must stay, do not check out the PR ref, do not \
             run any build or install step from it, and require an approving label from a \
             maintainer before the job runs.",
        references: &[
            "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
            "https://cwe.mitre.org/data/definitions/829.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "The trigger is present. It is only exploitable if the job also checks out the PR \
             head and executes something from it — check the checkout step's `ref` before \
             rating this critical.",
    },
    kinds: CI,
    pattern: r"(?im)^\s*pull_request_target\s*:",
    trigger: Trigger::Present,
    applies_if: None,
    unless: &[],
},
IacRule {
    spec: CodeSpec {
        id: "SENTINEL-IAC-CI-SCRIPT-INJECTION",
        title: "Untrusted workflow input interpolated into a shell step",
        cvss_vector: V_CRITICAL,
        cwe: "CWE-78",
        wstg: "WSTG-INPV-12",
        owasp_2025: owasp::A05,
        api_top10: None,
        description:
            "A `${{ }}` expression carrying attacker-controllable text — a pull request title, \
             a branch name, an issue body, a commit message — is interpolated directly into a \
             `run` block. GitHub substitutes the value into the script *before* the shell sees \
             it, so it is not a shell variable that can be quoted: it becomes part of the \
             script. A branch named with a backtick and a command executes that command on the \
             runner, with the job's token and secrets.",
        remediation:
            "Pass the value through the environment, where the shell treats it as data:\n\n\
             ```yaml\n\
             - env:\n\
             \x20   TITLE: ${{ github.event.pull_request.title }}\n\
             \x20 run: echo \"$TITLE\"\n\
             ```\n\n\
             The expression is evaluated when the environment is built, and `$TITLE` is a shell \
             variable from then on — quoting it is enough. Apply this to every field a \
             contributor can set.",
        references: &[
            "https://securitylab.github.com/resources/github-actions-untrusted-input/",
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "An interpolation of a user-settable field appears inside a run block. Confirm the \
             specific field is contributor-controllable; `github.sha` is not, `github.head_ref` \
             is.",
    },
    kinds: CI,
    pattern: r"\$\{\{\s*github\.(?:event\.(?:issue|pull_request|comment|discussion)\.(?:title|body)|head_ref|event\.head_commit\.message|event\.workflow_run\.head_branch)",
    trigger: Trigger::Present,
    applies_if: Some(r"(?im)^\s*-?\s*run\s*:"),
    unless: &[],
},
IacRule {
    spec: CodeSpec {
        id: "SENTINEL-IAC-CI-UNPINNED-ACTION",
        title: "Third-party CI action referenced by a mutable tag",
        cvss_vector: V_MED_LIMITED,
        cwe: "CWE-1357",
        wstg: "WSTG-CONF-02",
        owasp_2025: owasp::A08,
        api_top10: None,
        description:
            "A third-party action is referenced by branch or tag rather than by commit SHA. \
             Both are mutable and both are under the action author's control, so whatever they \
             push next runs inside your pipeline with your secrets — no compromise of your \
             repository required, only of theirs. Several supply-chain incidents have worked \
             exactly this way, including ones where a maintained action was retagged after a \
             maintainer account was taken over.",
        remediation:
            "Pin to a full commit SHA, with the version in a trailing comment so the line stays \
             readable:\n\n\
             ```yaml\n\
             - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3 # v3.5.0\n\
             ```\n\n\
             Dependabot updates SHA pins and writes the new version into the comment, so this \
             costs nothing ongoing. Restrict which actions may run at all in the \
             organisation's Actions policy.",
        references: &[
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
            "https://cwe.mitre.org/data/definitions/1357.html",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "The `uses` reference is a tag rather than a SHA. Actions published by GitHub \
             itself carry lower risk than one from an individual account, but the mechanism is \
             identical.",
    },
    kinds: CI,
    pattern: r"(?im)^\s*-?\s*uses\s*:\s*[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@(?:v?[0-9][\w.-]*|main|master|latest)\s*$",
    trigger: Trigger::Present,
    applies_if: None,
    unless: &["@sha256", "# v"],
},
IacRule {
    spec: CodeSpec {
        id: "SENTINEL-IAC-CI-BROAD-TOKEN",
        title: "Workflow token granted write permissions by default",
        cvss_vector: V_HIGH_INTEG,
        cwe: "CWE-732",
        wstg: "WSTG-ATHZ-02",
        owasp_2025: owasp::A01,
        api_top10: None,
        description:
            "The workflow requests `write-all`, or grants write across the board, rather than \
             the specific permissions its jobs need. Any step in that workflow — including one \
             inside a third-party action several dependencies deep — can then push commits, \
             publish packages, alter releases and approve its own pull requests using the \
             job's token.",
        remediation:
            "Set the default to read-only at the workflow level and raise it per job, only \
             where needed:\n\n\
             ```yaml\n\
             permissions:\n\
             \x20 contents: read\n\n\
             jobs:\n\
             \x20 release:\n\
             \x20   permissions:\n\
             \x20     contents: write      # this job publishes; the others do not\n\
             ```\n\n\
             Set the organisation-wide default to read-only as well, so a new workflow starts \
             from the safe end.",
        references: &["https://docs.github.com/en/actions/security-guides/automatic-token-authentication"],
        confidence: Confidence::Certain,
        triage_note: "Read directly from the permissions block; the judgement is about what the workflow does.",
    },
    kinds: CI,
    pattern: r"(?im)permissions\s*:\s*write-all|^\s*permissions\s*:\s*$\n(?:\s+\w+\s*:\s*write\s*$\n?){3,}",
    trigger: Trigger::Present,
    applies_if: None,
    unless: &[],
},

// ── Anywhere ────────────────────────────────────────────────────────────────
IacRule {
    spec: CodeSpec {
        id: "SENTINEL-IAC-HARDCODED-CREDENTIAL",
        title: "Credential written into an infrastructure definition",
        cvss_vector: V_HIGH_CONF,
        cwe: "CWE-798",
        wstg: "WSTG-ATHN-07",
        owasp_2025: owasp::A07,
        api_top10: None,
        description:
            "A password or key is written as a literal in an infrastructure file. Beyond the \
             obvious — everyone with repository access has it, and it is in the history — \
             Terraform additionally writes every attribute into its state file, so the \
             credential is duplicated into wherever the state is stored, usually a bucket with \
             a broader read list than the repository has.",
        remediation:
            "Take the value from a secret manager at apply time:\n\n\
             ```hcl\n\
             data \"aws_secretsmanager_secret_version\" \"db\" {\n\
             \x20 secret_id = \"prod/db/password\"\n\
             }\n\n\
             resource \"aws_db_instance\" \"main\" {\n\
             \x20 password = data.aws_secretsmanager_secret_version.db.secret_string\n\
             }\n\
             ```\n\n\
             Note that the value still lands in state — so encrypt the state backend, restrict \
             who can read it, and prefer a managed-rotation credential the module never sees at \
             all.",
        references: &[
            "https://cwe.mitre.org/data/definitions/798.html",
            "https://developer.hashicorp.com/terraform/language/state/sensitive-data",
        ],
        confidence: Confidence::Firm,
        triage_note:
            "A credential-shaped assignment with a literal value. Confirm it is not a \
             placeholder or a local development default before treating it as a live \
             credential.",
    },
    kinds: ANY,
    pattern: r#"(?i)(?:password|secret|api_?key|access_?key|token|passphrase)\s*[:=]\s*["'][^"'$\{\n]{8,}["']"#,
    trigger: Trigger::Present,
    applies_if: None,
    unless: &["var.", "data.", "${", "vault_", "_FILE", "secretKeyRef", "valueFrom", "changeme", "example", "REPLACE"],
},
];

pub struct NativeIacAdapter;

#[async_trait]
impl ScannerAdapter for NativeIacAdapter {
    fn name(&self) -> &'static str {
        INFRASTRUCTURE
    }

    async fn healthcheck(&self) -> Result<bool> {
        Ok(true)
    }

    async fn run(&self, target: &Target, _config_json: &str) -> Result<Vec<Finding>> {
        let Some(repo) = target.repo_ref.as_deref().filter(|r| !r.trim().is_empty()) else {
            tracing::info!("Sentinel Infrastructure: no source repository to read");
            return Ok(Vec::new());
        };
        let root = std::path::PathBuf::from(repo);
        let codebase = tokio::task::spawn_blocking(move || {
            codebase::walk(&root, &WalkLimits::default())
        })
        .await??;

        let mut findings = scan(&codebase, target.id, Uuid::new_v4());
        for f in &mut findings {
            sentinel_core::scoring::priority::PriorityScoringEngine::score_and_explain(f);
        }
        tracing::info!(finding_count = findings.len(), "Sentinel Infrastructure: complete");
        Ok(findings)
    }
}

struct Compiled {
    rule: &'static IacRule,
    pattern: Regex,
    applies_if: Option<Regex>,
}

fn compiled() -> &'static [Compiled] {
    static CACHE: OnceLock<Vec<Compiled>> = OnceLock::new();
    CACHE.get_or_init(|| {
        all()
            .iter()
            .filter_map(|rule| {
                let pattern = Regex::new(rule.pattern)
                    .map_err(|e| tracing::error!(rule = rule.spec.id, error = %e, "IaC rule dropped"))
                    .ok()?;
                let applies_if = match rule.applies_if {
                    Some(p) => Some(Regex::new(p).ok()?),
                    None => None,
                };
                Some(Compiled { rule, pattern, applies_if })
            })
            .collect()
    })
}

/// Run every IaC rule over every infrastructure file in the codebase.
pub fn scan(codebase: &Codebase, target_id: Uuid, scan_id: Uuid) -> Vec<Finding> {
    let mut findings = Vec::new();

    for file in &codebase.files {
        let Some(kind) = Kind::of(file) else { continue };

        for c in compiled() {
            if !c.rule.kinds.contains(&kind) {
                continue;
            }
            // The gate for the whole file: a "no USER instruction" rule has
            // nothing to say about a file that builds no image.
            if let Some(gate) = &c.applies_if {
                if !gate.is_match(&file.content) {
                    continue;
                }
            }
            if c.rule.unless.iter().any(|u| file.content.contains(u))
                && c.rule.trigger == Trigger::Absent
            {
                continue;
            }

            match c.rule.trigger {
                Trigger::Absent => {
                    if !c.pattern.is_match(&file.content) {
                        findings.push(fb::build(
                            &c.rule.spec,
                            INFRASTRUCTURE,
                            target_id,
                            scan_id,
                            &CodeMatch {
                                file: &file.relative,
                                line: 0,
                                snippet: format!(
                                    "{} — the expected declaration is absent from this file",
                                    file.relative
                                ),
                                detail: format!(
                                    "{} at {}; the setting this rule looks for is not declared \
                                     anywhere in the file, so the platform default applies",
                                    kind.label(),
                                    file.relative
                                ),
                                context: Vec::new(),
                            },
                        ));
                    }
                }
                Trigger::Present => {
                    // One finding per file per rule: the same misconfiguration
                    // on six lines of one manifest is one thing to fix.
                    let hit = file
                        .content
                        .lines()
                        .enumerate()
                        .map(|(i, l)| (i + 1, l))
                        .find(|(_, line)| {
                            c.pattern.is_match(line)
                                && !c.rule.unless.iter().any(|u| line.contains(u))
                        });

                    // A multi-line pattern will not match any single line, so
                    // fall back to matching the whole file and anchoring the
                    // finding at the first line of the match.
                    let (number, text) = match hit {
                        Some(found) => found,
                        None => match c.pattern.find(&file.content) {
                            Some(m) => {
                                if c.rule.unless.iter().any(|u| m.as_str().contains(u)) {
                                    continue;
                                }
                                let line_no = file.content[..m.start()].lines().count().max(1);
                                (line_no, m.as_str().lines().next().unwrap_or(""))
                            }
                            None => continue,
                        },
                    };

                    findings.push(fb::build(
                        &c.rule.spec,
                        INFRASTRUCTURE,
                        target_id,
                        scan_id,
                        &CodeMatch {
                            file: &file.relative,
                            line: number,
                            snippet: fb::redact_snippet(text),
                            detail: format!("{} at {}", kind.label(), file.relative),
                            context: fb::context_lines(&file.content, number, 3),
                        },
                    ));
                }
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::static_engine::codebase::{Provenance, WalkStop};
    use sentinel_core::models::finding::Severity;
    use std::collections::HashSet;
    use std::path::PathBuf;

    fn file(relative: &str, content: &str) -> SourceFile {
        SourceFile {
            path: PathBuf::from(format!("/repo/{relative}")),
            relative: relative.to_string(),
            extension: relative.rsplit('.').next().unwrap_or("").to_string(),
            provenance: Provenance::Authored,
            size_bytes: content.len() as u64,
            content: content.to_string(),
        }
    }

    fn run(files: Vec<SourceFile>) -> Vec<Finding> {
        let cb = Codebase {
            root: PathBuf::from("/repo"),
            files,
            skipped: vec![],
            stopped_because: WalkStop::Exhausted,
        };
        scan(&cb, Uuid::new_v4(), Uuid::new_v4())
    }

    fn has(findings: &[Finding], fragment: &str) -> bool {
        findings.iter().any(|f| f.title.contains(fragment))
    }

    #[test]
    fn every_rule_compiles_and_carries_complete_metadata() {
        assert_eq!(compiled().len(), all().len(), "a rule failed to compile");
        let mut seen = HashSet::new();
        for rule in all() {
            let s = &rule.spec;
            assert!(seen.insert(s.id), "duplicate rule id {}", s.id);
            assert!(s.score() > 0.0, "{} has an unparseable vector", s.id);
            assert!(s.cwe.starts_with("CWE-"), "{} has no CWE", s.id);
            assert!(s.wstg.starts_with("WSTG-"), "{} has no WSTG", s.id);
            assert!(
                owasp::is_known(s.owasp_2025),
                "{} maps to {:?}, which is not an OWASP Top 10:2025 category",
                s.id,
                s.owasp_2025
            );
            assert!(!s.references.is_empty(), "{} cites nothing", s.id);
            assert!(s.description.len() > 200, "{} description is too thin", s.id);
            assert!(s.remediation.len() > 120, "{} remediation is too thin", s.id);
            assert!(!rule.kinds.is_empty(), "{} applies to no file kind", s.id);
        }
    }

    /// An `Absent` rule must declare what makes it applicable, or it fires on
    /// every file of its kind including ones the rule has nothing to say about.
    #[test]
    fn absence_rules_declare_an_applicability_gate() {
        for rule in all().iter().filter(|r| r.trigger == Trigger::Absent) {
            assert!(
                rule.applies_if.is_some(),
                "{} fires on absence with no gate",
                rule.spec.id
            );
        }
    }

    #[test]
    fn file_kinds_are_recognised_by_name_and_by_content() {
        assert_eq!(Kind::of(&file("Dockerfile", "FROM x")), Some(Kind::Dockerfile));
        assert_eq!(Kind::of(&file("api.dockerfile", "FROM x")), Some(Kind::Dockerfile));
        assert_eq!(Kind::of(&file("docker-compose.yml", "services:")), Some(Kind::Compose));
        assert_eq!(Kind::of(&file("main.tf", "resource {}")), Some(Kind::Terraform));
        assert_eq!(
            Kind::of(&file(".github/workflows/ci.yml", "on: push")),
            Some(Kind::Workflow)
        );
        assert_eq!(
            Kind::of(&file("deploy/app.yaml", "apiVersion: apps/v1\nkind: Deployment")),
            Some(Kind::Kubernetes)
        );
        assert_eq!(Kind::of(&file("config.yaml", "server:\n  port: 8080")), None);
        assert_eq!(Kind::of(&file("src/main.rs", "fn main() {}")), None);
    }

    #[test]
    fn a_dockerfile_with_no_user_instruction_is_reported() {
        let f = run(vec![file("Dockerfile", "FROM node:20\nCOPY . .\nCMD [\"node\", \"app.js\"]")]);
        assert!(has(&f, "runs as root"), "{:?}", f.iter().map(|x| &x.title).collect::<Vec<_>>());
    }

    #[test]
    fn a_dockerfile_that_drops_privilege_is_not_reported() {
        let f = run(vec![file(
            "Dockerfile",
            "FROM node:20@sha256:abc\nRUN adduser app\nUSER 10001\nCMD [\"node\"]",
        )]);
        assert!(!has(&f, "runs as root"));
    }

    #[test]
    fn a_privileged_container_is_critical() {
        let f = run(vec![file("docker-compose.yml", "services:\n  app:\n    privileged: true")]);
        let finding = f.iter().find(|x| x.title.contains("privileged")).expect("reported");
        assert_eq!(finding.severity, Severity::Critical);
        assert!(finding.remediation.contains("drop"), "the fix names the capability drop");
    }

    #[test]
    fn mounting_the_docker_socket_is_reported() {
        let f = run(vec![file(
            "docker-compose.yml",
            "services:\n  ci:\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock",
        )]);
        assert!(has(&f, "Docker socket"));
    }

    #[test]
    fn a_mutable_base_image_tag_is_reported_and_a_digest_pin_is_not() {
        assert!(has(&run(vec![file("Dockerfile", "FROM node:latest\nUSER 1000")]), "mutable tag"));
        assert!(has(&run(vec![file("Dockerfile", "FROM ubuntu\nUSER 1000")]), "mutable tag"));
        assert!(!has(
            &run(vec![file("Dockerfile", "FROM node:20@sha256:abcdef\nUSER 1000")]),
            "mutable tag"
        ));
    }

    #[test]
    fn a_curl_pipe_shell_in_a_build_is_reported() {
        let f = run(vec![file("Dockerfile", "FROM x@sha256:a\nUSER 1\nRUN curl -sSL https://get.example.com | sh")]);
        assert!(has(&f, "Remote script"));
    }

    #[test]
    fn a_verified_download_is_not_reported() {
        let f = run(vec![file(
            "Dockerfile",
            "FROM x@sha256:a\nUSER 1\nRUN curl -o i.sh https://e.com/i.sh && sha256sum -c sums && sh i.sh",
        )]);
        assert!(!has(&f, "Remote script"));
    }

    #[test]
    fn an_open_security_group_is_reported() {
        let f = run(vec![file(
            "main.tf",
            "resource \"aws_security_group\" \"db\" {\n  ingress {\n    from_port = 5432\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}",
        )]);
        assert!(has(&f, "open to the entire internet"));
        let finding = f.iter().find(|x| x.title.contains("open to the entire")).unwrap();
        assert_eq!(finding.affected_component, "main.tf:4");
    }

    #[test]
    fn an_iam_policy_allowing_everything_is_reported() {
        let f = run(vec![file(
            "iam.tf",
            r#"policy = jsonencode({ "Statement": [{ "Effect": "Allow", "Action": "*", "Resource": "*" }] })"#,
        )]);
        assert!(has(&f, "every action on every resource"));
    }

    #[test]
    fn a_public_database_and_an_unencrypted_volume_are_both_reported() {
        let f = run(vec![file(
            "db.tf",
            "resource \"aws_db_instance\" \"m\" {\n  publicly_accessible = true\n  storage_encrypted = false\n}",
        )]);
        assert!(has(&f, "public address"));
        assert!(has(&f, "without encryption at rest"));
    }

    #[test]
    fn a_workload_with_no_security_context_is_reported() {
        let f = run(vec![file(
            "deploy.yaml",
            "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: app",
        )]);
        assert!(has(&f, "no security context"));
    }

    /// The gate: a Service manifest is not a workload and has no security
    /// context to declare.
    #[test]
    fn a_non_workload_manifest_is_not_asked_for_a_security_context() {
        let f = run(vec![file(
            "svc.yaml",
            "apiVersion: v1\nkind: Service\nspec:\n  ports:\n    - port: 80",
        )]);
        assert!(!has(&f, "no security context"));
    }

    #[test]
    fn a_wildcard_rbac_rule_is_reported_only_on_a_role_manifest() {
        let role = run(vec![file(
            "rbac.yaml",
            "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nrules:\n  - apiGroups: [\"*\"]\n    verbs: [\"*\"]",
        )]);
        assert!(has(&role, "every verb on every resource"));

        let other = run(vec![file(
            "cm.yaml",
            "apiVersion: v1\nkind: ConfigMap\ndata:\n  pattern: \"*\"",
        )]);
        assert!(!has(&other, "every verb on every resource"));
    }

    #[test]
    fn pull_request_target_is_reported() {
        let f = run(vec![file(
            ".github/workflows/ci.yml",
            "on:\n  pull_request_target:\n    types: [opened]\njobs:\n  a:\n    steps: []",
        )]);
        assert!(has(&f, "untrusted code with access to secrets"));
    }

    #[test]
    fn workflow_script_injection_is_reported() {
        let f = run(vec![file(
            ".github/workflows/ci.yml",
            "jobs:\n  a:\n    steps:\n      - run: echo \"${{ github.event.pull_request.title }}\"",
        )]);
        assert!(has(&f, "interpolated into a shell step"));
    }

    #[test]
    fn an_unpinned_action_is_reported_and_a_sha_pin_is_not() {
        assert!(has(
            &run(vec![file(".github/workflows/ci.yml", "    steps:\n      - uses: actions/checkout@v4")]),
            "mutable tag"
        ));
        assert!(!has(
            &run(vec![file(
                ".github/workflows/ci.yml",
                "    steps:\n      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3 # v4"
            )]),
            "mutable tag"
        ));
    }

    /// A value read from a variable is the recommended pattern and must not be
    /// reported as a hardcoded credential.
    #[test]
    fn a_credential_read_from_a_variable_is_not_reported() {
        let f = run(vec![file(
            "db.tf",
            "resource \"aws_db_instance\" \"m\" {\n  password = var.db_password\n}",
        )]);
        assert!(!has(&f, "Credential written into"));
    }

    #[test]
    fn a_literal_credential_in_terraform_is_reported() {
        let f = run(vec![file(
            "db.tf",
            "resource \"aws_db_instance\" \"m\" {\n  password = \"Pr0dDbP4ssw0rd!\"\n}",
        )]);
        assert!(has(&f, "Credential written into"));
    }

    #[test]
    fn a_secret_reference_in_kubernetes_is_not_reported_as_hardcoded() {
        let f = run(vec![file(
            "deploy.yaml",
            "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - env:\n        - name: DB_PASSWORD\n          valueFrom:\n            secretKeyRef:\n              name: db\n              key: password\n  securityContext:\n    runAsNonRoot: true",
        )]);
        assert!(!has(&f, "Credential written into"));
    }

    #[test]
    fn a_file_that_is_not_infrastructure_produces_nothing() {
        assert!(run(vec![file("src/app.js", "const privileged = true;")]).is_empty());
    }

    #[tokio::test]
    async fn the_engine_is_always_available() {
        assert!(NativeIacAdapter.healthcheck().await.unwrap());
        assert_eq!(NativeIacAdapter.name(), INFRASTRUCTURE);
    }
}
