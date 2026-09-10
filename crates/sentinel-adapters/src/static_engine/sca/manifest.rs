//! Reading what an application actually depends on.
//!
//! There is a real difference between a manifest and a lockfile, and a scanner
//! that ignores it reports the wrong thing. `package.json` says "any 4.x" and
//! `package-lock.json` says "4.17.20" — only the second is a fact about what is
//! deployed, and only the second can be matched against an advisory. So the
//! lockfiles are read first and the manifests are read only for what a lockfile
//! cannot supply: which dependencies the application asked for directly, as
//! opposed to the hundreds it inherited.
//!
//! That distinction survives into the report, because it changes the remediation
//! entirely. A vulnerable direct dependency is a version bump the team controls.
//! A vulnerable transitive one four levels down is a conversation with whoever
//! owns the package in between, or an override — and telling a developer to
//! "upgrade `minimist`" when nothing in their code mentions it is how a
//! dependency report gets ignored.
//!
//! Every parser here is deliberately tolerant: a lockfile it cannot fully
//! understand yields the packages it could read rather than an error. Half a
//! dependency tree scanned is worth more than a stage that failed.

use serde_json::Value;
use std::collections::BTreeMap;

/// Package ecosystems, named as OSV names them so the identifiers can be sent
/// to the advisory database without translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ecosystem {
    Npm,
    PyPI,
    Go,
    CratesIo,
    Maven,
    Packagist,
    RubyGems,
    NuGet,
    Hex,
}

impl Ecosystem {
    /// The identifier OSV expects in a query.
    pub fn osv_name(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPI => "PyPI",
            Ecosystem::Go => "Go",
            Ecosystem::CratesIo => "crates.io",
            Ecosystem::Maven => "Maven",
            Ecosystem::Packagist => "Packagist",
            Ecosystem::RubyGems => "RubyGems",
            Ecosystem::NuGet => "NuGet",
            Ecosystem::Hex => "Hex",
        }
    }

    /// What a report calls it.
    pub fn label(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPI => "PyPI (Python)",
            Ecosystem::Go => "Go modules",
            Ecosystem::CratesIo => "crates.io (Rust)",
            Ecosystem::Maven => "Maven (JVM)",
            Ecosystem::Packagist => "Packagist (PHP)",
            Ecosystem::RubyGems => "RubyGems",
            Ecosystem::NuGet => "NuGet (.NET)",
            Ecosystem::Hex => "Hex (Elixir)",
        }
    }

    /// The command that upgrades one package in this ecosystem.
    pub fn upgrade_command(self, name: &str, version: &str) -> String {
        match self {
            Ecosystem::Npm => format!("npm install {name}@{version}"),
            Ecosystem::PyPI => format!("pip install '{name}=={version}'"),
            Ecosystem::Go => format!("go get {name}@v{}", version.trim_start_matches('v')),
            Ecosystem::CratesIo => format!("cargo update -p {name} --precise {version}"),
            Ecosystem::Maven => format!("update the <version> of {name} to {version} in pom.xml"),
            Ecosystem::Packagist => format!("composer require {name}:{version}"),
            Ecosystem::RubyGems => format!("bundle update {name}  # to {version}"),
            Ecosystem::NuGet => format!("dotnet add package {name} --version {version}"),
            Ecosystem::Hex => format!("update {name} to {version} in mix.exs, then mix deps.get"),
        }
    }
}

/// One resolved dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    /// Repository-relative path of the file this was read from.
    pub manifest: String,
    /// Whether the application declares this itself, or inherited it.
    pub direct: bool,
}

impl Package {
    /// The identity used for deduplication: the same package at the same
    /// version read from two lockfiles is one dependency.
    pub fn key(&self) -> (Ecosystem, String, String) {
        (self.ecosystem, self.name.to_ascii_lowercase(), self.version.clone())
    }
}

/// Everything read from one repository's dependency files.
#[derive(Debug, Default)]
pub struct Inventory {
    pub packages: Vec<Package>,
    /// Manifest files that were found and read, for the coverage record.
    pub sources: Vec<String>,
    /// Manifests present but unresolvable — a `package.json` with no lockfile,
    /// for example. Reported, because "no vulnerable dependencies" while a
    /// whole ecosystem went unread is a misleading claim.
    pub unresolved: Vec<(String, String)>,
}

impl Inventory {
    /// Collapse duplicates, preferring the direct declaration where both exist.
    pub fn deduplicated(mut self) -> Inventory {
        let mut best: BTreeMap<(Ecosystem, String, String), Package> = BTreeMap::new();
        for pkg in self.packages.drain(..) {
            best.entry(pkg.key())
                .and_modify(|existing| {
                    if pkg.direct {
                        existing.direct = true;
                    }
                })
                .or_insert(pkg);
        }
        self.packages = best.into_values().collect();
        self
    }
}

/// Read every dependency file in the codebase.
pub fn collect(codebase: &crate::static_engine::codebase::Codebase) -> Inventory {
    let mut inv = Inventory::default();
    // Direct-dependency names per ecosystem, learned from the manifests, so a
    // lockfile entry can be classified even though lockfiles do not record it.
    let mut declared: BTreeMap<Ecosystem, Vec<String>> = BTreeMap::new();

    for file in &codebase.files {
        let name = file.file_name();
        match name {
            "package.json" => {
                declared
                    .entry(Ecosystem::Npm)
                    .or_default()
                    .extend(npm_declared(&file.content));
            }
            "Pipfile" | "pyproject.toml" => {
                declared
                    .entry(Ecosystem::PyPI)
                    .or_default()
                    .extend(python_declared(&file.content));
            }
            _ => {}
        }
    }

    for file in &codebase.files {
        let name = file.file_name();
        let path = file.relative.as_str();
        let found = match name {
            "package-lock.json" => npm_lock(&file.content, path),
            "yarn.lock" => yarn_lock(&file.content, path),
            "pnpm-lock.yaml" => pnpm_lock(&file.content, path),
            "requirements.txt" | "requirements-dev.txt" | "requirements_dev.txt" => {
                requirements_txt(&file.content, path)
            }
            "Pipfile.lock" => pipfile_lock(&file.content, path),
            "poetry.lock" => toml_package_blocks(&file.content, path, Ecosystem::PyPI),
            "Cargo.lock" => toml_package_blocks(&file.content, path, Ecosystem::CratesIo),
            "go.mod" => go_mod(&file.content, path),
            "go.sum" => go_sum(&file.content, path),
            "pom.xml" => pom_xml(&file.content, path),
            "composer.lock" => composer_lock(&file.content, path),
            "Gemfile.lock" => gemfile_lock(&file.content, path),
            "packages.config" => packages_config(&file.content, path),
            "mix.lock" => mix_lock(&file.content, path),
            _ if name.ends_with(".csproj") || name.ends_with(".fsproj") || name.ends_with(".vbproj") => {
                csproj(&file.content, path)
            }
            _ if name == "build.gradle" || name == "build.gradle.kts" => {
                gradle(&file.content, path)
            }
            _ => Vec::new(),
        };

        if !found.is_empty() {
            inv.sources.push(path.to_string());
            inv.packages.extend(found);
        }
    }

    // A manifest with no lockfile beside it is an ecosystem this scan cannot
    // speak about, and the report has to say so rather than imply it was clean.
    let has = |eco: Ecosystem| inv.packages.iter().any(|p| p.ecosystem == eco);
    for file in &codebase.files {
        match file.file_name() {
            "package.json" if !has(Ecosystem::Npm) && !file.relative.contains("node_modules") => {
                inv.unresolved.push((
                    file.relative.clone(),
                    "npm manifest found with no lockfile beside it. The declared ranges do not \
                     say which versions are installed, so nothing here could be matched against \
                     an advisory. Commit package-lock.json (or yarn.lock / pnpm-lock.yaml)."
                        .to_string(),
                ));
            }
            "Gemfile" if !has(Ecosystem::RubyGems) => {
                inv.unresolved.push((
                    file.relative.clone(),
                    "Gemfile found with no Gemfile.lock. Commit the lockfile so the installed \
                     gem versions can be assessed."
                        .to_string(),
                ));
            }
            "build.gradle" | "build.gradle.kts" if !has(Ecosystem::Maven) => {
                inv.unresolved.push((
                    file.relative.clone(),
                    "Gradle build found, but no versions could be resolved from it. Gradle \
                     resolves versions at build time, so run `gradle dependencies` (or use a \
                     version catalog) to produce a resolvable list."
                        .to_string(),
                ));
            }
            _ => {}
        }
    }

    // Mark direct dependencies now that every manifest has been read.
    for pkg in &mut inv.packages {
        if let Some(names) = declared.get(&pkg.ecosystem) {
            if names.iter().any(|n| n.eq_ignore_ascii_case(&pkg.name)) {
                pkg.direct = true;
            }
        }
    }

    inv.deduplicated()
}

// ── npm ──────────────────────────────────────────────────────────────────────

/// Direct dependency names from a `package.json`.
fn npm_declared(content: &str) -> Vec<String> {
    let Ok(json) = serde_json::from_str::<Value>(content) else {
        return Vec::new();
    };
    ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]
        .iter()
        .filter_map(|k| json.get(k)?.as_object())
        .flat_map(|obj| obj.keys().cloned())
        .collect()
}

/// `package-lock.json`, both the v1 shape and the v2/v3 shape.
fn npm_lock(content: &str, path: &str) -> Vec<Package> {
    let Ok(json) = serde_json::from_str::<Value>(content) else {
        return Vec::new();
    };
    let mut out = Vec::new();

    // v2/v3: a flat `packages` map keyed by install path.
    if let Some(packages) = json.get("packages").and_then(Value::as_object) {
        for (key, entry) in packages {
            // The empty key is the project itself, not a dependency.
            if key.is_empty() {
                continue;
            }
            // The installed name is the last node_modules segment, which is
            // what a scoped package such as `@scope/name` needs.
            let Some(name) = key.rsplit("node_modules/").next().filter(|n| !n.is_empty()) else {
                continue;
            };
            let Some(version) = entry.get("version").and_then(Value::as_str) else {
                continue;
            };
            out.push(Package {
                ecosystem: Ecosystem::Npm,
                name: name.to_string(),
                version: version.to_string(),
                manifest: path.to_string(),
                // The lockfile does not record this; the manifest pass does.
                direct: false,
            });
        }
    }

    // v1: a recursive `dependencies` tree.
    if out.is_empty() {
        if let Some(deps) = json.get("dependencies").and_then(Value::as_object) {
            collect_npm_v1(deps, path, &mut out);
        }
    }
    out
}

fn collect_npm_v1(deps: &serde_json::Map<String, Value>, path: &str, out: &mut Vec<Package>) {
    for (name, entry) in deps {
        if let Some(version) = entry.get("version").and_then(Value::as_str) {
            out.push(Package {
                ecosystem: Ecosystem::Npm,
                name: name.clone(),
                version: version.to_string(),
                manifest: path.to_string(),
                direct: false,
            });
        }
        if let Some(nested) = entry.get("dependencies").and_then(Value::as_object) {
            collect_npm_v1(nested, path, out);
        }
    }
}

/// `yarn.lock`, classic (v1) format.
///
/// Berry's v2+ lockfile is YAML with the same essential shape, and the same
/// line-oriented read works for both: a header line naming the specifiers,
/// then an indented `version` line.
fn yarn_lock(content: &str, path: &str) -> Vec<Package> {
    let mut out = Vec::new();
    let mut pending: Option<String> = None;

    for raw in content.lines() {
        let line = raw.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') && line.ends_with(':') {
            // `"lodash@^4.17.0", "lodash@^4.17.15":`
            let header = line.trim_end_matches(':');
            pending = header
                .split(',')
                .next()
                .map(|s| s.trim().trim_matches('"').to_string())
                .and_then(|spec| package_name_from_spec(&spec));
            continue;
        }
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("version") {
            if let Some(name) = pending.take() {
                let version = rest.trim().trim_start_matches(':').trim().trim_matches('"');
                if !version.is_empty() {
                    out.push(Package {
                        ecosystem: Ecosystem::Npm,
                        name,
                        version: version.to_string(),
                        manifest: path.to_string(),
                        direct: false,
                    });
                }
            }
        }
    }
    out
}

/// Strip the range from `name@range`, handling scoped packages whose name
/// itself starts with `@`.
fn package_name_from_spec(spec: &str) -> Option<String> {
    let (offset, rest) = if let Some(rest) = spec.strip_prefix('@') {
        (1, rest)
    } else {
        (0, spec)
    };
    let at = rest.find('@')?;
    let name = &spec[..offset + at];
    (!name.is_empty()).then(|| name.to_string())
}

/// `pnpm-lock.yaml`.
///
/// Entries appear under `packages:` as `/name/1.2.3:` (v5/v6) or
/// `/name@1.2.3:` (v9), with scoped names carrying their own slash.
fn pnpm_lock(content: &str, path: &str) -> Vec<Package> {
    let mut out = Vec::new();
    for raw in content.lines() {
        let line = raw.trim();
        if !line.starts_with('/') || !line.ends_with(':') {
            continue;
        }
        let body = line.trim_start_matches('/').trim_end_matches(':').trim_matches('\'');
        // Peer-dependency suffixes: `react-dom@18.0.0(react@18.0.0)`.
        let body = body.split('(').next().unwrap_or(body);

        let (name, version) = if let Some(idx) = body.rfind('@') {
            if idx == 0 {
                continue;
            }
            (&body[..idx], &body[idx + 1..])
        } else if let Some(idx) = body.rfind('/') {
            (&body[..idx], &body[idx + 1..])
        } else {
            continue;
        };
        if name.is_empty() || version.is_empty() || !version.starts_with(|c: char| c.is_ascii_digit()) {
            continue;
        }
        out.push(Package {
            ecosystem: Ecosystem::Npm,
            name: name.to_string(),
            version: version.to_string(),
            manifest: path.to_string(),
            direct: false,
        });
    }
    out
}

// ── Python ───────────────────────────────────────────────────────────────────

fn python_declared(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|line| {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') || l.starts_with('[') {
                return None;
            }
            let name: String = l
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
                .collect();
            (!name.is_empty()).then_some(name)
        })
        .collect()
}

/// `requirements.txt`. Only pinned versions are facts; a range is not.
fn requirements_txt(content: &str, path: &str) -> Vec<Package> {
    let mut out = Vec::new();
    for raw in content.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('-') || line.contains("://") {
            continue;
        }
        // Environment markers: `pkg==1.0; python_version < "3.9"`.
        let line = line.split(';').next().unwrap_or(line).trim();
        let Some((name, version)) = line.split_once("==") else {
            continue;
        };
        let name = name.split('[').next().unwrap_or(name).trim();
        let version = version.trim().trim_end_matches(".*");
        if name.is_empty() || version.is_empty() {
            continue;
        }
        out.push(Package {
            ecosystem: Ecosystem::PyPI,
            name: name.to_string(),
            version: version.to_string(),
            manifest: path.to_string(),
            direct: true,
        });
    }
    out
}

fn pipfile_lock(content: &str, path: &str) -> Vec<Package> {
    let Ok(json) = serde_json::from_str::<Value>(content) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for section in ["default", "develop"] {
        let Some(obj) = json.get(section).and_then(Value::as_object) else {
            continue;
        };
        for (name, entry) in obj {
            let Some(version) = entry.get("version").and_then(Value::as_str) else {
                continue;
            };
            let version = version.trim_start_matches("==").trim();
            if version.is_empty() {
                continue;
            }
            out.push(Package {
                ecosystem: Ecosystem::PyPI,
                name: name.clone(),
                version: version.to_string(),
                manifest: path.to_string(),
                direct: section == "default",
            });
        }
    }
    out
}

// ── TOML lockfiles: Cargo.lock and poetry.lock ───────────────────────────────

/// Both files use `[[package]]` blocks with `name` and `version` keys, so one
/// reader serves both rather than pulling in a TOML parser for two shapes.
fn toml_package_blocks(content: &str, path: &str, ecosystem: Ecosystem) -> Vec<Package> {
    let mut out = Vec::new();
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;

    let flush = |name: &mut Option<String>, version: &mut Option<String>, out: &mut Vec<Package>| {
        if let (Some(n), Some(v)) = (name.take(), version.take()) {
            out.push(Package {
                ecosystem,
                name: n,
                version: v,
                manifest: path.to_string(),
                direct: false,
            });
        }
    };

    for raw in content.lines() {
        let line = raw.trim();
        if line.starts_with("[[package]]") || line.starts_with('[') {
            flush(&mut name, &mut version, &mut out);
            continue;
        }
        if let Some(v) = toml_string_value(line, "name") {
            // A new name before the previous block was flushed means the block
            // ended without a header; keep the pair consistent.
            if name.is_some() {
                flush(&mut name, &mut version, &mut out);
            }
            name = Some(v);
        } else if let Some(v) = toml_string_value(line, "version") {
            version = Some(v);
        }
    }
    flush(&mut name, &mut version, &mut out);
    out
}

fn toml_string_value(line: &str, key: &str) -> Option<String> {
    let rest = line.strip_prefix(key)?.trim_start();
    let rest = rest.strip_prefix('=')?.trim();
    let value = rest.trim_matches('"').trim_matches('\'');
    (!value.is_empty() && !value.contains('{')).then(|| value.to_string())
}

// ── Go ───────────────────────────────────────────────────────────────────────

fn go_mod(content: &str, path: &str) -> Vec<Package> {
    let mut out = Vec::new();
    let mut in_require_block = false;

    for raw in content.lines() {
        let line = raw.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("require (") {
            in_require_block = true;
            continue;
        }
        if in_require_block && line == ")" {
            in_require_block = false;
            continue;
        }
        let spec = if in_require_block {
            line
        } else if let Some(rest) = line.strip_prefix("require ") {
            rest.trim()
        } else {
            continue;
        };
        let mut parts = spec.split_whitespace();
        let (Some(name), Some(version)) = (parts.next(), parts.next()) else {
            continue;
        };
        if !version.starts_with('v') {
            continue;
        }
        out.push(Package {
            ecosystem: Ecosystem::Go,
            name: name.to_string(),
            version: version.to_string(),
            manifest: path.to_string(),
            // Everything in go.mod's require list is a direct requirement
            // unless marked indirect, which the comment strip above removed —
            // so this is refined by the `// indirect` check below.
            direct: !raw.contains("// indirect"),
        });
    }
    out
}

/// `go.sum` lists the full transitive closure, which `go.mod` does not.
fn go_sum(content: &str, path: &str) -> Vec<Package> {
    let mut out = Vec::new();
    for raw in content.lines() {
        let mut parts = raw.split_whitespace();
        let (Some(name), Some(version)) = (parts.next(), parts.next()) else {
            continue;
        };
        // Each module appears twice, once with a `/go.mod` suffix.
        if version.ends_with("/go.mod") {
            continue;
        }
        if !version.starts_with('v') {
            continue;
        }
        out.push(Package {
            ecosystem: Ecosystem::Go,
            name: name.to_string(),
            version: version.to_string(),
            manifest: path.to_string(),
            direct: false,
        });
    }
    out
}

// ── JVM ──────────────────────────────────────────────────────────────────────

/// `pom.xml`. Reads only literal versions: a `${property}` reference cannot be
/// resolved without the whole effective POM, and guessing would be worse than
/// leaving it out and saying so.
fn pom_xml(content: &str, path: &str) -> Vec<Package> {
    let mut out = Vec::new();
    for block in content.split("<dependency>").skip(1) {
        let block = block.split("</dependency>").next().unwrap_or(block);
        let (Some(group), Some(artifact), Some(version)) = (
            xml_tag(block, "groupId"),
            xml_tag(block, "artifactId"),
            xml_tag(block, "version"),
        ) else {
            continue;
        };
        if version.starts_with("${") {
            continue;
        }
        out.push(Package {
            ecosystem: Ecosystem::Maven,
            name: format!("{group}:{artifact}"),
            version,
            manifest: path.to_string(),
            direct: true,
        });
    }
    out
}

fn xml_tag(block: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = block.find(&open)? + open.len();
    let end = block[start..].find(&close)? + start;
    let value = block[start..end].trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// Gradle build scripts, for the coordinates written as literals.
fn gradle(content: &str, path: &str) -> Vec<Package> {
    let mut out = Vec::new();
    for raw in content.lines() {
        let line = raw.split("//").next().unwrap_or("").trim();
        if !line.contains(':') {
            continue;
        }
        let Some(start) = line.find(['\'', '"']) else { continue };
        let quote = line.as_bytes()[start] as char;
        let Some(end) = line[start + 1..].find(quote).map(|i| i + start + 1) else {
            continue;
        };
        let coord = &line[start + 1..end];
        let parts: Vec<&str> = coord.split(':').collect();
        if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) || parts[2].starts_with('$') {
            continue;
        }
        out.push(Package {
            ecosystem: Ecosystem::Maven,
            name: format!("{}:{}", parts[0], parts[1]),
            version: parts[2].to_string(),
            manifest: path.to_string(),
            direct: true,
        });
    }
    out
}

// ── PHP, Ruby, .NET, Elixir ──────────────────────────────────────────────────

fn composer_lock(content: &str, path: &str) -> Vec<Package> {
    let Ok(json) = serde_json::from_str::<Value>(content) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (section, direct) in [("packages", true), ("packages-dev", false)] {
        let Some(list) = json.get(section).and_then(Value::as_array) else {
            continue;
        };
        for entry in list {
            let (Some(name), Some(version)) = (
                entry.get("name").and_then(Value::as_str),
                entry.get("version").and_then(Value::as_str),
            ) else {
                continue;
            };
            out.push(Package {
                ecosystem: Ecosystem::Packagist,
                name: name.to_string(),
                version: version.trim_start_matches('v').to_string(),
                manifest: path.to_string(),
                direct,
            });
        }
    }
    out
}

/// `Gemfile.lock`. Gems are listed under `GEM`/`specs:` at four-space
/// indentation, with their own dependencies indented six.
fn gemfile_lock(content: &str, path: &str) -> Vec<Package> {
    let mut out = Vec::new();
    let mut in_specs = false;
    for raw in content.lines() {
        if raw.trim() == "specs:" {
            in_specs = true;
            continue;
        }
        if !raw.starts_with(' ') && !raw.trim().is_empty() {
            in_specs = false;
            continue;
        }
        if !in_specs {
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        if indent != 4 {
            continue; // 6 is a transitive requirement line, not an installed gem
        }
        let spec = raw.trim();
        let Some((name, rest)) = spec.split_once(" (") else { continue };
        let version = rest.trim_end_matches(')');
        if name.is_empty() || version.is_empty() {
            continue;
        }
        out.push(Package {
            ecosystem: Ecosystem::RubyGems,
            name: name.to_string(),
            version: version.to_string(),
            manifest: path.to_string(),
            direct: false,
        });
    }
    out
}

fn csproj(content: &str, path: &str) -> Vec<Package> {
    let mut out = Vec::new();
    for block in content.split("<PackageReference").skip(1) {
        let block = block.split('>').next().unwrap_or(block);
        let (Some(name), Some(version)) = (
            xml_attribute(block, "Include"),
            xml_attribute(block, "Version"),
        ) else {
            continue;
        };
        if version.starts_with('$') {
            continue;
        }
        out.push(Package {
            ecosystem: Ecosystem::NuGet,
            name,
            version,
            manifest: path.to_string(),
            direct: true,
        });
    }
    out
}

fn packages_config(content: &str, path: &str) -> Vec<Package> {
    let mut out = Vec::new();
    for block in content.split("<package").skip(1) {
        let block = block.split('>').next().unwrap_or(block);
        let (Some(name), Some(version)) =
            (xml_attribute(block, "id"), xml_attribute(block, "version"))
        else {
            continue;
        };
        out.push(Package {
            ecosystem: Ecosystem::NuGet,
            name,
            version,
            manifest: path.to_string(),
            direct: true,
        });
    }
    out
}

fn xml_attribute(block: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let start = block.find(&needle)? + needle.len();
    let end = block[start..].find('"')? + start;
    let value = block[start..end].trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// `mix.lock`: `"name": {:hex, :name, "1.2.3", ...}`.
fn mix_lock(content: &str, path: &str) -> Vec<Package> {
    let mut out = Vec::new();
    for raw in content.lines() {
        let line = raw.trim();
        let Some((name_part, rest)) = line.split_once(':') else { continue };
        let name = name_part.trim().trim_matches('"');
        if name.is_empty() || !rest.contains(":hex") {
            continue;
        }
        // The version is the first quoted string after the :hex atom.
        let Some(after) = rest.split(":hex").nth(1) else { continue };
        let Some(start) = after.find('"') else { continue };
        let Some(end) = after[start + 1..].find('"').map(|i| i + start + 1) else {
            continue;
        };
        let version = &after[start + 1..end];
        if version.is_empty() {
            continue;
        }
        out.push(Package {
            ecosystem: Ecosystem::Hex,
            name: name.to_string(),
            version: version.to_string(),
            manifest: path.to_string(),
            direct: true,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(pkgs: &[Package]) -> Vec<(&str, &str)> {
        let mut v: Vec<(&str, &str)> =
            pkgs.iter().map(|p| (p.name.as_str(), p.version.as_str())).collect();
        v.sort();
        v
    }

    #[test]
    fn npm_lockfile_v3_reads_the_flat_package_map() {
        let lock = r#"{
          "lockfileVersion": 3,
          "packages": {
            "": { "name": "app", "version": "1.0.0" },
            "node_modules/lodash": { "version": "4.17.20" },
            "node_modules/@scope/pkg": { "version": "2.1.0" },
            "node_modules/a/node_modules/minimist": { "version": "0.0.8" }
          }
        }"#;
        let pkgs = npm_lock(lock, "package-lock.json");
        assert_eq!(
            names(&pkgs),
            vec![("@scope/pkg", "2.1.0"), ("lodash", "4.17.20"), ("minimist", "0.0.8")],
            "the project's own entry is not a dependency"
        );
    }

    #[test]
    fn npm_lockfile_v1_walks_the_nested_tree() {
        let lock = r#"{
          "lockfileVersion": 1,
          "dependencies": {
            "express": {
              "version": "4.17.1",
              "dependencies": { "qs": { "version": "6.7.0" } }
            }
          }
        }"#;
        assert_eq!(
            names(&npm_lock(lock, "package-lock.json")),
            vec![("express", "4.17.1"), ("qs", "6.7.0")]
        );
    }

    #[test]
    fn yarn_lock_reads_scoped_and_unscoped_entries() {
        let lock = r#"
# yarn lockfile v1

"@babel/core@^7.0.0":
  version "7.20.0"
  resolved "https://registry.yarnpkg.com/..."

lodash@^4.17.15, lodash@^4.17.20:
  version "4.17.21"
"#;
        assert_eq!(
            names(&yarn_lock(lock, "yarn.lock")),
            vec![("@babel/core", "7.20.0"), ("lodash", "4.17.21")]
        );
    }

    #[test]
    fn pnpm_lock_reads_both_the_slash_and_the_at_spellings() {
        let lock = "
packages:

  /lodash/4.17.20:
    resolution: {integrity: sha512-x}

  /@scope/pkg@2.0.1:
    resolution: {integrity: sha512-y}

  /react-dom@18.2.0(react@18.2.0):
    resolution: {integrity: sha512-z}
";
        assert_eq!(
            names(&pnpm_lock(lock, "pnpm-lock.yaml")),
            vec![("@scope/pkg", "2.0.1"), ("lodash", "4.17.20"), ("react-dom", "18.2.0")]
        );
    }

    /// A range is not a fact about what is installed, so it must not be
    /// reported as one.
    #[test]
    fn requirements_reads_pins_and_ignores_ranges() {
        let req = "\
# comment
Django==4.2.1
requests>=2.0.0
flask[async]==2.3.2
urllib3==1.26.5 ; python_version < '3.10'
-r other.txt
git+https://github.com/x/y.git
";
        assert_eq!(
            names(&requirements_txt(req, "requirements.txt")),
            vec![("Django", "4.2.1"), ("flask", "2.3.2"), ("urllib3", "1.26.5")]
        );
    }

    #[test]
    fn cargo_lock_and_poetry_lock_share_one_block_reader() {
        let cargo = r#"
[[package]]
name = "serde"
version = "1.0.190"

[[package]]
name = "tokio"
version = "1.35.1"
dependencies = ["serde"]
"#;
        assert_eq!(
            names(&toml_package_blocks(cargo, "Cargo.lock", Ecosystem::CratesIo)),
            vec![("serde", "1.0.190"), ("tokio", "1.35.1")]
        );
    }

    #[test]
    fn go_mod_distinguishes_direct_requirements_from_indirect_ones() {
        let gomod = "\
module example.com/app

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	golang.org/x/crypto v0.14.0 // indirect
)

require github.com/spf13/cobra v1.8.0
";
        let pkgs = go_mod(gomod, "go.mod");
        assert_eq!(pkgs.len(), 3);
        let direct: Vec<&str> = pkgs.iter().filter(|p| p.direct).map(|p| p.name.as_str()).collect();
        assert!(direct.contains(&"github.com/gin-gonic/gin"));
        assert!(!direct.contains(&"golang.org/x/crypto"), "indirect must not be marked direct");
    }

    #[test]
    fn go_sum_skips_the_go_mod_hash_lines() {
        let gosum = "\
github.com/x/y v1.2.3 h1:abc=
github.com/x/y v1.2.3/go.mod h1:def=
";
        assert_eq!(names(&go_sum(gosum, "go.sum")), vec![("github.com/x/y", "v1.2.3")]);
    }

    #[test]
    fn pom_reads_literal_versions_and_skips_property_references() {
        let pom = r#"
<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-text</artifactId>
      <version>1.9</version>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>lib</artifactId>
      <version>${lib.version}</version>
    </dependency>
  </dependencies>
</project>"#;
        assert_eq!(
            names(&pom_xml(pom, "pom.xml")),
            vec![("org.apache.commons:commons-text", "1.9")],
            "a property reference cannot be resolved without the effective POM"
        );
    }

    #[test]
    fn gradle_coordinates_are_read_from_both_quote_styles() {
        let build = r#"
dependencies {
    implementation 'com.google.guava:guava:31.1-jre'
    testImplementation("org.junit.jupiter:junit-jupiter:5.9.0")
    implementation "com.example:lib:$libVersion"
    implementation project(':core')
}"#;
        assert_eq!(
            names(&gradle(build, "build.gradle")),
            vec![
                ("com.google.guava:guava", "31.1-jre"),
                ("org.junit.jupiter:junit-jupiter", "5.9.0"),
            ]
        );
    }

    #[test]
    fn composer_lock_separates_runtime_from_development_packages() {
        let lock = r#"{
          "packages": [{ "name": "monolog/monolog", "version": "v2.9.1" }],
          "packages-dev": [{ "name": "phpunit/phpunit", "version": "9.6.0" }]
        }"#;
        let pkgs = composer_lock(lock, "composer.lock");
        let monolog = pkgs.iter().find(|p| p.name == "monolog/monolog").unwrap();
        assert_eq!(monolog.version, "2.9.1", "the leading v is not part of the version");
        assert!(monolog.direct);
        assert!(!pkgs.iter().find(|p| p.name.starts_with("phpunit")).unwrap().direct);
    }

    #[test]
    fn gemfile_lock_reads_installed_gems_not_their_requirements() {
        let lock = "\
GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.0.4)
      activesupport (= 7.0.4)
    nokogiri (1.13.10)

PLATFORMS
  ruby
";
        assert_eq!(
            names(&gemfile_lock(lock, "Gemfile.lock")),
            vec![("actionpack", "7.0.4"), ("nokogiri", "1.13.10")],
            "the six-space line is a requirement, not an installed gem"
        );
    }

    #[test]
    fn dotnet_project_files_yield_package_references() {
        let proj = r#"
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.3" />
    <PackageReference Include="Serilog" Version="$(SerilogVersion)" />
  </ItemGroup>
</Project>"#;
        assert_eq!(names(&csproj(proj, "App.csproj")), vec![("Newtonsoft.Json", "12.0.3")]);
    }

    #[test]
    fn mix_lock_reads_hex_packages() {
        let lock = r#"%{
  "plug": {:hex, :plug, "1.14.0", "abc", [:mix], [], "hexpm", "def"},
  "local": {:git, "https://example.com/x.git", "abc", []},
}"#;
        assert_eq!(names(&mix_lock(lock, "mix.lock")), vec![("plug", "1.14.0")]);
    }

    #[test]
    fn a_malformed_lockfile_yields_nothing_rather_than_failing_the_stage() {
        assert!(npm_lock("{not json", "package-lock.json").is_empty());
        assert!(composer_lock("<<<", "composer.lock").is_empty());
        assert!(pipfile_lock("", "Pipfile.lock").is_empty());
    }

    #[test]
    fn duplicate_entries_collapse_and_keep_the_direct_marking() {
        let inv = Inventory {
            packages: vec![
                Package { ecosystem: Ecosystem::Npm, name: "lodash".into(), version: "4.17.20".into(), manifest: "a".into(), direct: false },
                Package { ecosystem: Ecosystem::Npm, name: "lodash".into(), version: "4.17.20".into(), manifest: "b".into(), direct: true },
            ],
            ..Default::default()
        }
        .deduplicated();
        assert_eq!(inv.packages.len(), 1);
        assert!(inv.packages[0].direct, "a direct declaration anywhere makes it direct");
    }

    #[test]
    fn ecosystem_names_match_what_osv_expects() {
        assert_eq!(Ecosystem::Npm.osv_name(), "npm");
        assert_eq!(Ecosystem::PyPI.osv_name(), "PyPI");
        assert_eq!(Ecosystem::CratesIo.osv_name(), "crates.io");
        assert_eq!(Ecosystem::Maven.osv_name(), "Maven");
    }

    #[test]
    fn every_ecosystem_offers_a_concrete_upgrade_command() {
        for eco in [
            Ecosystem::Npm, Ecosystem::PyPI, Ecosystem::Go, Ecosystem::CratesIo,
            Ecosystem::Maven, Ecosystem::Packagist, Ecosystem::RubyGems,
            Ecosystem::NuGet, Ecosystem::Hex,
        ] {
            let cmd = eco.upgrade_command("pkg", "1.2.3");
            assert!(cmd.contains("pkg"), "{eco:?} command omits the package");
            assert!(cmd.contains("1.2.3"), "{eco:?} command omits the version");
        }
    }
}
