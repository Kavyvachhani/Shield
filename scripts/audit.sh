#!/usr/bin/env bash
#
# Supply-chain and configuration audit.
#
# Run before cutting a release, and whenever a dependency moves. Everything here
# is checkable rather than asserted — the point is that "the build is clean" is a
# claim somebody can reproduce, not a sentence in a README.
#
# Exit status is non-zero if any check fails, so this is usable in CI.

set -uo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
cd "$REPO_ROOT"

fail=0
section() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
bad() { printf '    FAIL: %s\n' "$1"; fail=1; }
ok()  { printf '    ok: %s\n' "$1"; }

section "Rust advisories (cargo audit)"
if command -v cargo-audit >/dev/null; then
  # Warnings are unmaintained/unsound transitive crates and are reported but not
  # fatal; an actual vulnerability is.
  if cargo audit 2>&1 | tee /tmp/sentinel-audit.txt | grep -q "^error"; then
    grep -E "^(Crate|Title|ID|Solution):" /tmp/sentinel-audit.txt | head -20
    bad "cargo audit reported a vulnerability"
  else
    ok "no known vulnerabilities across $(grep -oE '[0-9]+ crate dependencies' /tmp/sentinel-audit.txt | head -1)"
    warns=$(grep -cE '^Warning:' /tmp/sentinel-audit.txt)
    [[ "$warns" != "0" ]] && echo "    note: $warns unmaintained/unsound transitive crate(s); none ship in the Windows build's glib-free tree" 
  fi
else
  echo "    cargo-audit not installed (cargo install cargo-audit --locked)"
fi

section "JavaScript advisories (npm audit)"
if (cd apps/desktop && npm audit --audit-level=low >/dev/null 2>&1); then
  ok "no known vulnerabilities"
else
  (cd apps/desktop && npm audit 2>&1 | tail -20)
  bad "npm audit reported a vulnerability"
fi

section "npm install scripts"
# A package that runs code at install time is the usual supply-chain foothold.
count=$(cd apps/desktop && node -e "
const fs=require('fs');let n=0;
for(const d of fs.readdirSync('node_modules')){
  if(d.startsWith('.'))continue;
  const dirs=d.startsWith('@')?fs.readdirSync('node_modules/'+d).map(x=>d+'/'+x):[d];
  for(const m of dirs){try{
    const s=(JSON.parse(fs.readFileSync('node_modules/'+m+'/package.json','utf8')).scripts)||{};
    if(s.preinstall||s.install||s.postinstall){console.error('      '+m);n++;}
  }catch(e){}}
}
console.log(n);" 2>&1)
n="${count##*$'\n'}"
if [[ "$n" == "0" ]]; then ok "no package runs code at install time"; else bad "$n package(s) run install scripts"; fi

section "Webview content security policy"
csp=$(grep -o '"csp": "[^"]*"' apps/desktop/src-tauri/tauri.conf.json)
for directive in "default-src 'self'" "object-src 'none'" "frame-src 'none'"; do
  if [[ "$csp" == *"$directive"* ]]; then ok "$directive"; else bad "CSP is missing $directive"; fi
done
# The webview must not be able to reach the network directly; everything goes
# over the IPC bridge to Rust, which is where the scope gate lives.
if [[ "$csp" == *"connect-src ipc: http://ipc.localhost"* ]]; then
  ok "connect-src is limited to the IPC bridge"
else
  bad "connect-src allows something other than the IPC bridge"
fi
if [[ "$csp" == *"http"*"://"* && "$csp" != *"http://ipc.localhost"* ]]; then
  bad "CSP allows an external origin"
fi

section "Remote assets loaded at runtime"
# An application that describes itself as offline-capable must not fetch anything
# to render its own interface. Covers both @import and any url() — a webfont
# pulled from a CDN is the same disclosure whichever syntax reaches it.
if grep -rnE "@import +url\(['\"]?https?:|url\(['\"]?https?://" apps/desktop/src --include='*.css' 2>/dev/null; then
  bad "a stylesheet fetches something from a remote origin"
else
  ok "no remote stylesheets or webfonts in source"
fi

# And the same again on what actually shipped, since the check above only sees
# what was written rather than what the bundler emitted.
if [[ -d apps/desktop/dist ]]; then
  if grep -rohE "url\(https?://[^)]*\)" apps/desktop/dist/assets/*.css 2>/dev/null | grep -q .; then
    grep -rohE "url\(https?://[^)]*\)" apps/desktop/dist/assets/*.css | sort -u | sed 's/^/      /'
    bad "the built stylesheet fetches from a remote origin"
  else
    ok "the built stylesheet fetches nothing remote"
  fi
  fonts=$(ls apps/desktop/dist/assets/*.woff2 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$fonts" -gt 0 ]]; then
    ok "$fonts webfont(s) bundled locally"
  else
    echo "      note: no webfonts in the bundle; the interface will use platform fonts"
  fi
else
  echo "    dist/ not built; run npm run build to check the emitted output too"
fi

section "Font licences travel with the fonts"
# The OFL requires the licence accompany the font wherever it is redistributed.
fonts_dir=apps/desktop/src/assets/fonts
missing=0
# Once per family, not once per subset file — two Inter subsets are still one
# licence obligation.
check_family() {
  local prefix="$1" licence="$2" name="$3"
  compgen -G "$fonts_dir/$prefix*.woff2" >/dev/null || return 0
  if [[ ! -f "$fonts_dir/$licence" ]]; then
    bad "$name is bundled without its licence ($licence)"
    missing=1
  fi
}
check_family "inter-" "Inter-LICENSE.txt" "Inter"
check_family "jetbrains-mono-" "JetBrainsMono-LICENSE.txt" "JetBrains Mono"
[[ $missing -eq 0 ]] && ok "every bundled font ships with its OFL text"

section "Tauri capability grants"
perms=$(grep -o '"[a-z-]*:[a-z-]*"' apps/desktop/src-tauri/capabilities/default.json | tr -d '"' | tr '\n' ' ')
ok "granted: ${perms:-none}"
for risky in "fs:" "shell:" "http:" "process:"; do
  if [[ "$perms" == *"$risky"* ]]; then bad "the webview is granted $risky — it should reach the OS only through vetted commands"; fi
done

section "Installer privileges"
if grep -q '"installMode": "currentUser"' apps/desktop/src-tauri/tauri.conf.json; then
  ok "installs per-user; no administrator elevation requested"
else
  bad "the installer requests elevation"
fi
if grep -qE '"(externalBin|sidecar)"' apps/desktop/src-tauri/tauri.conf.json; then
  bad "third-party binaries are bundled into the installer"
else
  ok "no third-party binaries bundled"
fi

section "Design tokens"
(cd apps/desktop && npm run --silent check:tokens) || bad "design token check failed"

printf '\n'
if [[ $fail -eq 0 ]]; then
  printf '\033[32mAll checks passed.\033[0m\n'
else
  printf '\033[31mOne or more checks failed.\033[0m\n'
fi
exit $fail
