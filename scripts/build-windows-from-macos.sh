#!/usr/bin/env bash
#
# Build the Windows installer from macOS.
#
# Tauri links against each platform's native webview, which is why the usual
# advice is that a Windows .exe must be built on Windows. That is true of the
# *supported* path, but it is possible from macOS: cargo-xwin supplies the MSVC
# headers and import libraries, lld-link does the linking, and Tauri's NSIS
# bundler drives a local makensis. Tauri prints "Cross-platform compilation is
# experimental" while doing it, and that warning is worth taking seriously —
# see the caveats at the bottom.
#
# The output is an unsigned NSIS installer:
#   target/x86_64-pc-windows-msvc/release/bundle/nsis/SentinelVAPT_<version>_x64-setup.exe
#
# Usage:  ./scripts/build-windows-from-macos.sh [output-directory]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${1:-}"

# ── The trap that costs an hour if you hit it ────────────────────────────────
#
# Homebrew's `rust` formula installs its own rustc at /opt/homebrew/bin, which
# comes before ~/.cargo/bin on a default PATH. That rustc has only the host
# target in its sysroot, so a cross-build fails with
#
#     error[E0463]: can't find crate for `core`
#     note: the `x86_64-pc-windows-msvc` target may not be installed
#
# even though `rustup target list --installed` shows the target present — the
# target belongs to rustup's toolchain, and the compiler being invoked is not
# rustup's. Putting ~/.cargo/bin first is the whole fix.
export PATH="$HOME/.cargo/bin:$PATH"

echo "==> Toolchain"
if [[ "$(command -v rustc)" != "$HOME/.cargo/bin/rustc" ]]; then
  echo "error: rustc resolves to $(command -v rustc), not rustup's." >&2
  echo "       A non-rustup rustc has no Windows sysroot and the build will fail." >&2
  exit 1
fi
rustc -vV | sed -n '1p;2p'

echo "==> Prerequisites"
if ! rustup target list --installed | grep -qx 'x86_64-pc-windows-msvc'; then
  echo "    installing the Windows target"
  rustup target add x86_64-pc-windows-msvc
fi

if ! command -v cargo-xwin >/dev/null; then
  echo "    installing cargo-xwin (supplies the MSVC CRT headers and import libs)"
  cargo install cargo-xwin --locked
fi

# Tauri's NSIS bundler shells out to makensis. On Windows it uses the bundled
# makensis.exe; on macOS it needs one on PATH.
if ! command -v makensis >/dev/null; then
  echo "error: makensis not found. Install it with:  brew install makensis" >&2
  exit 1
fi
echo "    makensis $(makensis -VERSION)"

echo "==> Building"
cd "$REPO_ROOT/apps/desktop"
npm ci --silent
npm run tauri build -- \
  --runner cargo-xwin \
  --target x86_64-pc-windows-msvc \
  --bundles nsis

BUNDLE_DIR="$REPO_ROOT/target/x86_64-pc-windows-msvc/release/bundle/nsis"
INSTALLER="$(find "$BUNDLE_DIR" -name '*-setup.exe' -print -quit)"

if [[ -z "$INSTALLER" ]]; then
  echo "error: no installer was produced under $BUNDLE_DIR" >&2
  exit 1
fi

echo
echo "==> Built $(basename "$INSTALLER") ($(du -h "$INSTALLER" | cut -f1))"
shasum -a 256 "$INSTALLER"

if [[ -n "$DEST" ]]; then
  mkdir -p "$DEST"
  cp "$INSTALLER" "$DEST/"
  echo "==> Copied to $DEST/$(basename "$INSTALLER")"
fi

cat <<'CAVEATS'

Caveats — read before shipping this to anyone
─────────────────────────────────────────────
• Tauri calls cross-compilation experimental and it is not what CI uses. For a
  release, prefer .github/workflows/release.yml, which builds on a real Windows
  runner and also produces the .msi.
• The installer is unsigned. Windows SmartScreen will warn on first run:
  More info → Run anyway. Signing is only wired up on Windows hosts.
• Only the NSIS .exe is produced here. The .msi needs WiX, which is Windows-only.
• Nothing in this build has been executed on Windows. It compiles and bundles;
  that is not the same as having been tested. Run it on a Windows machine before
  handing it to a client.
CAVEATS
