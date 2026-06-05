#!/usr/bin/env bash
#
# herdr installer — downloads a prebuilt binary from the latest GitHub release.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/karatatar/herdr/master/install.sh | bash
#
# Environment overrides:
#   HERDR_REPO    GitHub "owner/repo" to install from   (default: karatatar/herdr)
#   HERDR_BINDIR  install directory                      (default: ~/.local/bin)
#   HERDR_TAG     release tag to install                 (default: latest)
#
set -euo pipefail

REPO="${HERDR_REPO:-karatatar/herdr}"
BINDIR="${HERDR_BINDIR:-$HOME/.local/bin}"
TAG="${HERDR_TAG:-latest}"

os="$(uname -s)"
arch="$(uname -m)"

case "$os" in
  Linux)  plat="linux" ;;
  Darwin) plat="macos" ;;
  *) echo "herdr: unsupported operating system: $os" >&2; exit 1 ;;
esac

case "$arch" in
  x86_64 | amd64)  cpu="x86_64" ;;
  aarch64 | arm64) cpu="aarch64" ;;
  *) echo "herdr: unsupported architecture: $arch" >&2; exit 1 ;;
esac

asset="herdr-${plat}-${cpu}"

if [ "$TAG" = "latest" ]; then
  url="https://github.com/${REPO}/releases/latest/download/${asset}"
else
  url="https://github.com/${REPO}/releases/download/${TAG}/${asset}"
fi

echo "herdr: downloading ${asset} (${TAG})"
echo "       ${url}"

mkdir -p "$BINDIR"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

if ! curl -fSL "$url" -o "$tmp"; then
  echo "herdr: download failed — does a release with asset '${asset}' exist for ${REPO}?" >&2
  exit 1
fi

chmod +x "$tmp"
mv "$tmp" "$BINDIR/herdr"
trap - EXIT

echo "herdr: installed to ${BINDIR}/herdr"

case ":$PATH:" in
  *":$BINDIR:"*) ;;
  *) echo "herdr: note — ${BINDIR} is not on your PATH; add it to use 'herdr' directly." >&2 ;;
esac

"$BINDIR/herdr" --version 2>/dev/null || true
