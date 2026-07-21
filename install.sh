#!/bin/sh
# install.sh - installer for the ngstone agent binary.
#
# This installs *only* the agent (`ngstone`), the thing you run on your own
# machine to expose a local port through your ngstone edge. The edge binary
# (`ngstoned`) is server infrastructure meant to be installed deliberately on
# a VPS, not via curl-pipe, so it is intentionally not handled here.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/emilio-kariuki/ngstone/main/install.sh | sh
#
# Environment overrides:
#   NGSTONE_VERSION      release tag to install, e.g. "v0.1.0" (default: latest)
#   NGSTONE_INSTALL_DIR  directory to install the binary into (default: see below)

set -eu

REPO="emilio-kariuki/ngstone"
BINARY_NAME="ngstone"

# --- helpers ---------------------------------------------------------------

info() {
	printf 'ngstone-install: %s\n' "$1"
}

fail() {
	printf 'ngstone-install: error: %s\n' "$1" >&2
	exit 1
}

need_cmd() {
	command -v "$1" >/dev/null 2>&1 || fail "required command '$1' not found"
}

# --- detect OS and architecture ---------------------------------------------

detect_os() {
	os=$(uname -s)
	case "$os" in
	Darwin) echo "darwin" ;;
	Linux) echo "linux" ;;
	*) fail "unsupported OS '$os' (ngstone only ships darwin and linux builds)" ;;
	esac
}

detect_arch() {
	arch=$(uname -m)
	case "$arch" in
	x86_64 | amd64) echo "amd64" ;;
	arm64 | aarch64) echo "arm64" ;;
	*) fail "unsupported architecture '$arch' (ngstone only ships amd64 and arm64 builds)" ;;
	esac
}

# --- resolve the release to install -----------------------------------------

resolve_version() {
	if [ -n "${NGSTONE_VERSION:-}" ]; then
		echo "$NGSTONE_VERSION"
		return
	fi

	need_cmd curl
	tag=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" |
		grep '"tag_name"' | head -n1 | cut -d'"' -f4)
	[ -n "$tag" ] || fail "could not resolve latest release tag from the GitHub API"
	echo "$tag"
}

# --- pick a checksum tool ----------------------------------------------------

sha256_of() {
	if command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | cut -d' ' -f1
	elif command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	else
		fail "need either 'shasum' or 'sha256sum' to verify the download"
	fi
}

# --- pick an install directory ----------------------------------------------

resolve_install_dir() {
	if [ -n "${NGSTONE_INSTALL_DIR:-}" ]; then
		mkdir -p "$NGSTONE_INSTALL_DIR"
		echo "$NGSTONE_INSTALL_DIR"
		return
	fi

	if [ -w /usr/local/bin ]; then
		echo "/usr/local/bin"
		return
	fi

	fallback="$HOME/.local/bin"
	mkdir -p "$fallback"
	echo "$fallback"
}

# --- main --------------------------------------------------------------------

main() {
	need_cmd curl
	need_cmd tar

	os=$(detect_os)
	arch=$(detect_arch)
	version=$(resolve_version)

	info "installing ngstone ${version} for ${os}/${arch}"

	tmpdir=$(mktemp -d)
	trap 'rm -rf "$tmpdir"' EXIT

	archive="ngstone_${os}_${arch}.tar.gz"
	base_url="https://github.com/${REPO}/releases/download/${version}"

	info "downloading ${archive}"
	curl -fsSL -o "$tmpdir/$archive" "${base_url}/${archive}" ||
		fail "failed to download ${base_url}/${archive} (does this release/platform exist?)"

	info "downloading checksums.txt"
	curl -fsSL -o "$tmpdir/checksums.txt" "${base_url}/checksums.txt" ||
		fail "failed to download checksums.txt for ${version}"

	expected=$(grep " ${archive}\$" "$tmpdir/checksums.txt" | cut -d' ' -f1)
	[ -n "$expected" ] || fail "no checksum entry found for ${archive} in checksums.txt"

	actual=$(sha256_of "$tmpdir/$archive")
	if [ "$expected" != "$actual" ]; then
		fail "checksum mismatch for ${archive}
  expected: ${expected}
  actual:   ${actual}
Refusing to install a binary that doesn't match its published checksum."
	fi
	info "checksum verified"

	tar -xzf "$tmpdir/$archive" -C "$tmpdir" "$BINARY_NAME"

	install_dir=$(resolve_install_dir)
	install -m 755 "$tmpdir/$BINARY_NAME" "$install_dir/$BINARY_NAME" 2>/dev/null ||
		{
			cp "$tmpdir/$BINARY_NAME" "$install_dir/$BINARY_NAME"
			chmod 755 "$install_dir/$BINARY_NAME"
		}

	installed_version=$("$install_dir/$BINARY_NAME" -version 2>/dev/null || echo "$version")

	info "installed ${installed_version} to ${install_dir}/${BINARY_NAME}"

	case ":$PATH:" in
	*":$install_dir:"*) ;;
	*)
		info "NOTE: ${install_dir} is not on your PATH."
		info "Add it, e.g.: export PATH=\"${install_dir}:\$PATH\""
		;;
	esac
}

main "$@"
