#!/usr/bin/env bash
# Print the Homebrew formula for an ngstone release.
# Usage: homebrew-formula.sh <tag> <checksums.txt>
set -euo pipefail

tag="$1"
checksums="$2"
base="https://github.com/emilio-kariuki/ngstone/releases/download/${tag}"

sha() {
  local file="ngstone_$1.tar.gz" sum
  sum="$(awk -v f="$file" '$2 == f { print $1 }' "$checksums")"
  [[ "$sum" =~ ^[0-9a-f]{64}$ ]] || { echo "missing or malformed checksum for $file in $checksums" >&2; exit 1; }
  echo "$sum"
}

# Resolve every checksum before printing, so a bad one fails the script.
darwin_arm64="$(sha darwin_arm64)"
darwin_amd64="$(sha darwin_amd64)"
linux_arm64="$(sha linux_arm64)"
linux_amd64="$(sha linux_amd64)"

cat <<RUBY
class Ngstone < Formula
  desc "Self-hosted HTTP tunnel, a personal ngrok alternative"
  homepage "https://github.com/emilio-kariuki/ngstone"
  license "MIT"
  on_macos do
    on_arm do
      url "${base}/ngstone_darwin_arm64.tar.gz"
      sha256 "${darwin_arm64}"
    end
    on_intel do
      url "${base}/ngstone_darwin_amd64.tar.gz"
      sha256 "${darwin_amd64}"
    end
  end

  on_linux do
    on_arm do
      url "${base}/ngstone_linux_arm64.tar.gz"
      sha256 "${linux_arm64}"
    end
    on_intel do
      url "${base}/ngstone_linux_amd64.tar.gz"
      sha256 "${linux_amd64}"
    end
  end

  def install
    bin.install "ngstone"
    bin.install "ngstoned"
  end

  test do
    output = shell_output("#{bin}/ngstone -version")
    assert_match "ngstone", output
  end
end
RUBY
