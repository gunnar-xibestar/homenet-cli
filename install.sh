#!/bin/sh
# Easy installer for homenet, a beginner-friendly Linux CLI that wraps nmap.
# Only scan networks you own or are authorized to scan.
#
# Read this file before you run it:
#   curl -fsSL -o install.sh https://github.com/gunnar-xibestar/homenet-cli/releases/latest/download/install.sh
#   less install.sh
#   sh install.sh
#
# Or pipe it (questions are read from /dev/tty, not from the pipe):
#   curl -fsSL https://github.com/gunnar-xibestar/homenet-cli/releases/latest/download/install.sh | sh
set -eu

# ---------------------------------------------------------------------------
# Release asset names
#
# These match .github/workflows/release.yml and packaging/build-binary.sh
# and packaging/build-deb.sh. The release job copies install.sh from the
# repo root when that file exists, writes SHA256SUMS with sha256sum, and
# uploads that file with the other assets.
#
# SHA256SUMS_ASSET
#   GNU sha256sum text format: "<64 hex><two spaces><filename>"
#   A "*" before the filename (binary mode) is also accepted.
# DEB_NAME_PREFIX
#   Debian package: homenet_<version>_<arch>.deb
#   <arch> is amd64 or arm64 (Debian names, not the raw uname -m value).
#   <version> is the pyproject version, with no leading v. Tag v0.3.0
#   publishes homenet_0.3.0_<arch>.deb. The control file sets Package: homenet.
# BIN_NAME_PREFIX
#   Standalone executable, not a tarball: homenet-linux-<arch>
#   Example: homenet-linux-amd64. Installed as ~/.local/bin/homenet (mode 755).
# RELEASE_DOWNLOAD_BASE
#   https://github.com/gunnar-xibestar/homenet-cli/releases/latest/download
#   install.sh itself is also a release asset. This script does not download
#   itself.
# ---------------------------------------------------------------------------
REPO_SLUG="gunnar-xibestar/homenet-cli"
RELEASE_DOWNLOAD_BASE="https://github.com/${REPO_SLUG}/releases/latest/download"
SHA256SUMS_ASSET="SHA256SUMS"
DEB_NAME_PREFIX="homenet_"
BIN_NAME_PREFIX="homenet-linux-"

USER_INSTALL=0
ARCH=""
debian_ubuntu=0
tmpdir=""
sums_file=""
deb_asset=""

usage() {
  cat <<'EOF'
Install homenet on Linux.

homenet lists devices on a network. Only scan networks you own or are
authorized to scan.

Usage:
  install.sh [--user]
  install.sh --help

  --user   Copy the homenet program to ~/.local/bin. Does not use sudo.
           Without --user, Debian and Ubuntu install a .deb and ask
           before sudo. Other Linux systems use ~/.local/bin.

When you install with the pipe, pass flags after -s:
  curl -fsSL .../install.sh | sh -s -- --user

The password prompt, when you see one, comes from sudo itself.
EOF
}

die() {
  printf '%s\n' "$@" >&2
  exit 1
}

while [ $# -gt 0 ]; do
  case $1 in
    --help)
      usage
      exit 0
      ;;
    --user)
      USER_INSTALL=1
      ;;
    *)
      die "Unknown option: $1" "Try: install.sh --help"
      ;;
  esac
  shift
done

printf '%s\n' "Only scan networks you own or are authorized to scan."

machine=$(uname -m) || die "Could not read this computer's architecture (uname -m)." "Nothing was installed."
case $machine in
  x86_64|amd64)
    ARCH="amd64"
    ;;
  aarch64|arm64)
    ARCH="arm64"
    ;;
  *)
    die "This installer only works on 64-bit PC (x86_64 / amd64) and 64-bit ARM (aarch64 / arm64)." \
      "This computer reports ${machine}." \
      "Nothing was installed."
    ;;
esac

if command -v curl >/dev/null 2>&1; then
  DOWNLOADER="curl"
elif command -v wget >/dev/null 2>&1; then
  DOWNLOADER="wget"
else
  die "curl or wget is required to download homenet." "Nothing was installed."
fi

if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  die "sha256sum or shasum is required to check the download." "Nothing was installed."
fi

if [ -r /etc/os-release ]; then
  os_id=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"'"'")
  os_like=$(sed -n 's/^ID_LIKE=//p' /etc/os-release | tr -d '"'"'")
  os_ids=$(printf '%s %s' "$os_id" "$os_like")
  case " ${os_ids} " in
    *" debian "*|*" ubuntu "*)
      debian_ubuntu=1
      ;;
  esac
fi

download_to() {
  url=$1
  dest=$2
  if [ "$DOWNLOADER" = "curl" ]; then
    curl -fsSL -o "$dest" "$url" || return 1
  else
    wget -q -O "$dest" "$url" || return 1
  fi
}

# Asset names are limited to A-Za-z0-9._+- so the only character that needs
# encoding in a URL path is "+".
asset_url() {
  encoded=$(printf '%s\n' "$1" | sed 's/+/%2B/g')
  printf '%s/%s\n' "$RELEASE_DOWNLOAD_BASE" "$encoded"
}

fetch_asset() {
  asset=$1
  dest=$2
  url=$(asset_url "$asset")
  if ! download_to "$url" "$dest"; then
    die "Could not download ${asset} from the latest homenet release." "Nothing was installed."
  fi
  if [ ! -s "$dest" ]; then
    die "The download of ${asset} was empty." "Nothing was installed."
  fi
}

# Filename from one SHA256SUMS line. Strips a text-mode or binary-mode prefix.
name_from_sum_line() {
  printf '%s\n' "$1" | tr -d '\r' | sed -e 's/^[0-9A-Fa-f][0-9A-Fa-f]*[[:space:]][[:space:]]*//' -e 's/^\*//'
}

hash_from_sum_line() {
  printf '%s\n' "$1" | tr -d '\r' | awk '{print $1}'
}

cleanup() {
  if [ -n "$tmpdir" ]; then
    rm -rf "$tmpdir"
    tmpdir=""
  fi
}

tmpdir=$(mktemp -d) || die "Could not create a temporary folder." "Nothing was installed."
trap cleanup EXIT
trap 'cleanup; exit 1' INT TERM

printf '%s\n' "Downloading the latest homenet release..."
sums_file="${tmpdir}/${SHA256SUMS_ASSET}"
fetch_asset "$SHA256SUMS_ASSET" "$sums_file"

# Sets deb_asset to the single homenet_<version>_<arch>.deb name, or exits.
select_deb() {
  deb_asset=""
  deb_count=0
  while IFS= read -r raw || [ -n "$raw" ]; do
    case $raw in
      ''|\#*)
        continue
        ;;
    esac
    got=$(name_from_sum_line "$raw")
    case $got in
      *[!A-Za-z0-9._+-]*|*..*)
        continue
        ;;
      "${DEB_NAME_PREFIX}"*"_${ARCH}.deb")
        middle=${got#"${DEB_NAME_PREFIX}"}
        middle=${middle%"_${ARCH}.deb"}
        if [ -z "$middle" ]; then
          continue
        fi
        deb_count=$((deb_count + 1))
        deb_asset=$got
        ;;
    esac
  done < "$sums_file"
  if [ "$deb_count" -eq 0 ]; then
    die "SHA256SUMS has no entry for a homenet package for ${ARCH}." \
      "Expected a file named homenet_<version>_${ARCH}.deb." \
      "Nothing was installed."
  fi
  if [ "$deb_count" -ne 1 ]; then
    die "SHA256SUMS lists more than one homenet package for ${ARCH}." "Nothing was installed."
  fi
}

verify_asset() {
  filename=$1
  dir=$2
  found_line=""
  while IFS= read -r raw || [ -n "$raw" ]; do
    case $raw in
      ''|\#*)
        continue
        ;;
    esac
    got=$(name_from_sum_line "$raw")
    if [ "$got" = "$filename" ]; then
      found_line=$raw
      break
    fi
  done < "$sums_file"
  if [ -z "$found_line" ]; then
    die "SHA256SUMS has no entry for ${filename}." "Nothing was installed."
  fi
  hash=$(hash_from_sum_line "$found_line")
  case $hash in
    *[!0-9A-Fa-f]*)
      die "The SHA256SUMS line for ${filename} is not a SHA-256 hash." "Nothing was installed."
      ;;
  esac
  if [ "${#hash}" -ne 64 ]; then
    die "The SHA256SUMS line for ${filename} is not a SHA-256 hash." "Nothing was installed."
  fi
  # Text mode: hash, two spaces, filename. sha256sum -c / shasum -c compare it.
  printf '%s  %s\n' "$hash" "$filename" > "${dir}/CHECK.wanted"
  if command -v sha256sum >/dev/null 2>&1; then
    if ! (cd "$dir" && sha256sum -c --status CHECK.wanted); then
      die "The file ${filename} does not match SHA256SUMS." "Nothing was installed."
    fi
  else
    if ! (cd "$dir" && shasum -a 256 -c --status CHECK.wanted); then
      die "The file ${filename} does not match SHA256SUMS." "Nothing was installed."
    fi
  fi
}

sums_lists() {
  want=$1
  while IFS= read -r raw || [ -n "$raw" ]; do
    case $raw in
      ''|\#*)
        continue
        ;;
    esac
    got=$(name_from_sum_line "$raw")
    if [ "$got" = "$want" ]; then
      return 0
    fi
  done < "$sums_file"
  return 1
}

after_install() {
  if ! command -v nmap >/dev/null 2>&1; then
    printf '%s\n' "nmap is not installed. homenet needs it to scan."
    printf '%s\n' "sudo apt install nmap"
  fi
  printf '%s\n' "Next step:"
  printf '%s\n' "homenet doctor"
  printf '%s\n' "Only scan networks you own or are authorized to scan."
}

install_binary() {
  bin_asset="${BIN_NAME_PREFIX}${ARCH}"
  case $bin_asset in
    *[!A-Za-z0-9._+-]*)
      die "The binary name ${bin_asset} looks unexpected." "Nothing was installed."
      ;;
  esac
  if ! sums_lists "$bin_asset"; then
    die "SHA256SUMS has no entry for ${bin_asset}." "Nothing was installed."
  fi
  if [ -z "${HOME:-}" ]; then
    die "HOME is not set, so homenet cannot be copied to ~/.local/bin." "Nothing was installed."
  fi
  if [ "$USER_INSTALL" -eq 1 ]; then
    printf '%s\n' "Installing the homenet program into ~/.local/bin. This does not use sudo."
  else
    printf '%s\n' "This is not Debian or Ubuntu, so homenet goes into ~/.local/bin. This does not use sudo."
  fi
  fetch_asset "$bin_asset" "${tmpdir}/${bin_asset}"
  verify_asset "$bin_asset" "$tmpdir"
  bindir="${HOME}/.local/bin"
  mkdir -p "$bindir" || die "Could not create ${bindir}." "Nothing was installed."
  cp "${tmpdir}/${bin_asset}" "${bindir}/homenet" || die "Could not copy homenet to ${bindir}." "Nothing was installed."
  chmod 755 "${bindir}/homenet" || die "Could not make ${bindir}/homenet runnable." "Nothing was installed."
  printf '%s\n' "Installed homenet to ${bindir}/homenet"
  case ":${PATH:-}:" in
    *":${bindir}:"*)
      ;;
    *)
      printf '%s\n' "\$HOME/.local/bin is not on PATH. Add this line, then open a new terminal:"
      printf '%s\n' "export PATH=\"\$HOME/.local/bin:\$PATH\""
      ;;
  esac
  after_install
}

ask_deb() {
  install_cmd="sudo apt install ./${deb_asset}"
  printf '%s\n' "The package file is in this folder. This command installs it:"
  printf '%s\n' "$install_cmd"
  printf '%s\n' "The password prompt comes from sudo itself, not from homenet."
  if ! (: </dev/tty) 2>/dev/null; then
    printf '%s\n' "There is no terminal to ask you, so sudo was not run."
    printf '%s\n' "When you are ready, from this folder, run:"
    printf '%s\n' "$install_cmd"
    exit 0
  fi
  printf '%s' "Run this now? [y/N] " >/dev/tty
  if ! IFS= read -r answer </dev/tty; then
    printf '%s\n' "Could not read an answer, so sudo was not run."
    printf '%s\n' "When you are ready, from this folder, run:"
    printf '%s\n' "$install_cmd"
    exit 0
  fi
  case $answer in
    y|Y|yes|YES|Yes)
      printf '%s\n' "Running that command. sudo may ask for your password. That prompt comes from sudo, not homenet."
      # The password prompt is sudo's own. Do not pass -n, -A, or -S.
      if ! sudo apt install "./${deb_asset}"; then
        die "The install command did not finish." \
          "Nothing was installed. The package file is still in this folder. Run:" \
          "$install_cmd"
      fi
      after_install
      ;;
    *)
      printf '%s\n' "Okay, not running sudo."
      printf '%s\n' "When you are ready, from this folder, run:"
      printf '%s\n' "$install_cmd"
      exit 0
      ;;
  esac
}

install_deb() {
  select_deb
  fetch_asset "$deb_asset" "${tmpdir}/${deb_asset}"
  verify_asset "$deb_asset" "$tmpdir"
  if [ -e "./${deb_asset}" ]; then
    die "A file named ${deb_asset} is already in this folder." \
      "Move it aside and run the installer again. Nothing was installed."
  fi
  cp "${tmpdir}/${deb_asset}" "./${deb_asset}" || die "Could not place ${deb_asset} in this folder." "Nothing was installed."
  ask_deb
}

if [ "$USER_INSTALL" -eq 1 ] || [ "$debian_ubuntu" -eq 0 ]; then
  install_binary
else
  install_deb
fi
