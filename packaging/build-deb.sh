#!/usr/bin/env bash
# Build a .deb from dist/homenet-linux-<arch>.
# Usage: packaging/build-deb.sh amd64|arm64 [VERSION]
# VERSION defaults to the version in pyproject.toml.
# Output: dist/homenet_<version>_<arch>.deb
set -euo pipefail

arch="${1:-}"
case "${arch}" in
  amd64 | arm64) ;;
  *)
    echo "usage: $0 amd64|arm64 [VERSION]" >&2
    exit 2
    ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${2:-}"
if [[ -z "${version}" ]]; then
  version="$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "${repo_root}/pyproject.toml" | head -n1)"
fi
if [[ -z "${version}" ]]; then
  echo "could not read version from pyproject.toml" >&2
  exit 1
fi

binary="${repo_root}/dist/homenet-linux-${arch}"
if [[ ! -f "${binary}" ]]; then
  echo "missing ${binary}; run packaging/build-binary.sh ${arch} first" >&2
  exit 1
fi

staging="$(mktemp -d)"
trap 'rm -rf "${staging}"' EXIT
root="${staging}/homenet_${version}_${arch}"

install -d -m 0755 "${root}/DEBIAN" "${root}/usr/bin" "${root}/usr/lib/homenet" \
  "${root}/usr/share/man/man1" "${root}/usr/share/doc/homenet"
install -m 0755 "${binary}" "${root}/usr/bin/homenet"
printf 'deb\n' >"${root}/usr/lib/homenet/install-method"
chmod 0644 "${root}/usr/lib/homenet/install-method"
gzip -9n -c "${repo_root}/packaging/homenet.1" >"${root}/usr/share/man/man1/homenet.1.gz"
chmod 0644 "${root}/usr/share/man/man1/homenet.1.gz"

cat >"${root}/usr/share/doc/homenet/copyright" <<COPYRIGHT
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: homenet-cli
Source: https://github.com/gunnar-xibestar/homenet-cli

Files: *
Copyright: Gunnar Jackson
License: GPL-3.0-or-later
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 .
 On Debian systems, the complete text of the GNU General Public License
 version 3 can be found in /usr/share/common-licenses/GPL-3.
COPYRIGHT
chmod 0644 "${root}/usr/share/doc/homenet/copyright"

installed_size="$(du -sk --exclude=DEBIAN "${root}" | cut -f1)"
cat >"${root}/DEBIAN/control" <<CONTROL
Package: homenet
Version: ${version}
Architecture: ${arch}
Maintainer: Gunnar Jackson <gunnar-xibestar@users.noreply.github.com>
Installed-Size: ${installed_size}
Depends: nmap, iproute2
Section: net
Priority: optional
Homepage: https://github.com/gunnar-xibestar/homenet-cli
Description: beginner-friendly home network detection tool
 homenet wraps nmap so you can list devices, ports, and services on your
 home network without learning nmap's flags. Only scan networks you own
 or have permission to scan.
CONTROL

mkdir -p "${repo_root}/dist"
out="${repo_root}/dist/homenet_${version}_${arch}.deb"
dpkg-deb --build --root-owner-group "${root}" "${out}"
echo "built ${out#"${repo_root}/"}"
