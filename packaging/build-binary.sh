#!/usr/bin/env bash
# Build a onefile homenet binary inside ubuntu:22.04 (old glibc for wide compatibility).
# Usage: packaging/build-binary.sh amd64|arm64
# Output: dist/homenet-linux-<arch>
set -euo pipefail

arch="${1:-}"
case "${arch}" in
  amd64 | arm64) ;;
  *)
    echo "usage: $0 amd64|arm64" >&2
    exit 2
    ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="ubuntu:22.04"
name="homenet-linux-${arch}"
mkdir -p "${repo_root}/dist"

docker run --rm \
  --platform "linux/${arch}" \
  -v "${repo_root}:/src:ro" \
  -v "${repo_root}/dist:/out" \
  -e "NAME=${name}" \
  -e "HOST_UID=$(id -u)" \
  -e "HOST_GID=$(id -g)" \
  "${image}" \
  bash -euo pipefail -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends python3 python3-pip python3-venv libpython3.10 binutils >/dev/null
    cp -a /src /build
    rm -rf /build/dist /build/build /build/src/*.egg-info
    python3 -m venv /venv
    /venv/bin/pip install -q --upgrade pip
    /venv/bin/pip install -q /build pyinstaller
    cd /build
    /venv/bin/pyinstaller --onefile --clean --noconfirm \
      --name "${NAME}" \
      --collect-all homenet \
      --copy-metadata homenet-cli \
      --distpath /out --workpath /tmp/pyi-work --specpath /tmp/pyi-spec \
      packaging/entry.py
    chown "${HOST_UID}:${HOST_GID}" "/out/${NAME}"
  '

echo "built dist/${name}"
