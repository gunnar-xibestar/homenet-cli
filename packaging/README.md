# Packaging

Build a onefile Linux binary and a `.deb` locally. Requires Docker (the binary
is built in `ubuntu:22.04` so it runs on older glibc) and `dpkg-deb`.

```sh
packaging/build-binary.sh amd64        # -> dist/homenet-linux-amd64
packaging/build-deb.sh amd64           # -> dist/homenet_<version>_amd64.deb
packaging/build-deb.sh amd64 0.3.0     # explicit version
```

For `arm64`, run on an arm64 host, or enable QEMU emulation
(`docker run --privileged --rm tonistiigi/binfmt --install arm64`); emulated
builds are slow.

Inspect the result:

```sh
dpkg-deb -I dist/homenet_*_amd64.deb
dpkg-deb -c dist/homenet_*_amd64.deb
```

CI builds both architectures in `.github/workflows/build.yml` and uploads the
binary and `.deb` as artifacts.

## Releases

Pushing a `v*` tag (for example `v0.3.0`, matching `version` in
`pyproject.toml`) runs `.github/workflows/release.yml`. It builds both
architectures, smoke-tests each binary, installs each `.deb`, runs lintian,
then publishes a GitHub Release with these assets: `homenet-linux-<arch>`
(bare executables), `homenet_<version>_<arch>.deb`, `install.sh` (when it
exists at the repo root), and `SHA256SUMS` covering all of them. A tag that does not match the pyproject version fails the build.
Running the workflow manually (workflow_dispatch) is a dry run: it builds and
tests but publishes nothing.

Verify a download:

```sh
sha256sum -c --ignore-missing SHA256SUMS
```
