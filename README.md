# homenet

homenet is a beginner-friendly (not so much considering setup) command line interface for seeing what is on your home network. It wraps nmap, so you can list devices, ports, and services without learning nmap's flags. It runs on Linux and needs Python 3.10 or newer.

> **Only scan networks you own or have permission to scan.**

That line is the rule for this tool. Scanning a network you do not own can be illegal. The commands that print this reminder are in [Safety](docs/safety.md).

## Install

pipx keeps homenet in its own environment and puts the `homenet` command on your PATH. This repository is the package `homenet-cli`. It is not on PyPI. The PyPI project named `homenet` is a different tool.

```bash
pipx install "git+https://github.com/gunnar-xibestar/homenet-cli.git"
```

Then run `homenet --help`.

Distro packages, an SSH or local install, a virtual environment, and nmap are in [Install](docs/install.md). `sudo` will not see a virtual environment's command; see [Sudo and virtual environments](docs/sudo.md).

## Quick start

Run these three in order, on a network you are allowed to scan.

```bash
homenet doctor
homenet whoami-net
homenet devices
```

What you should see is in [Quick start](docs/quick-start.md). To print the underlying command without running a scan:

```bash
homenet explain devices
```

## Commands

| Command | What it does |
| --- | --- |
| [`homenet doctor`](docs/quick-start.md#homenet-doctor) | tools, privileges, and the network route |
| [`homenet whoami-net`](docs/quick-start.md#homenet-whoami-net) | this computer's address on the home network |
| [`homenet devices`](docs/quick-start.md#homenet-devices) | devices on the home network right now |
| [`homenet device 192.168.1.20`](docs/commands.md#homenet-device) | one device, using an address from devices |
| [`homenet ports 192.168.1.1`](docs/commands.md#homenet-ports) | open ports on one device, with a plain-English risk |
| [`homenet services 192.168.1.1`](docs/commands.md#homenet-services) | services on one device, plus program and version when known |
| [`homenet router`](docs/commands.md#homenet-router) | gateway, and whether its admin page answers |
| [`homenet baseline`](docs/commands.md#homenet-baseline) | save the current device list |
| [`homenet new-devices`](docs/commands.md#homenet-new-devices) | what changed since that saved snapshot |
| [`homenet speed`](docs/speed.md#speed-contacts-cloudflare) | an estimate of download speed |
| [`homenet wifi`](docs/wifi.md#homenet-wifi) | signal, band, and channel for the Wi-Fi you are on |
| [`homenet dns`](docs/dns.md#homenet-dns) | DNS servers, who they belong to, and a lookup |
| [`homenet uninstall`](docs/uninstall.md#homenet-uninstall) | remove homenet; saved data stays unless --purge |
| [`homenet explain devices`](docs/explain.md#see-the-real-command) | show the real commands, without running them |

The table lists every command the CLI has. `explain` takes the name of any command, for example `homenet explain devices`. Longer notes are in [Commands](docs/commands.md).

## Documentation

- [Safety](docs/safety.md) — the scan rule, and which commands print it
- [Install](docs/install.md) — pipx, a clone and virtual environment, nmap, and privileges
- [Sudo and virtual environments](docs/sudo.md) — why plain `sudo homenet` fails, and the fix
- [Quick start](docs/quick-start.md) — what `doctor`, `whoami-net`, and `devices` print
- [Commands](docs/commands.md) — per-command details
- [Uninstall](docs/uninstall.md) — remove homenet, and `--purge`
- [Wi-Fi](docs/wifi.md) — signal, band, and channel
- [DNS](docs/dns.md) — servers, who they belong to, and a lookup
- [JSON output](docs/json.md) — `--json` on stdout, errors on stderr
- [Exit codes](docs/exit-codes.md) — `0`, `1`, and `2`
- [Progress](docs/progress.md) — status lines, `-v`, and `-vv`
- [See the real command](docs/explain.md) — `--show-cmd` and `explain`
- [Speed](docs/speed.md) — the Cloudflare download estimate
- [WSL 2](docs/wsl.md) — the virtual network and mirrored mode
- [Troubleshooting](docs/troubleshooting.md) — sudo `PATH`, and WSL 2

## License

homenet-cli is free software, licensed under the GNU General Public License, version 3 or (at your option) any later version (`GPL-3.0-or-later`). See [LICENSE](LICENSE) for the full text.

Copyright (C) 2026 Gunnar Jackson

The license covers the code, not what you point it at: only scan networks you own or have permission to scan.
