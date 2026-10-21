# Install

## Install with pipx

pipx keeps homenet in its own environment and puts the `homenet` command on your PATH. This repository is the package `homenet-cli`. It is not on PyPI. The PyPI project named `homenet` is a different tool.

Get pipx from your distro, then run `pipx ensurepath` and open a new terminal:

```bash
# Debian or Ubuntu
sudo apt update
sudo apt install pipx
pipx ensurepath

# Fedora
sudo dnf install pipx
pipx ensurepath

# Arch Linux (package name is python-pipx)
sudo pacman -S python-pipx
pipx ensurepath
```

Install homenet with one of these:

```bash
pipx install "git+https://github.com/gunnar-xibestar/homenet-cli.git"

# Or install over SSH:
pipx install "git+ssh://git@github.com/gunnar-xibestar/homenet-cli.git"

# Or, from a clone of this repo:
pipx install .
```

Then run `homenet --help`.

## From a clone

The repo includes a `dev` extra used by CI (`pytest`, `ruff`, and `tomli` on Python 3.10). From a checkout:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

That installs an editable `homenet` plus the test tools. For everyday use of a clone, `pipx install .` above is enough.

## You need nmap

The scan commands run nmap. `homenet doctor` also looks for the `ip` command and for ping. `homenet wifi` can use `nmcli` and `iw`. `homenet dns` can use `resolvectl`. Those three are optional: doctor warns when one is missing, and the command still exits 0.

```bash
sudo apt install nmap       # Debian, Ubuntu
sudo dnf install nmap       # Fedora
sudo pacman -S nmap         # Arch Linux
```

If a required tool is missing, doctor prints an apt fix: `sudo apt install nmap`, `sudo apt install iproute2` (the `ip` command), or `sudo apt install iputils-ping`. A missing optional tool is a warning with its own apt fix: `network-manager` for `nmcli`, `iw` for `iw`, and `systemd-resolved` for `resolvectl`.

## Privileges

Scans work as a normal user. No command runs a SYN scan. `ports` is a TCP connect scan (`-sT`) and works without root. `services` uses `-sT -sV --version-light` and works without root too. `router` only requests the gateway's admin page, so root does not change that result. Root adds MAC addresses and makers to `devices`, `device`, and `baseline`. `new-devices` uses that same sweep, so those fields show up there as well.

## See also

- [Sudo and virtual environments](sudo.md)
- [Quick start](quick-start.md)
- [README](../README.md)
