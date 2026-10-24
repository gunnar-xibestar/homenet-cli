# Install

> **Only scan networks you own or are authorized to scan.**

Scanning a network you do not own can be illegal.

## Easy install

One line downloads the installer from the latest GitHub release and runs it:

```bash
curl -fsSL https://github.com/gunnar-xibestar/homenet-cli/releases/latest/download/install.sh | sh
```

The script is fed to `sh` on standard input, so it reads your answers from the terminal (`/dev/tty`), not from that pipe.

Here is what it does:

- It reads the machine type with `uname -m`. 64-bit PC (`x86_64` / `amd64`) and 64-bit ARM (`aarch64` / `arm64`) work. Anything else stops, with nothing installed.
- It downloads `SHA256SUMS` and checks the file it is about to install with `sha256sum` (or `shasum -a 256`). If the checksum does not match, or the file is not listed, it stops and installs nothing.
- On Debian and Ubuntu it downloads `homenet_<version>_<arch>.deb` and asks before it runs `sudo`. The password prompt comes from sudo itself, not from homenet.
- On other Linux systems, or when you pass `--user`, it copies a single program to `~/.local/bin/homenet`. That path does not use sudo.
- If `nmap` is missing it prints `sudo apt install nmap` and does not run it. Then it tells you to run `homenet doctor`.

`<version>` comes from the `.deb` name in `SHA256SUMS` (for example `homenet_0.3.0_amd64.deb`). `<arch>` is `amd64` or `arm64`.

## Read the script first

You should read an installer before you pipe it to a shell. Save it, read it, then run it:

```bash
curl -fsSL -o install.sh https://github.com/gunnar-xibestar/homenet-cli/releases/latest/download/install.sh
less install.sh
sh install.sh
```

The copy of `install.sh` in this repository is that same script.

## Manual deb install

On Debian or Ubuntu you can install the package yourself. Open the latest release and use the file named `homenet_<version>_<arch>.deb` for this computer (`amd64` on a 64-bit PC, `arm64` on 64-bit ARM). This example is version `0.3.0` on `amd64`. Replace the name if the release is newer or the machine is ARM.

```bash
curl -fsSL -O https://github.com/gunnar-xibestar/homenet-cli/releases/latest/download/SHA256SUMS
curl -fsSL -O https://github.com/gunnar-xibestar/homenet-cli/releases/latest/download/homenet_0.3.0_amd64.deb
sha256sum -c --ignore-missing SHA256SUMS
sudo apt install ./homenet_0.3.0_amd64.deb
```

Run those in the same folder. `sha256sum -c --ignore-missing` checks every file you downloaded that is listed in `SHA256SUMS`, and skips names that are not in the folder. If a line says `FAILED`, or the name is not in `SHA256SUMS`, do not install that file.

`sudo` asks for your password. That prompt comes from sudo itself, not from homenet.

## Manual binary install

The release also has a single program, `homenet-linux-amd64` or `homenet-linux-arm64`. It is not a tarball. This puts it on your account only, with no sudo:

```bash
curl -fsSL -O https://github.com/gunnar-xibestar/homenet-cli/releases/latest/download/SHA256SUMS
curl -fsSL -o homenet-linux-amd64 https://github.com/gunnar-xibestar/homenet-cli/releases/latest/download/homenet-linux-amd64
sha256sum -c --ignore-missing SHA256SUMS
mkdir -p ~/.local/bin
cp homenet-linux-amd64 ~/.local/bin/homenet
chmod 755 ~/.local/bin/homenet
```

Use `homenet-linux-arm64` on 64-bit ARM. If `homenet` is not found, add this line to `~/.bashrc`, then open a new terminal:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

## Check checksums by hand

`SHA256SUMS` lists every release file. From the folder where you downloaded it and the file you want to install:

```bash
sha256sum -c --ignore-missing SHA256SUMS
```

`--ignore-missing` checks the files that are in the folder and does not complain about the ones you did not download. You want `OK` next to the file you will install. `FAILED` means do not install it.

## User install

`--user` always uses the binary in `~/.local/bin`, including on Debian and Ubuntu. It does not run sudo.

```bash
curl -fsSL -o install.sh https://github.com/gunnar-xibestar/homenet-cli/releases/latest/download/install.sh
sh install.sh --user
```

With the pipe, flags go after `-s`, or `sh` treats them as its own options:

```bash
curl -fsSL https://github.com/gunnar-xibestar/homenet-cli/releases/latest/download/install.sh | sh -s -- --user
```

## WSL 2

Install homenet inside the Ubuntu (WSL) shell, not from Windows PowerShell or Command Prompt.

In the default NAT mode, WSL only sees its virtual network, so scans won't find home devices. Mirrored networking mode helps. On Windows, add this to `%UserProfile%\.wslconfig`:

```ini
[wsl2]
networkingMode=mirrored
```

Then, from Windows, shut WSL down and open the Ubuntu shell again:

```bash
wsl --shutdown
```

More on the virtual network is in [WSL 2](wsl.md).

When the installer runs `sudo`, the password prompt comes from sudo itself, not from homenet.

## Uninstall

`homenet uninstall` asks first. It removes a pipx install, a virtual environment, a user-site install, or the single program in `~/.local/bin`. It removes that file only when it is the real program there, not a symbolic link and not a file outside that folder. It does not remove a `.deb`. Saved device data stays unless you pass `--purge`. The questions it asks are in [Uninstall](uninstall.md).

The `.deb` package name is `homenet`. `homenet uninstall` prints this and does not run it:

```bash
sudo apt remove homenet
```

The password prompt comes from sudo itself.

You can also delete a binary install yourself. That does not delete saved data:

```bash
rm ~/.local/bin/homenet
```

[Uninstall](uninstall.md) covers `baseline.json` and `--purge`.

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
- [WSL 2](wsl.md)
- [Uninstall](uninstall.md)
- [README](../README.md)
