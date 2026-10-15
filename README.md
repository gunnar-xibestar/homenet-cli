# homenet

homenet is a beginner-friendly command for seeing what is on your home network. It wraps nmap, so you can list devices, ports, and services without learning nmap's flags. It runs on Linux and needs Python 3.10 or newer.

> **Only scan networks you own or have permission to scan.**

That line is the rule for this tool. Scanning a network you do not own can be illegal. `homenet devices`, `device`, `ports`, `services`, `router`, `baseline`, and `new-devices` print it before they do any work. When you add `--json`, the reminder is left out and only data is printed.

## Install with pipx

pipx keeps homenet in its own environment and puts the `homenet` command on your PATH. This repository is the package `homenet-cli`. It is not on PyPI. The PyPI project named `homenet` is a different tool. This git repository is private, so the install needs GitHub access.

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

Install homenet with one of these. A plain https install fails until git has credentials.

```bash
# Sign in once. git then uses gh as its credential helper.
gh auth login
pipx install "git+https://github.com/gunnarmail01-sketch/homenet-cli.git"

# Or install over SSH:
pipx install "git+ssh://git@github.com/gunnarmail01-sketch/homenet-cli.git"

# Or, from a clone of this repo:
pipx install .
```

Then run `homenet --help`.

### From a clone

The repo includes a `dev` extra used by CI (`pytest`, `ruff`, and `tomli` on Python 3.10). From a checkout:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

That installs an editable `homenet` plus the test tools. For everyday use of a clone, `pipx install .` above is enough.

## You need nmap

The scan commands run nmap. `homenet doctor` also looks for the `ip` command and for ping.

```bash
sudo apt install nmap       # Debian, Ubuntu
sudo dnf install nmap       # Fedora
sudo pacman -S nmap         # Arch Linux
```

If a tool is missing, doctor prints an apt fix: `sudo apt install nmap`, `sudo apt install iproute2` (the `ip` command), or `sudo apt install iputils-ping`.

### Privileges

Scans work as a normal user. No command runs a SYN scan. `services` uses `-sT -sV --version-light` and works without root. `ports` is a TCP connect scan (`-sT`) and works without root too. Sudo mainly adds MAC addresses and vendors to `devices`, `device`, and `baseline`. `new-devices` uses that same sweep, so those fields show up there as well.

When doctor warns about privileges, MAC addresses and makers need a scan run with sudo. `homenet doctor` does not need sudo. `sudo` resets `PATH`, so `sudo homenet devices` fails with "command not found" when homenet came from a venv or pipx. Use the absolute path doctor prints, or:

```bash
sudo "$(command -v homenet)" devices
```

A privileges warning still lets doctor exit 0. A missing tool or no network route is a failure and exits 1. On WSL 2's virtual network, doctor adds a `wsl` warning and still exits 0.

## Quick start

Run these three in order, on a network you are allowed to scan.

### `homenet doctor`

You should see a heading, **Home network doctor**, then five lines in this order: `nmap`, `ip`, `privileges`, `network`, and `ping`. Each line starts with `PASS`, `WARN`, or `FAIL`. A warning or failure adds a `Fix:` line when doctor knows one. When every check is fine, the last line is `All 5 checks passed.` A warning (often privileges, or a gateway that ignores ping) still exits 0. Any `FAIL` exits 1. Doctor does not need sudo. On WSL 2 NAT it can add a sixth line, `wsl`, which is also a warning.

### `homenet whoami-net`

You should see **This computer on your home network**, then four rows:

- **Interface**, how this computer is connected, such as Wi-Fi
- **IP address**, this computer, shown with its prefix when the subnet is known (for example `192.168.1.100/24`)
- **Gateway**, usually your home router
- **Home network**, the group of addresses your devices share (for example `192.168.1.0/24`)

This reads your own route with `ip`. A missing value is `not available`. Exit 0 when the route can be read. If you are not connected, it tells you to connect to Wi-Fi or Ethernet. On a 172.16/12 address inside WSL it adds a warning that this may be the WSL virtual network, not the home LAN. The command still exits 0.

### `homenet devices`

The safety reminder prints first. Then **Devices on your home network**, a table with columns **IP address**, **Name**, **MAC address**, and **Maker**, and a count such as `4 devices found.` This is an nmap ping sweep (`-sn`) of the home network from `whoami-net`. It can take up to a couple of minutes. Names nmap does not already know are looked up when possible. Anything it cannot see is `unknown`, which is common for MAC addresses and makers unless you used the privilege fix above. If nothing answers, it says no devices were found and asks you to check the connection. Exit 0 when the sweep finishes.

## Commands

```bash
homenet doctor                  # tools, privileges, and the network route
homenet whoami-net              # this computer's address on the home network
homenet devices                 # devices on the home network right now
homenet device 192.168.1.20     # one device, using an address from devices
homenet ports 192.168.1.1       # open ports on one device, with a plain-English risk
homenet services 192.168.1.1    # services on one device, plus program and version when known
homenet router                  # gateway, and whether its admin page answers
homenet baseline                # save the current device list
homenet new-devices             # what changed since that saved snapshot
homenet speed                   # a short download sample from Cloudflare
homenet explain devices         # show the real commands, without running them
```

`device` prints the name, IP address, MAC address, and maker, then a Ports section. It uses the same ping sweep as `devices` (`-sn`), which does not scan ports, so that section says `No ports were reported for this device.` `ports` checks the top 100 TCP ports on one address and labels each open port low, medium, or high risk. `services` names the program and version on one address when it can. `router` asks the gateway on ports 80, 443, and 8080 and only requests the page. No open ports, and a router with no admin page, are still a successful run.

`baseline` saves the device list to `$XDG_DATA_HOME/homenet/baseline.json` when that variable is an absolute path, otherwise `~/.local/share/homenet/baseline.json`. `new-devices` compares a fresh sweep with that file. If you have not saved one yet, it says to run `homenet baseline` first.

### `--json` and exit codes

Every command except `baseline` takes `--json`. JSON goes to stdout, with no safety banner. Errors go to stderr as `{"error": "...", "fix_hint": "..."}`.

Exit `0` means the command succeeded. Exit `1` means it failed. `doctor` exits `1` only when a check fails at error level. Warnings still exit `0`. `new-devices` exits `0` when nothing changed, `1` when a device is new, missing, changed, or has a different MAC address, and `2` when the command itself fails. A usage mistake, such as leaving off the IP address, exits `2`.

### See the real command

`homenet --show-cmd devices` still runs the command. Before each underlying command runs, homenet prints it to stderr, shell-quoted, as you would type it:

```text
$ nmap -sn -T4 -oX - 192.168.1.0/24
```

The flag can sit before or after the command name: `homenet devices --show-cmd` is the same. Add `--json` and those `$` lines are left out. The JSON object gains a `commands` list instead. Each item has `argv`, `display`, `purpose`, and `kind` (`exec` or `http`). On failure the error object gains that same list.

`homenet explain devices` prints each command and a one-line purpose, and does not run them:

```text
$ nmap -sn -T4 -oX - 192.168.1.0/24
  find devices that are up (ping sweep)
```

`explain devices --network 192.168.1.0/24` uses that subnet and does not run `ip`. `explain router` also takes `--gateway 192.168.1.1`. The `router` command does not take `--gateway`. Without those options, explain looks up your home network and gateway the same way a real run does, which may run the `ip` command. It is not a scan. A bad `--network` gets the usual invalid-target error and fix hint. `explain` accepts `--json`. `device`, `baseline`, and `new-devices` use the same ping sweep as `devices`.

## Speed contacts Cloudflare

`homenet speed` times one short HTTPS download and prints megabits per second, the number of bytes, and how long it took. The sample comes from **speed.cloudflare.com**: `https://speed.cloudflare.com/__down?bytes=1000000` (one million bytes). The command says this is a short download from Cloudflare (speed.cloudflare.com), not a full speed test. Your computer must be able to reach that host.

## Troubleshooting

### `sudo: homenet: command not found` in a venv or pipx

`sudo` keeps a short `PATH`. It does not see `homenet` when that command lives in a virtualenv or in pipx's bin directory. `homenet doctor` does not need sudo, and running `sudo homenet doctor` fails the same way.

When you want MAC addresses and makers, run the scan through the program file itself. Doctor prints a line you can copy. You can also look the command up in your own shell, before sudo starts:

```bash
sudo "$(command -v homenet)" devices
```

`command -v` prints the absolute path, and the quotes hand that path to sudo. The same form works for `device` and `baseline`.

### WSL 2 shows a virtual network, not the home LAN

WSL 2 normally puts Linux on a private network inside `172.16.0.0/12`. `homenet whoami-net` and `homenet doctor` warn that this may be the WSL virtual network, not the home LAN. A real LAN in that range can look the same, including WSL in mirrored mode. The warning does not change the exit code.

To use the same network as Windows, add this to `%UserProfile%\.wslconfig` (that file is on the Windows side):

```ini
[wsl2]
networkingMode=mirrored
```

Then shut WSL down from Windows and open it again:

```bash
wsl --shutdown
```

Run `homenet whoami-net`. The address should now be on your home LAN, and the warning should be gone.
