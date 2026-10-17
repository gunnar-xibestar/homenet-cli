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

The scan commands run nmap. `homenet doctor` also looks for the `ip` command and for ping. `homenet wifi` can use `nmcli` and `iw`. `homenet dns` can use `resolvectl`. Those three are optional: doctor warns when one is missing, and the command still exits 0.

```bash
sudo apt install nmap       # Debian, Ubuntu
sudo dnf install nmap       # Fedora
sudo pacman -S nmap         # Arch Linux
```

If a required tool is missing, doctor prints an apt fix: `sudo apt install nmap`, `sudo apt install iproute2` (the `ip` command), or `sudo apt install iputils-ping`. A missing optional tool is a warning with its own apt fix: `network-manager` for `nmcli`, `iw` for `iw`, and `systemd-resolved` for `resolvectl`.

### Privileges

Scans work as a normal user. No command runs a SYN scan. `ports` is a TCP connect scan (`-sT`) and works without root. `services` uses `-sT -sV --version-light` and works without root too. `router` only requests the gateway's admin page, so root does not change that result. Root adds MAC addresses and makers to `devices`, `device`, and `baseline`. `new-devices` uses that same sweep, so those fields show up there as well.

### Running with sudo (Debian/Ubuntu)

When doctor warns about privileges, MAC addresses and makers need a scan run with sudo. `sudo` resets `PATH`, so plain `sudo homenet` cannot find a venv's `homenet` and fails with "command not found". Look the program up in your own shell first, or use the absolute path doctor prints:

```bash
sudo "$(command -v homenet)" devices
```

The same form works for a pipx install. `doctor`, `whoami-net`, `explain`, `speed`, `wifi`, `dns`, and `uninstall` do not need sudo. A privileges warning still lets doctor exit 0. A missing required tool or no network route is a failure and exits 1. A missing `nmcli`, `iw`, or `resolvectl` is only a warning. On WSL 2's virtual network, doctor adds a `wsl` warning and still exits 0.

## Quick start

Run these three in order, on a network you are allowed to scan.

### `homenet doctor`

You should see a heading, **Home network doctor**, then `nmap`, `ip`, `privileges`, `network`, and `ping`, then the optional tools `nmcli`, `iw`, and `resolvectl`. On WSL 2 NAT a `wsl` warning is inserted before those optional tools. Each line starts with `PASS`, `WARN`, or `FAIL`. A warning or failure adds a `Fix:` line when doctor knows one. When every check is fine, including the optional tools, the last line is `All 8 checks passed.` A warning (often privileges, a gateway that ignores ping, or a missing optional tool) still exits 0. Any `FAIL` exits 1. Doctor does not need sudo. `wifi` and `dns` do not need sudo either.

### `homenet whoami-net`

You should see **This computer on your home network**, then five rows:

- **Interface**, how this computer is connected, such as Wi-Fi
- **IP address**, this computer, without a prefix (for example `192.168.1.100`)
- **Gateway**, usually your home router
- **Home network**, the group of addresses your devices share (for example `192.168.1.0/24`)
- **Network size**, how many addresses that network holds (for example `/24 (256 addresses: 192.168.1.0–192.168.1.255)`)

This reads your own route with `ip`. A missing value is `not available`. Exit 0 when the route can be read. If you are not connected, it tells you to connect to Wi-Fi or Ethernet. On a 172.16/12 address inside WSL it adds a warning that this may be the WSL virtual network, not the home LAN. The command still exits 0.

### `homenet devices`

The safety reminder prints first. Then **Devices on your home network**, a table with columns **IP address**, **Name**, **MAC address**, and **Maker**, and a count such as `4 devices found.` This is an nmap ping sweep (`-sn`) of the home network from `whoami-net`. It can take up to a couple of minutes. Names nmap does not already know are looked up when possible. Anything it cannot see is `unknown`, which is common for MAC addresses and makers unless you used the privilege fix above. The row for this computer is named **this computer**, and its MAC address is filled in from this machine when the scan did not see one. If nothing answers, it says no devices were found and asks you to check the connection. Exit 0 when the sweep finishes.

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
homenet speed                   # an estimate of download speed
homenet wifi                    # signal, band, and channel for the Wi-Fi you are on
homenet dns                     # DNS servers, who they belong to, and a lookup
homenet uninstall               # remove homenet; saved data stays unless --purge
homenet explain devices         # show the real commands, without running them
```

`device` prints the name, IP address, MAC address, and maker, then a Ports section. It uses the same ping sweep as `devices` (`-sn`), which does not scan ports, so that section says `No ports were reported for this device.` `ports` checks the top 100 TCP ports on one address and labels each open port low, medium, or high risk. `services` names the program and version on one address when it can. `router` asks the gateway on ports 80, 443, and 8080 and only requests the page. No open ports, and a router with no admin page, are still a successful run.

`baseline` saves the device list to `$XDG_DATA_HOME/homenet/baseline.json` when that variable is an absolute path, otherwise `~/.local/share/homenet/baseline.json`. `new-devices` compares a fresh sweep with that file. If you have not saved one yet, it says to run `homenet baseline` first.

### `homenet uninstall`

Removes this copy of homenet. It asks `Uninstall homenet? [y/N]` and the default is no. `--yes` skips the question. If this is not an interactive terminal and you did not pass `--yes`, homenet stops and tells you to add `--yes`, instead of waiting for an answer that will never come.

What it runs depends on how homenet was installed. It prints that command before it runs it:

- a virtual environment or a user-site install (`pip install` or `pip install --user`): `python -m pip uninstall -y homenet-cli`, using this program's Python
- pipx: `pipx uninstall homenet-cli`

`--show-cmd` still prints the `$` line when the command actually runs. `homenet explain uninstall` prints the command and its purpose without running it. `--json` prints the result with no question on stdout. Add `--yes` for a script. `--show-cmd --json` adds the `commands` list, the same way as the other commands.

The saved device snapshot stays put. homenet prints where it lives (`$XDG_DATA_HOME/homenet/baseline.json`, or `~/.local/share/homenet/baseline.json`) and says it was kept.

`--purge` deletes that data folder, and source checkouts it finds under your home directory. A folder counts as a checkout only when its name is exactly `homenet-cli` and it contains a `pyproject.toml` whose project name is `homenet-cli`. homenet lists every path it will delete, grouped as data and source checkouts, before it asks anything. `--yes` covers the uninstall and the data folder only. Deleting a source checkout always requires you to type `yes`, even when you passed `--yes`. If there is no terminal to type that, the checkouts stay and homenet says so. A checkout with uncommitted or unpushed git changes is called out in that list. Answering no runs nothing and deletes nothing.

The search stays inside your home directory. It does not follow symbolic links, does not walk hidden folders other than `~/.local`, skips dependency folders such as `node_modules`, and only looks a few levels down. It will not delete your home directory, `/`, or any path outside your home. If `HOME` is unset or empty, it deletes no files and explains why. A relative or empty `XDG_DATA_HOME` is ignored, the same way as when saving a baseline. Only the homenet data folder is removed, never its parent.

A system package (apt), an editable checkout, or an install homenet does not recognize is not removed. homenet prints the command to run yourself, such as `sudo apt remove python3-homenet-cli` or `python -m pip uninstall homenet-cli` from the source checkout, and exits 1. Nothing is run for those, and an editable checkout is not deleted. `uninstall` does not need sudo.

### `homenet wifi`

Prints the Wi-Fi name, the interface, and the signal as words plus a number, such as `Good (-55 dBm)`. Excellent is -50 dBm or stronger, Good is -60 or stronger, Fair is -70 or stronger, and anything weaker is Weak. When the radio reading is only a percent, that percent is used instead. When neither is available, the signal line says `unknown (install iw to see signal)`. One more line explains the band and channel: 2.4 GHz reaches farther, and 5 GHz is faster but has a shorter range. Link speed is shown when `iw` reports it.

Inside WSL the command prints `Wi-Fi info isn't visible inside WSL` and exits 0. If this computer has no Wi-Fi, is not connected, or does not have `nmcli` or `iw`, it prints a short reason and still exits 0. `wifi` does not need sudo.

```text
Your Wi-Fi

Network     Home
Interface   wlan0
Signal      Good (-55 dBm)
Channel     36 (5 GHz)
Link speed  866.7 Mb/s

Channel 36 is on 5 GHz. 5 GHz is faster but has a shorter range, and 2.4 GHz reaches farther.
```

On WSL:

```text
Your Wi-Fi

Wi-Fi info isn't visible inside WSL
```

### `homenet dns`

Lists each DNS server and who it likely belongs to:

- the gateway address is **your router**
- a loopback address, such as `127.0.0.53`, is **this computer (local resolver)**. The upstream servers are listed too.
- Cloudflare (`1.1.1.1`, `1.0.0.1`, `2606:4700:4700::/48`), Google (`8.8.8.8`, `8.8.4.4`, `2001:4860:4860::/48`), and Quad9 (`9.9.9.9`, `149.112.112.112`, `2620:fe::/48`) are named public resolvers
- another private or link-local address, such as `192.168.1.2` or `fe80::1`, is **a device on your network**
- any other public address is **likely your internet provider**

The last line is a lookup of `example.com`: whether it succeeded, how long it took, and the address it found. `dns` does not need sudo. It exits 0 even when the lookup fails, so you can read the reason.

```text
DNS servers

Server       Who it is
192.168.1.1  your router
1.1.1.1      Cloudflare (public)
8.8.8.8      Google (public)

Lookup of example.com succeeded in 18.2 ms (93.184.216.34).
```

A local resolver lists the upstream servers under the table:

```text
Server      Who it is
127.0.0.53  this computer (local resolver)

Upstream servers: 192.168.1.1 (your router), 1.1.1.1 (Cloudflare (public)).
```

### `--json` and exit codes

Every command except `baseline` takes `--json`. JSON goes to stdout, with no safety banner. Errors go to stderr as `{"error": "...", "fix_hint": "..."}`.

Exit `0` means the command succeeded. Exit `1` means it failed. `doctor` exits `1` only when a check fails at error level. Warnings still exit `0`, including a missing `nmcli`, `iw`, or `resolvectl`. `wifi` and `dns` exit `0`, including when Wi-Fi is not available, inside WSL, and when the lookup fails. `new-devices` exits `0` when nothing changed, `1` when a device is new, missing, changed, or has a different MAC address, and `2` when the command itself fails. `uninstall` exits `0` when it removes homenet or when the answer is no, and `1` when it refuses or the uninstall fails. A usage mistake, such as leaving off the IP address, exits `2`.

### Progress

In a terminal, homenet shows a status line on stderr while a scan, sweep, HTTP check, Wi-Fi read, or DNS check runs, such as `Scanning 192.168.1.0/24… (12s)`, `Reading Wi-Fi…`, or `Checking DNS…`, and clears it when the step finishes. `--json`, and a run whose stderr is not a terminal, leave that line out so stdout stays intact.

`homenet speed` uses its own line, and there is no flag to turn it off. In a terminal it updates in place, for example `Testing download speed... 3s of 8s, about 212 Mbps so far`. During warmup, while the rate is still zero, that line says `warming up`. The line is cleared before the result or an error is printed. When stderr is not a terminal, each update is a plain line and the carriage return is left out. `--json` prints no progress line on stdout or stderr.

`-v` prints each step on stderr, such as `Parsed 7 hosts`, `Resolving names…`, `Reading Wi-Fi link of wlan0 (iw)`, or `Looking up example.com`. `-vv` also shows nmap's progress every 5 seconds. The flag can go before or after the command. Wi-Fi and DNS do not print nmap progress.

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

`explain wifi` lists the `nmcli` and `iw` reads, and `explain dns` lists `resolvectl status` when that tool is installed. Neither runs them. `wifi` and `dns` do not take `--network`. A live `homenet dns` may also run `ip` to learn the gateway so it can label your router. That is the same lookup as `whoami-net`.

`explain speed` lists one download per connection and does not run them. The default is 4:

```text
$ curl -sS --max-time 10 'https://speed.cloudflare.com/__down?bytes=25000000'
  download 25000000 bytes to estimate speed
```

That block is repeated once per connection. `homenet speed --show-cmd` still runs the test. Before each request it prints that same curl line on stderr. A connection is requested again until the 8 seconds are up, so the line can appear more than once.

## Speed contacts Cloudflare

`homenet speed` estimates download speed. It opens 4 connections to **speed.cloudflare.com** and downloads for about 8 seconds:

`https://speed.cloudflare.com/__down?bytes=25000000`

The first second is warmup and is not part of the estimate. The number is an estimate, not a full speed test. Wi-Fi and other devices in your home can make it lower than your plan. Your computer must be able to reach that host.

```text
Download speed  about 215 Mbps (estimate)
Used 4 connections over about 8 seconds.
```

If a connection fails, one more line says how many reported an error, for example `2 connections reported an error.`

`--json` keeps `download_mbps`, `bytes`, `seconds`, and `url`, and adds `median_mbps`, `connections`, `warmup_s`, `errors`, and `total_bytes`.

## Troubleshooting

### Running with sudo (Debian/Ubuntu)

`sudo` resets `PATH`, so plain `sudo homenet` fails with `sudo: homenet: command not found` when that command lives in a virtualenv. sudo cannot find the venv's `homenet`. `doctor`, `whoami-net`, `explain`, `speed`, `wifi`, `dns`, and `uninstall` do not need sudo, and `sudo homenet doctor` fails the same way.

When you want MAC addresses and makers, look the program up in your own shell, before sudo starts. Doctor prints a line you can copy.

```bash
sudo "$(command -v homenet)" devices
```

`command -v` prints the absolute path, and the quotes hand that path to sudo. The same form works for a pipx install, and for `device`, `baseline`, and `new-devices`.

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
