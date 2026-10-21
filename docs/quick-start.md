# Quick start

Run these three in order, on a network you are allowed to scan.

## `homenet doctor`

You should see a heading, **Home network doctor**, then `nmap`, `ip`, `privileges`, `network`, and `ping`, then the optional tools `nmcli`, `iw`, and `resolvectl`. On WSL 2 NAT a `wsl` warning is inserted before those optional tools. Each line starts with `PASS`, `WARN`, or `FAIL`. A warning or failure adds a `Fix:` line when doctor knows one. When every check is fine, including the optional tools, the last line is `All 8 checks passed.` A warning (often privileges, a gateway that ignores ping, or a missing optional tool) still exits 0. Any `FAIL` exits 1. Doctor does not need sudo. `wifi` and `dns` do not need sudo either.

## `homenet whoami-net`

You should see **This computer on your home network**, then five rows:

- **Interface**, how this computer is connected, such as Wi-Fi
- **IP address**, this computer, without a prefix (for example `192.168.1.100`)
- **Gateway**, usually your home router
- **Home network**, the group of addresses your devices share (for example `192.168.1.0/24`)
- **Network size**, how many addresses that network holds (for example `/24 (256 addresses: 192.168.1.0–192.168.1.255)`)

This reads your own route with `ip`. A missing value is `not available`. Exit 0 when the route can be read. If you are not connected, it tells you to connect to Wi-Fi or Ethernet. On a 172.16/12 address inside WSL it adds a warning that this may be the WSL virtual network, not the home LAN. The command still exits 0.

## `homenet devices`

The safety reminder prints first. Then **Devices on your home network**, a table with columns **IP address**, **Name**, **MAC address**, and **Maker**, and a count such as `4 devices found.` This is an nmap ping sweep (`-sn`) of the home network from `whoami-net`. It can take up to a couple of minutes. Names nmap does not already know are looked up when possible. Anything it cannot see is `unknown`, which is common for MAC addresses and makers unless you used the privilege fix above. The row for this computer is named **this computer**, and its MAC address is filled in from this machine when the scan did not see one. If nothing answers, it says no devices were found and asks you to check the connection. Exit 0 when the sweep finishes.

The privilege fix is in [Sudo and virtual environments](sudo.md#running-with-sudo-debianubuntu).

## See also

- [Commands](commands.md)
- [Sudo and virtual environments](sudo.md)
- [WSL 2](wsl.md)
- [README](../README.md)
