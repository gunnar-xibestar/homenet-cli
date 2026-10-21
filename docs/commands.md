# Commands

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

## `homenet device`

`device` prints the name, IP address, MAC address, and maker, then a Ports section. It uses the same ping sweep as `devices` (`-sn`), which does not scan ports, so that section says `No ports were reported for this device.` `ports` checks the top 100 TCP ports on one address and labels each open port low, medium, or high risk. `services` names the program and version on one address when it can. `router` asks the gateway on ports 80, 443, and 8080 and only requests the page. No open ports, and a router with no admin page, are still a successful run.

## `homenet ports`

`ports` checks the top 100 TCP ports on one address and labels each open port low, medium, or high risk.

## `homenet services`

`services` names the program and version on one address when it can.

## `homenet router`

`router` asks the gateway on ports 80, 443, and 8080 and only requests the page. No open ports, and a router with no admin page, are still a successful run.

## `homenet baseline`

`baseline` saves the device list to `$XDG_DATA_HOME/homenet/baseline.json` when that variable is an absolute path, otherwise `~/.local/share/homenet/baseline.json`. `new-devices` compares a fresh sweep with that file. If you have not saved one yet, it says to run `homenet baseline` first.

## `homenet new-devices`

`new-devices` compares a fresh sweep with that file. If you have not saved one yet, it says to run `homenet baseline` first.

## See also

- [Quick start (`doctor`, `whoami-net`, `devices`)](quick-start.md)
- [Uninstall](uninstall.md)
- [Wi-Fi](wifi.md)
- [DNS](dns.md)
- [Speed](speed.md)
- [See the real command](explain.md)
- [Progress](progress.md)
- [JSON output](json.md)
- [Exit codes](exit-codes.md)
- [README](../README.md)
