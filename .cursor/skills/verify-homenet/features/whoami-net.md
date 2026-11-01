# Who am I on the network

whoami-net prints this computer's interface, address, gateway, and home network. It reads `ip`. It does not run nmap.

## Sub-features

- `whoami-plain` prints the five rows and exits 0 when the route can be read.
- `whoami-json` prints the same facts as JSON.

## How to get to it (user POV)

- Run `homenet whoami-net`.
- Run `homenet whoami-net --json`.

## Driving it with homenet-drive

Preconditions:

- `homenet-drive doctor` is ready.
- `ip` is on `/usr/bin` or `/bin`. The drive's PATH includes both after the sentinel and the venv.

- **Plain table.** Run `homenet-drive run --feature whoami-net -- whoami-net`. Exit 0 when the machine has a route. stdout contains `This computer on your home network`, `Interface`, `IP address`, `Gateway`, `Home network`, and `Network size`. A missing value is the words `not available`. `nmap.log` is empty.
- **JSON table.** Run `homenet-drive run --feature whoami-net -- whoami-net --json`. Exit 0 when the route can be read. stdout is JSON and contains no safety banner. `nmap.log` is empty.

## Gotchas

- Exit 0 with `not available` still proves the command ran. It does not prove an address was found. Say which fields were missing.
- On WSL NAT the plain output adds a warning and still exits 0. This checkout's drive is the Linux VM the agent is on, which may not be WSL.
- whoami-net is not a scan. Do not follow it with `homenet devices` inside the same proof unless you are on the devices feature and you stop for its unmet precondition.
