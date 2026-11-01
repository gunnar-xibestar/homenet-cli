# Explain

Explain prints the command homenet would run, and a one-line purpose, and does not run it. `--network` supplies the home network so explain does not need `ip`.

## Sub-features

- `explain-devices` shows the ping sweep for a private /24.
- `explain-json` returns that plan as JSON.
- `explain-bad-network` rejects a network that is not an IPv4 CIDR.

## How to get to it (user POV)

- Run `homenet explain devices --network 192.168.1.0/24`.
- Run `homenet explain devices --network 192.168.1.0/24 --json`.
- Run `homenet explain devices --network not-a-network`.

## Driving it with homenet-drive

Preconditions:

- `homenet-drive doctor` is ready.
- `nmap.log` must stay empty. Explain does not invoke nmap.

- **Show the sweep.** Run `homenet-drive run --feature explain -- explain devices --network 192.168.1.0/24`. Exit 0. stdout contains a line `$ <path>/nmap -sn -T4 -oX - 192.168.1.0/24` and the next line `find devices that are up (ping sweep)`. `<path>/nmap` is the sentinel, because it is first on `PATH`. `nmap.log` is empty.
- **JSON plan.** Run `homenet-drive run --feature explain -- explain devices --network 192.168.1.0/24 --json`. Exit 0. stdout is JSON whose `command` is `devices` and whose `commands` list includes argv containing `nmap`, `-sn`, and `192.168.1.0/24`. There is no safety banner. `nmap.log` is empty.
- **Bad network.** Run `homenet-drive run --feature explain -- explain devices --network not-a-network`. Exit 1. stdout contains `not a valid IP address or subnet` and `Fix:`. `nmap.log` is empty.

## Gotchas

- `homenet explain devices` without `--network` may run `ip` to find the home network. That entry point is a different proof. Do not use it as proof of the `--network` path.
- The printed nmap path is whatever `PATH` finds. Under this harness that is the sentinel. The flags and the target are the proof, not a bare `nmap` with no directory.
- `homenet devices --show-cmd` still scans. It is not explain.
- A public `--network` such as `8.8.8.0/24` is still printed by explain. Explain does not apply the scan guard. Refusing a public target is [Refuse a public port scan](./refuse-public.md), not this feature.
