# Devices

devices prints the safety banner and then a ping sweep of the home network from whoami-net. That sweep is nmap.

## Sub-features

- `devices-live` lists hosts that answered, or says none did.
- `devices-json` prints the same list as JSON without the banner.

## How to get to it (user POV)

- Run `homenet devices`.
- Run `homenet devices --json`.

## Driving it with homenet-drive

Preconditions:

- The operator is authorized to scan the network whoami-net would name.
- A real nmap is what `homenet` will execute.
- This harness does not meet that second precondition. Its sentinel refuses scan flags.

- **Do not start the sweep.** The command would be `homenet-drive run --feature devices -- devices`. Stop before running it. Report the unmet precondition: the verification PATH serves the sentinel, which will not perform `-sn`. Do not delete the sentinel, and do not put a real nmap ahead of it, to make this pass.
- **JSON is the same stop.** `homenet devices --json` is a second entry point. It is not verified by the plain command, and it is not verified while the sentinel is in place.

## Gotchas

- A transcript whose `nmap.log` contains `-sn` is a blocked scan, not a device list. Do not read exit 99 as "no devices found".
- `homenet explain devices --network 192.168.1.0/24` proves the planned command only. It is the explain feature.
- `homenet devices --show-cmd` still scans. Showing the command is not a substitute for this feature, and it is still a scan the harness must not launch.
