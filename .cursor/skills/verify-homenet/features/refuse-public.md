# Refuse a public port scan

Asking for ports on a public address is refused before nmap starts. `8.8.8.8` is the address this map uses.

## Sub-features

- `ports-public` prints the safety banner and a refusal, and exits 1.
- `ports-public-json` returns that refusal as JSON on stderr, with no banner.

## How to get to it (user POV)

- Run `homenet ports 8.8.8.8`.
- Run `homenet ports 8.8.8.8 --json`.

## Driving it with homenet-drive

Preconditions:

- `homenet-drive doctor` is ready.
- The scratch home has no saved baseline. The drive's fresh `HOME` provides that.

- **Plain refusal.** Run `homenet-drive run --feature refuse-public -- ports 8.8.8.8`. Exit 1. stdout contains `Only scan networks you own or have permission to scan.` and `8.8.8.8`. The refusal is one of `outside your local subnet`, `not a private home-network range`, or `Could not detect your local network.` stdout also contains `Fix:`. `nmap.log` is empty. The scratch data directory is gone after the drive returns, which is the absence of a baseline file.
- **JSON refusal.** Run `homenet-drive run --feature refuse-public -- ports 8.8.8.8 --json`. Exit 1. stdout is empty or only whitespace. stderr is one JSON object with `error` and `fix_hint`. The error names `8.8.8.8` or the missing local network. There is no safety banner. `nmap.log` is empty.

## Gotchas

- `homenet device 8.8.8.8` sweeps the detected home network and then looks for that address. It is not this refusal. Do not drive it here.
- `homenet explain ports 8.8.8.8 --network 192.168.1.0/24` prints a plan. It does not prove the scan was refused.
- Which refusal sentence appears depends on whether this machine has a default route. All three sentences above are refusals that happen before nmap. An empty `nmap.log` is required for every one of them.
- Exit 99 with a scan line in `nmap.log` means the guard did not hold. That is a failed proof, not a pass.
