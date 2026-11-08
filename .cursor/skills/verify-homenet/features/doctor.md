# Doctor

Doctor reports whether nmap, ip, ping, privileges, and the network route look usable, plus the optional tools nmcli, iw, and resolvectl. It does not scan the LAN.

## Sub-features

- `doctor-plain` prints the Home network doctor report and an exit code of 0 when nothing is an error, or 1 when an error-level check failed.
- `doctor-json` prints the same checks as JSON on stdout.

## How to get to it (user POV)

- Run `homenet doctor`.
- Run `homenet doctor --json`.

## Driving it with homenet-drive

Preconditions:

- `homenet-drive doctor` is ready.
- The sentinel is on `PATH`, so the nmap line is about the sentinel, not a distro package.

- **Plain report.** Run `homenet-drive run --feature doctor -- doctor`. Exit 0 or 1. stdout contains `Home network doctor`, then lines whose status is `PASS`, `WARN`, or `FAIL` for `nmap`, `ip`, `privileges`, `network`, and `ping`. A non-PASS line may include `Fix:`. The last paragraph is `All 8 checks passed.` or a count of failures and warnings. `nmap.log` contains a version probe and no scan flag.
- **JSON report.** Run `homenet-drive run --feature doctor -- doctor --json`. Exit 0 or 1. stdout is a JSON document and does not contain the safety banner. stderr is empty unless a check writes there. `nmap.log` again has only the version probe.

## Gotchas

- A PASS for nmap that mentions version `0.0.0` is the verification sentinel. It does not prove the machine's real nmap is installed.
- Warnings, including a gateway that ignores ping, still exit 0. Only an error-level check exits 1.
- Doctor may run real `ip` and `ping` against the default gateway. That is the user path. It is not an nmap scan.
- Two leading middle-dot lines are padding, not part of the heading.
