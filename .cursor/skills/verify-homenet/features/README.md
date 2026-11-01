# homenet verification map

This directory is the maintained source for verifying the user-facing behavior of the homenet CLI. Read this index, then use the matching feature file as the recipe.

## Baseline preconditions

- The checkout is the repo that contains this skill.
- `.cursor/skills/verify-homenet/bin/homenet-drive setup` has been run, and `homenet-drive doctor` reports the venv binary and the `pyproject.toml` version.
- Every drive uses `homenet-drive run`, which sets a fresh `HOME` and XDG directories under `/tmp/homenet-verify-*`.
- The sentinel `nmap` is first on `PATH`. It answers version probes and refuses scan arguments.
- Never drive `homenet` against the operator's real home, and never remove the sentinel to let a scan out.

## Driving conventions

- Start from the baseline preconditions unless the feature adds its own.
- Pass homenet arguments after `--`. Keep flags and addresses unchanged.
- Treat a sentinel exit 99 as "a scan was attempted and blocked", not as a successful scan.
- Leave proof artifacts in place. Cleanup does not delete them.

## Proof and skip reporting

- Capture the command, stdout, stderr, exit code, and `nmap.log`.
- Record the feature id and the entry point with the artifact path.
- If a precondition is missing, stop and report the command you would have run and the unmet precondition. Do not count a different command as proof of that entry point.

## Feature entry contract

Each feature file has an H1, one opening paragraph, then these H2 sections in order: `Sub-features`, `How to get to it (user POV)`, `Driving it with homenet-drive`, `Gotchas`.

## Features

- [Doctor](./doctor.md) checks tools, privileges, and the route. It does not scan the network.
- [Explain](./explain.md) prints the nmap command for a named home network and does not run it.
- [Refuse a public port scan](./refuse-public.md) refuses `homenet ports 8.8.8.8` before nmap starts.
- [Who am I on the network](./whoami-net.md) prints this computer's address from `ip`.
- [Devices](./devices.md) is the live ping sweep. This harness does not allow that scan to start.
