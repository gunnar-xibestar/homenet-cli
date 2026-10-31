---
name: verify-scan-guard
description: Prove homenet's validate_target refuses public and oversized IPv4 networks inside a stated bound. Use when changing src/homenet/core/runner.py, especially validate_target, _ALLOWED_RANGES, or MAX_PREFIX_LEN.
---

# Verify the scan guard

A user who can make homenet call `validate_target` with `force=True` must still be unable to scan a public range or anything larger than a /16. The CLI does not expose `force` today. `devices.sweep` and `run_scan` do, and `run_scan` calls `validate_target` before it looks for nmap (`src/homenet/core/runner.py`, `validate_target` and `run_scan`).

## Property

With `force=True`, an IPv4 network is accepted only when it sits inside `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, or `127.0.0.0/8` and its prefix is /16 or longer. Every other IPv4 network in the bound is refused. With `force=False` and local network `192.168.1.0/24`, a network in that same bound is accepted only when the force=True rule accepts it and it is a subnet of `192.168.1.0/24`.

Harm: if this breaks, homenet can hand nmap a public address or a range bigger than a /16.

## Tool

The check calls the real `validate_target`. It does not reimplement the decision and compare two copies of the same function. The allowed ranges and the /16 floor are repeated in `check_scan_guard.py` as the promise, so editing `_ALLOWED_RANGES` or `MAX_PREFIX_LEN` without editing the promise makes the check fail.

This is a bounded exhaustive test, not a model checker. TLA+ would describe the guard in another language. An SMT verifier on `ipaddress` does not add cases this loop does not already execute, and it is harder for this repo to install. The loop is the check.

## Run

From the repo root:

```bash
python3 .cursor/skills/verify-scan-guard/check_scan_guard.py
```

The script inserts `src` on `sys.path` itself. Exit 0 prints `scan guard passed` and a case count. Exit 1 prints up to eight counterexamples as `validate_target(...)` lines. No package install is required beyond Python 3.10 and this checkout.

## How to read a failure

A counterexample names the target string, `force`, and the local network. `accepted` means the function returned that network. `refused` means `TargetNotAllowedError`. `invalid` means `InvalidTargetError`.

If the function accepts `11.0.0.0/16` or `8.8.8.8/32`, the public-range raise in `validate_target` is missing or no longer covers that network. If it accepts `10.0.0.0/8` or `10.0.0.0/15`, the `/16` floor is missing. If it accepts `192.168.1.0/16` with `force=False` and local `192.168.1.0/24`, the local-subnet check is missing. If a malformed string is `accepted` or `refused` instead of `invalid`, parsing no longer rejects it before the range check.

A modeling error looks different: the promise in `check_scan_guard.py` disagrees with the ranges you can read in `runner.py`, or the counterexample is outside the bound below. Do not edit the promise to match a bug. Do not edit `runner.py` unless the user asked for a product change.

## Bound

Executed, every case:

- All 65,536 IPv4 /16 networks, and for each, prefixes 16 through 32 on that block's base address. Both `force=True` (no local network) and `force=False` with local `192.168.1.0/24`.
- Every aligned subnet of the five allowed ranges whose prefix is shorter than /16 (the networks only the size gate can refuse).
- Prefixes 0 through 15 on these bases: `0.0.0.0`, `1.2.3.4`, `8.8.8.8`, `11.0.0.0`, `172.32.0.0`, `192.167.0.0`, `203.0.113.0`, `255.255.255.255`.
- These malformed strings: empty, spaces, `-10.0.0.0`, `10.0.0.0 24`, `::1`, `2001:db8::/32`, `10.0.0.0/33`, `not-an-ip`, `10.0.0.0/16 extra`.

Not executed: every other host address inside a /16, every public prefix shorter than /16 that is not one of those eight bases, and every possible string. `validate_target` decides from the normalized network plus one prefix comparison (`prefixlen < 16`) and `subnet_of` against the five ranges. A change that special-cases a single address that is not a /16 base is outside this bound until this script grows a case for it.

`ports.scan_ports` also refuses addresses outside the detected local subnet before nmap, in `resolve_local_target`. That path is not this check.

## When the code and this check disagree

The check covers `validate_target` in `src/homenet/core/runner.py`. It was last confirmed against commit `SYNC_COMMIT`.

If `runner.py` changed after that commit, read `validate_target` again before trusting a pass. Move `SYNC_COMMIT` forward only after the script still describes the function at the new commit: same refusal order (parse, IPv4, inside the five ranges, then the /16 floor, then the local subnet unless `force`), and the promise ranges still match `_ALLOWED_RANGES` and `MAX_PREFIX_LEN`.

## Seeing it fail

Delete or skip the public-range `raise` in `validate_target`, run the script, and confirm it exits 1. The first counterexamples are public networks that were accepted, starting at `0.0.0.0/16`. Restore the file. Do not leave the broken function in the tree. A pass you have never seen fail is not evidence.
