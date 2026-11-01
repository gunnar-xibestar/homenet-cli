---
name: verify-homenet
description: Drive the homenet CLI (terminal, not a web UI) in an isolated home directory and prove doctor, explain, whoami-net, a refused public port scan, or the devices command. Use when changing those commands, their output, or the scan refusal a user sees.
---

# Verify homenet

homenet is a short-lived Linux CLI. There is no server to keep up. Verification installs the checkout once, then runs one command per drive in its own PTY, with its own `HOME` and XDG directories. The primary surface is the `homenet` command. `install.sh` is a separate installer and is not what this skill drives.

Two drives can run at the same time. Each uses a new `/tmp/homenet-verify-*` directory. Do not point a drive at the operator's real home.

## Launch

From the repo root, with Python 3.10+. On Debian or Ubuntu, `python3 -m venv` needs the `python3-venv` package (`python3.12-venv` on this image) or setup fails with `ensurepip is not available`.

```bash
.cursor/skills/verify-homenet/bin/homenet-drive setup
```

That creates `.cursor/skills/verify-homenet/.venv` and runs `pip install -e <repo>`. It does not install nmap. Ready means `homenet-drive doctor` prints `verify-homenet doctor: ready` and the version matches `pyproject.toml`.

Each drive starts `homenet` in a new session with a controlling terminal on stdout. Stderr is a separate pipe so the proof keeps both streams. The process exits on its own. Scratch dirs for a finished drive are removed when that drive returns. `homenet-drive cleanup` is still required after a drive that is killed mid-command.

## Doctor

Run this before trusting a drive, and again when a drive looks wrong:

```bash
.cursor/skills/verify-homenet/bin/homenet-drive doctor
```

It is read-only. It checks that `.venv/bin/homenet` exists, resolves inside that venv, and `homenet --version` prints `homenet <version>` from `pyproject.toml`. It does not scan.

## Drive

```bash
.cursor/skills/verify-homenet/bin/homenet-drive run --feature <id> -- <homenet args>
```

The helper (`bin/homenet-drive`) does all of the following:

- Sets `HOME`, `XDG_DATA_HOME`, `XDG_CONFIG_HOME`, and `XDG_CACHE_HOME` under `/tmp/homenet-verify-<feature>-<time>-<pid>`.
- Puts `.cursor/skills/verify-homenet/sentinel` first on `PATH`, then the venv, then the `PATH` already in the environment, so `ip` and `ping` stay findable. The sentinel binary is named `nmap`. It appends its arguments to the drive's nmap log. `--version` and any non-scan probe print `Nmap version 0.0.0 (homenet verification sentinel)` and exit 0. Scan arguments (`-sn`, `-sT`, `-sS`, `-sV`, `-oX`, `--top-ports`, `-p`, `-p-`, `-A`, `-O`, `--script`) exit 99 and do not scan.
- Runs `homenet` with stdout on a PTY and stderr on a pipe.
- Writes the proof under `.cursor/skills/verify-homenet/artifacts/<feature>/<run-id>/`.

Read the feature file before choosing `<homenet args>`. The feature id is the file name without `.md`.

A command that reaches nmap with scan arguments fails this harness on purpose. That is a refusal, not a successful scan. Do not remove the sentinel to make `devices` pass.

## Evidence

Each artifact directory holds `command.txt`, `stdout.txt`, `stderr.txt`, `exit_code.txt`, `nmap.log`, and `transcript.txt`.

Proof standards:

- Drive the real `homenet` binary from the verification venv. Do not call `validate_target` or other internals and call that a user proof.
- Record the command, both streams, and the exit code. A final screen without the command is not proof.
- `nmap.log` is the side effect for "did this turn into a scan?". Empty means nmap was not started. A log that contains only a version probe is not a scan. A log that contains a scan flag means the command tried to scan; the sentinel blocked it.
- `--json` proof is the JSON on stdout for success, or the JSON error on stderr. It has no safety banner.
- Plain stdout on a terminal includes two leading padding lines and, when the command succeeds, five trailing ones. Each line is one middle dot (U+00B7) when stdout is UTF-8. Do not treat those dots as part of the command's text.
- The sentinel is a stand-in. A doctor line that says nmap `0.0.0` is the sentinel answering `--version`, not a distro nmap. Whether a machine without this harness reports nmap missing is not covered by that PASS.

## Cleanup

```bash
.cursor/skills/verify-homenet/bin/homenet-drive cleanup
```

This sends `SIGTERM` only to pids recorded in `.cursor/skills/verify-homenet/run-state/` (drives this skill started and did not finish) and deletes `/tmp/homenet-verify-*` directories. It does not delete `.cursor/skills/verify-homenet/artifacts/`. A finished `run` already removes its own scratch directory. After cleanup, confirm the artifact directory from the drive is still there.

## Helpers

`bin/homenet-drive` is the only helper. Invoke it by that path. `setup`, `doctor`, `run`, and `cleanup` are its subcommands.

## Feature map

The maintained map is [features/README.md](features/README.md). A proof that drives one entry point does not cover the others listed there.
