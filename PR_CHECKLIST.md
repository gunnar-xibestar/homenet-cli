# PR Checklist (homenet-cli)

Use this for every change. Reviewers: block merges on unchecked safety items.

## Tests & fixtures
- [ ] New/changed parsing logic has tests using saved samples in `tests/fixtures/`
- [ ] Edge cases covered: no hosts up, malformed/truncated XML, missing MAC/vendor, 100% ping loss
- [ ] Fixtures are hand-written or sanitized (no real MACs/hostnames from personal networks)
- [ ] No test runs real `nmap`, `ping`, or `ip` (the `no_real_commands` guard stays autouse)
- [ ] `ruff check .`, `ruff format --check .` and `pytest` pass locally

## Safety
- [ ] Subnet guard: only private RFC1918 (10/8, 172.16/12, 192.168/16) or local link/loopback ranges; public ranges are refused
- [ ] Overly large ranges are refused (e.g. larger than /16) with a clear message
- [ ] No `shell=True`; commands are built as argument lists only, never string concatenation
- [ ] Default scan is non-intrusive (`-sn`); `-sS`, `-sU`, `-O`, `-A`, `--script`, `-p-` etc. require an explicit opt-in flag
- [ ] No sudo/root assumptions; works (with reduced detail) as a normal user and explains when root would help
- [ ] User input (targets, flags) is validated before reaching nmap

## UX
- [ ] Errors are beginner-friendly: what went wrong + how to fix (e.g. "nmap is not installed: try `sudo apt install nmap`")
- [ ] No raw tracebacks for expected failures (missing nmap, no network, bad subnet, parse errors)
