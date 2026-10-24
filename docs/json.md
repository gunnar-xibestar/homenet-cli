# JSON output

## `--json` and exit codes

Every command except `baseline` takes `--json`. JSON goes to stdout, with no safety banner. Errors go to stderr as `{"error": "...", "fix_hint": "..."}`.

## See also

- [Exit codes](exit-codes.md)
- [Safety](safety.md)
- [See the real command](explain.md)
- [README](../README.md)
