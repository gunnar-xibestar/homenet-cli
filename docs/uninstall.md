# Uninstall

## `homenet uninstall`

Removes this copy of homenet. It asks `Uninstall homenet? [y/N]` and the default is no. `--yes` skips that question. A non-interactive terminal needs `--yes`.

It prints the command before it runs it:

- a virtual environment or a user-site install: `python -m pip uninstall -y homenet-cli`
- pipx: `pipx uninstall homenet-cli`

The saved device snapshot stays. `--purge` deletes `baseline.json` and removes the data folder only when that leaves it empty. It also lists source checkouts named `homenet-cli` under your home directory. Deleting one always requires you to type `yes`, and only when the checkout is a clean git clone with no local changes, unpushed commits, or extra git config.

A system package or an editable checkout is not removed. `uninstall` does not need sudo.

## A release package or ~/.local/bin

`homenet uninstall` does not remove a `.deb`, and it does not remove a program copied to `~/.local/bin`. How to remove those, and the `sudo apt remove homenet` command, are in [Install](install.md#uninstall).

## See also

- [Exit codes](exit-codes.md)
- [Commands](commands.md)
- [README](../README.md)
