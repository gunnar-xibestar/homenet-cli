# Sudo and virtual environments

## Running with sudo (Debian/Ubuntu)

When doctor warns about privileges, MAC addresses and makers need a scan run with sudo. `sudo` resets `PATH`, so plain `sudo homenet` cannot find a venv's `homenet` and fails with "command not found". Look the program up in your own shell first, or use the absolute path doctor prints:

```bash
sudo "$(command -v homenet)" devices
```

The same form works for a pipx install. `doctor`, `whoami-net`, `explain`, `speed`, `wifi`, `dns`, and `uninstall` do not need sudo. A privileges warning still lets doctor exit 0. A missing required tool or no network route is a failure and exits 1. A missing `nmcli`, `iw`, or `resolvectl` is only a warning. On WSL 2's virtual network, doctor adds a `wsl` warning and still exits 0.

## See also

- [From a clone](install.md#from-a-clone)
- [Privileges](install.md#privileges)
- [Troubleshooting](troubleshooting.md#running-with-sudo-debianubuntu)
- [README](../README.md)
