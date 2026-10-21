# Exit codes

Exit `0` means the command succeeded. Exit `1` means it failed. `doctor` exits `1` only when a check fails at error level. Warnings still exit `0`, including a missing `nmcli`, `iw`, or `resolvectl`. `wifi` and `dns` exit `0`, including when Wi-Fi is not available, inside WSL, and when the lookup fails. `new-devices` exits `0` when nothing changed, `1` when a device is new, missing, changed, or has a different MAC address, and `2` when the command itself fails. `uninstall` exits `0` when it removes homenet or when the answer is no, and `1` when it refuses or the uninstall fails. A usage mistake, such as leaving off the IP address, exits `2`.

## See also

- [JSON output](json.md)
- [Uninstall](uninstall.md)
- [Commands](commands.md)
- [README](../README.md)
