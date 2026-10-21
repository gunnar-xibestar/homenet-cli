# Troubleshooting

## Running with sudo (Debian/Ubuntu)

`sudo` resets `PATH`, so plain `sudo homenet` fails with `sudo: homenet: command not found` when that command lives in a virtualenv. sudo cannot find the venv's `homenet`. `doctor`, `whoami-net`, `explain`, `speed`, `wifi`, `dns`, and `uninstall` do not need sudo, and `sudo homenet doctor` fails the same way.

When you want MAC addresses and makers, look the program up in your own shell, before sudo starts. Doctor prints a line you can copy.

```bash
sudo "$(command -v homenet)" devices
```

`command -v` prints the absolute path, and the quotes hand that path to sudo. The same form works for a pipx install, and for `device`, `baseline`, and `new-devices`.

## WSL 2 shows a virtual network, not the home LAN

WSL 2 normally puts Linux on a private network inside `172.16.0.0/12`. `homenet whoami-net` and `homenet doctor` warn that this may be the WSL virtual network, not the home LAN. A real LAN in that range can look the same, including WSL in mirrored mode. The warning does not change the exit code.

To use the same network as Windows, add this to `%UserProfile%\.wslconfig` (that file is on the Windows side):

```ini
[wsl2]
networkingMode=mirrored
```

Then shut WSL down from Windows and open it again:

```bash
wsl --shutdown
```

Run `homenet whoami-net`. The address should now be on your home LAN, and the warning should be gone.

The same notes are on the [WSL 2](wsl.md) page.

## See also

- [Sudo and virtual environments](sudo.md#running-with-sudo-debianubuntu)
- [WSL 2](wsl.md)
- [README](../README.md)
