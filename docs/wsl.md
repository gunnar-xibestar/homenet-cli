# WSL 2

## Install in the Ubuntu shell

Install homenet inside the Ubuntu (WSL) shell, not from Windows PowerShell or Command Prompt. The installer steps are in [Install](install.md#wsl-2).

In the default NAT mode, WSL only sees its virtual network, so scans won't find home devices. Mirrored networking mode helps. Add `networkingMode=mirrored` under `[wsl2]` in `%UserProfile%\.wslconfig`, then run `wsl --shutdown`. The block is below, and the same notes are in [Install](install.md#wsl-2).

If the installer runs sudo, the password prompt comes from sudo itself, not from homenet.

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

## See also

- [Install](install.md#wsl-2)
- [Troubleshooting](troubleshooting.md)
- [Quick start](quick-start.md)
- [Wi-Fi](wifi.md)
- [README](../README.md)
