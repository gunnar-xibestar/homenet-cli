# Wi-Fi

## `homenet wifi`

Prints the Wi-Fi name, the interface, and the signal as words plus a number, such as `Good (-55 dBm)`. Excellent is -50 dBm or stronger, Good is -60 or stronger, Fair is -70 or stronger, and anything weaker is Weak. When the radio reading is only a percent, that percent is used instead. When neither is available, the signal line says `unknown (install iw to see signal)`. One more line explains the band and channel: 2.4 GHz reaches farther, and 5 GHz is faster but has a shorter range. Link speed is shown when `iw` reports it.

Inside WSL the command prints `Wi-Fi info isn't visible inside WSL` and exits 0. If this computer has no Wi-Fi, is not connected, or does not have `nmcli` or `iw`, it prints a short reason and still exits 0. `wifi` does not need sudo.

```text
Your Wi-Fi

Network     Home
Interface   wlan0
Signal      Good (-55 dBm)
Channel     36 (5 GHz)
Link speed  866.7 Mb/s

Channel 36 is on 5 GHz. 5 GHz is faster but has a shorter range, and 2.4 GHz reaches farther.
```

On WSL:

```text
Your Wi-Fi

Wi-Fi info isn't visible inside WSL
```

## See also

- [WSL 2](wsl.md)
- [See the real command](explain.md)
- [Commands](commands.md)
- [README](../README.md)
