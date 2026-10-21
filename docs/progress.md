# Progress

In a terminal, homenet shows a status line on stderr while a scan, sweep, HTTP check, Wi-Fi read, or DNS check runs, such as `Scanning 192.168.1.0/24… (12s)`, `Reading Wi-Fi…`, or `Checking DNS…`, and clears it when the step finishes. `--json`, and a run whose stderr is not a terminal, leave that line out so stdout stays intact.

`homenet speed` uses its own line, and there is no flag to turn it off. In a terminal it updates in place, for example `Testing download speed... 3s of 8s, about 212 Mbps so far`. During warmup, while the rate is still zero, that line says `warming up`. The line is cleared before the result or an error is printed. When stderr is not a terminal, each update is a plain line and the carriage return is left out. `--json` prints no progress line on stdout or stderr.

`-v` prints each step on stderr, such as `Parsed 7 hosts`, `Resolving names…`, `Reading Wi-Fi link of wlan0 (iw)`, or `Looking up example.com`. `-vv` also shows nmap's progress every 5 seconds. The flag can go before or after the command. Wi-Fi and DNS do not print nmap progress.

## See also

- [See the real command](explain.md)
- [Speed](speed.md)
- [README](../README.md)
