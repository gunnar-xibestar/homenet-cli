# See the real command

`homenet --show-cmd devices` still runs the command. Before each underlying command runs, homenet prints it to stderr, shell-quoted, as you would type it:

```text
$ nmap -sn -T4 -oX - 192.168.1.0/24
```

The flag can sit before or after the command name: `homenet devices --show-cmd` is the same. Add `--json` and those `$` lines are left out. The JSON object gains a `commands` list instead. Each item has `argv`, `display`, `purpose`, and `kind` (`exec` or `http`). On failure the error object gains that same list.

`homenet explain devices` prints each command and a one-line purpose, and does not run them:

```text
$ nmap -sn -T4 -oX - 192.168.1.0/24
  find devices that are up (ping sweep)
```

`explain devices --network 192.168.1.0/24` uses that subnet and does not run `ip`. `explain router` also takes `--gateway 192.168.1.1`. The `router` command does not take `--gateway`. Without those options, explain looks up your home network and gateway the same way a real run does, which may run the `ip` command. It is not a scan. A bad `--network` gets the usual invalid-target error and fix hint. `explain` accepts `--json`. `device`, `baseline`, and `new-devices` use the same ping sweep as `devices`.

`explain wifi` lists the `nmcli` and `iw` reads, and `explain dns` lists `resolvectl status` when that tool is installed. Neither runs them. `wifi` and `dns` do not take `--network`. A live `homenet dns` may also run `ip` to learn the gateway so it can label your router. That is the same lookup as `whoami-net`.

`explain speed` lists one download per connection and does not run them. The default is 4:

```text
$ curl -sS --max-time 10 'https://speed.cloudflare.com/__down?bytes=25000000'
  download 25000000 bytes to estimate speed
```

That block is repeated once per connection. `homenet speed --show-cmd` still runs the test. Before each request it prints that same curl line on stderr. A connection is requested again until the 8 seconds are up, so the line can appear more than once.

## See also

- [Progress](progress.md)
- [Speed](speed.md)
- [JSON output](json.md)
- [Commands](commands.md)
- [README](../README.md)
