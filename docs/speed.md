# Speed contacts Cloudflare

`homenet speed` estimates download speed. It opens 4 connections to **speed.cloudflare.com** and downloads for about 8 seconds:

`https://speed.cloudflare.com/__down?bytes=25000000`

The first second is warmup and is not part of the estimate. The number is an estimate, not a full speed test. Wi-Fi and other devices in your home can make it lower than your plan. Your computer must be able to reach that host.

```text
Download speed  about 215 Mbps (estimate)
Used 4 connections over about 8 seconds.
```

If a connection fails, one more line says how many reported an error, for example `2 connections reported an error.`

`--json` keeps `download_mbps`, `bytes`, `seconds`, and `url`, and adds `median_mbps`, `connections`, `warmup_s`, `errors`, and `total_bytes`.

## See also

- [See the real command](explain.md)
- [Progress](progress.md)
- [JSON output](json.md)
- [README](../README.md)
