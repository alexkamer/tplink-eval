# TP-Link Archer C4000 traffic collector

Reads the same per-device counters shown by **Advanced → System Tools → Traffic Monitor** on an Archer C4000 v3.

The client uses the router's local web API and Python's standard library. It does not require installing packages.

Edit the local `.env` file before running:

```dotenv
TPLINK_ROUTER=http://router.local
TPLINK_USERNAME=
TPLINK_PASSWORD=replace-with-router-password
TPLINK_INTERVAL=10
TPLINK_DEVICE_MAP=device-map.json
```

`.env` is ignored by Git. Existing process environment variables override values from the file, and command-line options override both.

Set `TPLINK_USERNAME` to the email address used by the router's TP-Link cloud login. Leave it blank if the web interface asks only for a local router password. The script selects the corresponding login endpoint automatically.

## Run once

```sh
uv run python main.py
```

JSON output:

```sh
uv run python main.py --json
```

## Monitor and retain history

The interval defaults to `TPLINK_INTERVAL` from `.env`. Append one JSON document per sample:

```sh
uv run python main.py --output traffic.jsonl
```

You can override the interval for one invocation:

```sh
uv run python main.py --interval 10 --output traffic.jsonl
```

If `TPLINK_PASSWORD` is blank or missing, the script prompts for it without echoing.

## Friendly device names

Add aliases to `device-map.json`, using each device's MAC address as the key:

```json
{
  "<DEVICE-MAC-1>": "My laptop",
  "<DEVICE-MAC-2>": "Media server"
}
```

Replace the placeholder keys with MAC addresses from your own router. MAC addresses are case-insensitive and may use hyphens or colons. A mapped name replaces the router-provided name in table and JSON output. Devices without a mapping retain their original names. Use `uv run python main.py --json` to find MAC addresses.

`device-map.json` is ignored by Git because friendly names may contain private information. Use `--device-map another-file.json` to select a different file.

## Router session behavior

This TP-Link firmware normally permits only one router-admin session. The collector logs out when it exits. If a browser session is active, log out there first. `--force-login` can replace that session explicitly.

The returned fields are:

- `upload_bytes_per_second`: router field `retx_byte`
- `download_bytes_per_second`: router field `rerx_byte`
- `total_bytes`: cumulative traffic since the Traffic Monitor counters were last reset
- device name, connection type, IP address, and MAC address

Keep the collector on the LAN. Do not expose the router administration interface or this API to the Internet.
