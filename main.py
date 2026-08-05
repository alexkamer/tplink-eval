from __future__ import annotations

import argparse
import getpass
import json
import os
import secrets
import sys
import time
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPCookieProcessor, Request, build_opener


ENV_FILE = Path(__file__).resolve().parent / ".env"
DEFAULT_DEVICE_MAP = Path(__file__).resolve().parent / "device-map.json"


class RouterError(RuntimeError):
    pass


def _safe_router_error(payload: Any) -> str:
    sensitive_keys = {"password", "username", "owneraccount", "cloudusername", "stok", "token"}

    def redact(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: "<redacted>" if key.lower() in sensitive_keys else redact(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [redact(item) for item in value]
        return value

    return json.dumps(redact(payload), separators=(",", ":"), sort_keys=True)


@dataclass(frozen=True)
class TrafficSample:
    device_type: str
    device_name: str
    mac: str
    ip: str
    upload_bytes_per_second: int
    download_bytes_per_second: int
    total_bytes: int


class TPLinkC4000:
    """Minimal client for the Archer C4000 v3 web API."""

    def __init__(
        self,
        base_url: str,
        password: str,
        *,
        username: str | None = None,
        timeout: float = 5.0,
        force_login: bool = False,
    ) -> None:
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Router URL must be an http(s) URL, such as http://192.168.1.1")
        if (
            parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("Router URL must contain only the scheme and host")

        self.base_url = base_url.rstrip("/")
        self.password = password
        self.username = username
        self.timeout = timeout
        self.force_login = force_login
        self.stok: str | None = None
        self.opener = build_opener(HTTPCookieProcessor(CookieJar()))

    def _post(self, path: str, form: dict[str, Any]) -> Any:
        body = urlencode(form, doseq=True).encode("ascii")
        request = Request(
            f"{self.base_url}{path}",
            data=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Origin": self.base_url,
                "Referer": f"{self.base_url}/webpages/login.html",
                "X-Requested-With": "XMLHttpRequest",
                "User-Agent": (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/151.0.0.0 Safari/537.36"
                ),
            },
            method="POST",
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                payload = json.load(response)
        except HTTPError as exc:
            raise RouterError(f"Router returned HTTP {exc.code}") from exc
        except URLError as exc:
            raise RouterError(f"Could not reach {self.base_url}: {exc.reason}") from exc
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RouterError("Router returned a non-JSON response") from exc

        if not payload.get("success"):
            error_data = payload.get("data")
            nested_error = error_data.get("errorcode") if isinstance(error_data, dict) else None
            error = payload.get("errorcode") or nested_error
            if error == "user conflict":
                raise RouterError(
                    "Another router-admin session is active. Log out of the web UI, "
                    "or rerun with --force-login to replace it."
                )
            if error:
                raise RouterError(str(error))
            raise RouterError(f"Router request failed: {_safe_router_error(payload)}")
        return payload.get("data")

    @staticmethod
    def _encrypt_password(password: str, modulus_hex: str, exponent_hex: str) -> str:
        modulus = int(modulus_hex, 16)
        exponent = int(exponent_hex, 16)
        block_size = (modulus.bit_length() + 7) // 8
        password_bytes = password.encode("utf-8")
        if len(password_bytes) > block_size - 11:
            raise RouterError("Password is too long for the router's RSA key")

        # The C4000 firmware uses PKCS#1 v1.5 type-2 encryption. Its browser
        # client creates a new, non-zero random padding string for every login.
        padding_length = block_size - len(password_bytes) - 3
        padding = bytearray()
        while len(padding) < padding_length:
            padding.extend(byte for byte in secrets.token_bytes(padding_length) if byte != 0)
        encoded = b"\x00\x02" + bytes(padding[:padding_length]) + b"\x00" + password_bytes
        message = int.from_bytes(encoded, "big")
        encrypted = pow(message, exponent, modulus)
        return f"{encrypted:0{block_size * 2}x}"

    def login(self) -> None:
        login_form = "cloud_login" if self.username else "login"
        login_path = f"/cgi-bin/luci/;stok=/login?form={login_form}"
        login_fields = self._post(login_path, {"operation": "read"})
        try:
            modulus, exponent = login_fields["password"]
        except (KeyError, TypeError, ValueError) as exc:
            raise RouterError("Router did not return its login encryption key") from exc

        form: dict[str, Any] = {
            "operation": "login",
            "password": self._encrypt_password(self.password, modulus, exponent),
        }
        if self.username:
            form["username"] = self.username
        if self.force_login:
            form["confirm"] = "true"

        result = self._post(login_path, form)
        try:
            self.stok = result["stok"]
        except (KeyError, TypeError) as exc:
            raise RouterError("Login succeeded but the router returned no session token") from exc

    def _admin_post(self, endpoint: str, form: dict[str, Any]) -> Any:
        if not self.stok:
            raise RouterError("Not logged in")
        return self._post(f"/cgi-bin/luci/;stok={self.stok}{endpoint}", form)

    def traffic(self) -> list[TrafficSample]:
        devices = self._admin_post("/admin/traffic?form=dev_name", {"operation": "read"})
        counters = self._admin_post("/admin/traffic?form=lists", {"operation": "load"})

        device_by_mac = {
            str(device.get("mac", "")).upper(): device
            for device in (devices or [])
            if device.get("mac")
        }
        samples: list[TrafficSample] = []
        for counter in counters or []:
            mac = str(counter.get("mac", "")).upper()
            device = device_by_mac.get(mac, {})
            samples.append(
                TrafficSample(
                    device_type=str(device.get("wire_type") or counter.get("device_type") or "--"),
                    device_name=str(
                        device.get("hostname")
                        or counter.get("device_name")
                        or counter.get("ip")
                        or "unknown"
                    ),
                    mac=mac,
                    ip=str(counter.get("ip") or device.get("ip") or ""),
                    upload_bytes_per_second=_as_int(counter.get("retx_byte")),
                    download_bytes_per_second=_as_int(counter.get("rerx_byte")),
                    total_bytes=_as_int(counter.get("total_byte")),
                )
            )
        return sorted(
            samples,
            key=lambda sample: sample.upload_bytes_per_second + sample.download_bytes_per_second,
            reverse=True,
        )

    def logout(self) -> None:
        if not self.stok:
            return
        try:
            self._admin_post("/admin/system?form=logout", {"operation": "write"})
        finally:
            self.stok = None


def _as_int(value: Any) -> int:
    try:
        return int(float(value or 0))
    except (TypeError, ValueError):
        return 0


def _human_bytes(value: int, *, rate: bool = False) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    number = float(value)
    unit = units[0]
    for unit in units:
        if abs(number) < 1024 or unit == units[-1]:
            break
        number /= 1024
    suffix = "/s" if rate else ""
    return f"{number:.1f} {unit}{suffix}"


def _print_table(samples: list[TrafficSample], captured_at: str) -> None:
    print(f"Captured {captured_at}")
    print(f"{'TYPE':<7} {'DEVICE':<25} {'IP':<15} {'DOWN':>12} {'UP':>12} {'TOTAL':>12}")
    for sample in samples:
        print(
            f"{sample.device_type[:7]:<7} "
            f"{sample.device_name[:25]:<25} "
            f"{sample.ip[:15]:<15} "
            f"{_human_bytes(sample.download_bytes_per_second, rate=True):>12} "
            f"{_human_bytes(sample.upload_bytes_per_second, rate=True):>12} "
            f"{_human_bytes(sample.total_bytes):>12}"
        )


def _sample_document(samples: list[TrafficSample]) -> dict[str, Any]:
    return {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "devices": [asdict(sample) for sample in samples],
    }


def _normalize_mac(value: str) -> str:
    return "".join(character for character in value.upper() if character.isalnum())


def _load_device_map(path: Path) -> dict[str, str]:
    if not path.is_absolute():
        path = Path(__file__).resolve().parent / path
    if not path.is_file():
        return {}

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in device map {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"Device map {path} must be a JSON object of MAC addresses to names")

    device_map: dict[str, str] = {}
    for mac, name in data.items():
        if not isinstance(mac, str) or not isinstance(name, str) or not name.strip():
            raise ValueError(f"Device map {path} must contain only non-empty string names")
        normalized_mac = _normalize_mac(mac)
        if len(normalized_mac) != 12:
            raise ValueError(f"Invalid MAC address in device map {path}: {mac}")
        device_map[normalized_mac] = name.strip()
    return device_map


def _apply_device_map(
    samples: list[TrafficSample], device_map: dict[str, str]
) -> list[TrafficSample]:
    return [
        replace(sample, device_name=device_map.get(_normalize_mac(sample.mac), sample.device_name))
        for sample in samples
    ]


def _load_dotenv(path: Path = ENV_FILE) -> None:
    """Load simple KEY=VALUE entries without overriding the process environment."""
    if not path.is_file():
        return

    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise ValueError(f"Invalid .env entry on line {line_number}: expected KEY=VALUE")

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or not key.replace("_", "a").isalnum() or key[0].isdigit():
            raise ValueError(f"Invalid .env variable name on line {line_number}")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ.setdefault(key, value)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read per-device traffic from a TP-Link Archer C4000")
    parser.add_argument(
        "--router",
        default=os.environ.get("TPLINK_ROUTER", "http://192.168.1.1"),
        help="router base URL (default: %(default)s; env: TPLINK_ROUTER)",
    )
    parser.add_argument(
        "--username",
        default=os.environ.get("TPLINK_USERNAME"),
        help="optional local/cloud username (env: TPLINK_USERNAME)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=os.environ.get("TPLINK_INTERVAL", "0"),
        help="poll every N seconds; zero collects once (env: TPLINK_INTERVAL)",
    )
    parser.add_argument(
        "--device-map",
        type=Path,
        default=Path(os.environ.get("TPLINK_DEVICE_MAP", str(DEFAULT_DEVICE_MAP))),
        help="JSON file mapping MAC addresses to display names (env: TPLINK_DEVICE_MAP)",
    )
    parser.add_argument("--json", action="store_true", help="print each sample as JSON")
    parser.add_argument("--output", type=Path, help="append samples as JSON Lines to this file")
    parser.add_argument(
        "--force-login",
        action="store_true",
        help="replace another active router-admin session",
    )
    parser.add_argument("--timeout", type=float, default=5.0, help="request timeout in seconds")
    return parser.parse_args()


def main() -> int:
    router: TPLinkC4000 | None = None
    try:
        _load_dotenv()
        args = parse_args()
        if args.interval < 0:
            print("--interval cannot be negative", file=sys.stderr)
            return 2
        device_map = _load_device_map(args.device_map)

        password = os.environ.get("TPLINK_PASSWORD")
        if not password:
            password = getpass.getpass("Router password: ")

        router = TPLinkC4000(
            args.router,
            password,
            username=args.username,
            timeout=args.timeout,
            force_login=args.force_login,
        )
        router.login()
        while True:
            samples = _apply_device_map(router.traffic(), device_map)
            document = _sample_document(samples)
            line = json.dumps(document, separators=(",", ":"))
            if args.json:
                print(line, flush=True)
            else:
                _print_table(samples, document["captured_at"])

            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                with args.output.open("a", encoding="utf-8") as output:
                    output.write(line + "\n")

            if args.interval == 0:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 130
    except (RouterError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        if router is not None:
            try:
                router.logout()
            except RouterError:
                pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
