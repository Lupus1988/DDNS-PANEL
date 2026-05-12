from __future__ import annotations

import base64
import ipaddress
import json
import os
import secrets
import shutil
import socket
import subprocess
import tempfile
import urllib.parse
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any


APP_DIR = Path(os.environ.get("DDNS_PANEL_APP_DIR", "/opt/ddns-panel"))
CONFIG_DIR = APP_DIR / "config"
AUTH_FILE = APP_DIR / "auth.json"
SECRET_FILE = APP_DIR / "secret.key"
AUDIT_LOG_FILE = APP_DIR / "audit.log"
IP_BLOCK_FILE = APP_DIR / "ip-block.json"
ENTRIES_FILE = CONFIG_DIR / "entries.json"
SETUP_FILE = CONFIG_DIR / "setup.json"

ETC_DIR = Path("/etc/ddns-panel")
SECRETS_FILE = ETC_DIR / "secrets.json"

STATE_DIR = Path("/var/lib/ddns-panel")
STATUS_FILE = STATE_DIR / "status.json"

AVAHI_HOSTS_FILE = Path("/etc/avahi/hosts")
LOCAL_HOSTS_FILE = Path("/etc/hosts")
NPM_PROXY_DIR = Path("/mnt/ncdata/docker/npm/data/nginx/proxy_host")
NPM_PROXY_FILE = NPM_PROXY_DIR / "999-ddns-local.conf"

SYSTEMD_TIMER_FILE = Path("/etc/systemd/system/ddns-panel-update.timer")
UPDATE_SCRIPT = APP_DIR / "ddns-panel-update.py"

PANEL_PORT = 5085
SESSION_TIMEOUT_MINUTES = 20
RESET_PIN_MAX_ATTEMPTS = 5
RESET_PIN_LOCK_SECONDS = 900
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCK_SECONDS = 600


DEFAULT_SETUP = {
    "interval_minutes": 5,
    "boot_delay_seconds": 120,
    "request_timeout_seconds": 5,
    "retry_count": 2,
    "retry_delay_seconds": 3,
    "only_update_on_change": True,
    "log_lines": 40,
    "ipv4_sources": [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://ipv4.icanhazip.com",
    ],
    "ipv6_sources": [
        "https://api6.ipify.org",
        "https://ipv6.icanhazip.com",
    ],
    "mdns_enabled": True,
    "mdns_hostname": "ddns-panel.local",
    "local_proxy_enabled": True,
    "panel_port": PANEL_PORT,
}


PROVIDER_DEFAULT_IP_MODES = {
    "dynu": "dual",
    "duckdns": "dual",
    "noip": "ipv4",
    "freedns": "ipv4",
    "dynv6": "dual",
    "desec": "dual",
    "he": "dual",
    "cloudns": "ipv4",
    "ydns": "ipv4",
    "ddnss": "dual",
    "cloudflare": "dual",
}


PROVIDER_SUPPORTED_IP_MODES = {
    "dynu": {"ipv4", "ipv6", "dual"},
    "duckdns": {"ipv4", "ipv6", "dual"},
    "noip": {"ipv4", "ipv6"},
    "freedns": {"ipv4", "ipv6"},
    "dynv6": {"ipv4", "ipv6", "dual"},
    "desec": {"ipv4", "ipv6", "dual"},
    "he": {"ipv4", "ipv6", "dual"},
    "cloudns": {"ipv4", "ipv6"},
    "ydns": {"ipv4", "ipv6"},
    "ddnss": {"ipv4", "ipv6", "dual"},
    "cloudflare": {"ipv4", "ipv6", "dual"},
}


def now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def load_or_create_secret_key() -> str:
    if SECRET_FILE.exists():
        return SECRET_FILE.read_text(encoding="utf-8").strip()
    SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
    value = secrets.token_hex(32)
    SECRET_FILE.write_text(value, encoding="utf-8")
    try:
        SECRET_FILE.chmod(0o600)
    except Exception:
        pass
    return value


def write_audit_log(message: str) -> None:
    AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT_LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(f"{now_iso()} {message}\n")
    try:
        AUDIT_LOG_FILE.chmod(0o600)
    except Exception:
        pass


def normalize_setup(data: dict[str, Any] | None) -> dict[str, Any]:
    data = data or {}
    merged = dict(DEFAULT_SETUP)
    merged.update({key: value for key, value in data.items() if key in merged})
    merged["interval_minutes"] = max(1, int(merged.get("interval_minutes", 5) or 5))
    merged["boot_delay_seconds"] = max(5, int(merged.get("boot_delay_seconds", 120) or 120))
    merged["request_timeout_seconds"] = max(2, int(merged.get("request_timeout_seconds", 5) or 5))
    merged["retry_count"] = max(0, int(merged.get("retry_count", 2) or 2))
    merged["retry_delay_seconds"] = max(1, int(merged.get("retry_delay_seconds", 3) or 3))
    merged["log_lines"] = max(10, int(merged.get("log_lines", 40) or 40))
    merged["only_update_on_change"] = bool(merged.get("only_update_on_change", True))
    merged["mdns_enabled"] = bool(merged.get("mdns_enabled", True))
    merged["local_proxy_enabled"] = bool(merged.get("local_proxy_enabled", True))
    hostname = str(merged.get("mdns_hostname", "ddns.local")).strip().lower() or "ddns.local"
    if not hostname.endswith(".local"):
        hostname += ".local"
    merged["mdns_hostname"] = hostname
    merged["panel_port"] = PANEL_PORT
    for key in ("ipv4_sources", "ipv6_sources"):
        sources = merged.get(key, [])
        if isinstance(sources, str):
            sources = [item.strip() for item in sources.splitlines() if item.strip()]
        merged[key] = [str(item).strip() for item in sources if str(item).strip()] or list(DEFAULT_SETUP[key])
    return merged


def load_setup() -> dict[str, Any]:
    return normalize_setup(load_json(SETUP_FILE, DEFAULT_SETUP))


def save_setup(data: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_setup(data)
    save_json(SETUP_FILE, normalized)
    return normalized


def normalize_entries(data: dict[str, Any] | None) -> dict[str, list[dict[str, Any]]]:
    items = []
    for raw in (data or {}).get("entries", []):
        if not isinstance(raw, dict):
            continue
        entry_id = str(raw.get("id", "")).strip() or secrets.token_hex(8)
        provider = str(raw.get("provider", "dynu")).strip().lower() or "dynu"
        default_ip_mode = PROVIDER_DEFAULT_IP_MODES.get(provider, "ipv4")
        supported_ip_modes = PROVIDER_SUPPORTED_IP_MODES.get(provider, {"ipv4"})
        ip_mode = str(raw.get("ip_mode", default_ip_mode)).strip().lower() or default_ip_mode
        if ip_mode not in supported_ip_modes:
            ip_mode = default_ip_mode
        hostname = str(raw.get("hostname", "")).strip().lower()
        name = str(raw.get("name", "")).strip() or hostname or "DDNS-Eintrag"
        items.append(
            {
                "id": entry_id,
                "name": name,
                "enabled": bool(raw.get("enabled", True)),
                "provider": provider,
                "ip_mode": ip_mode,
                "hostname": hostname,
                "created_at": str(raw.get("created_at", now_iso())),
                "updated_at": str(raw.get("updated_at", now_iso())),
            }
        )
    items.sort(key=lambda item: item["name"].lower())
    return {"entries": items}


def load_entries() -> dict[str, list[dict[str, Any]]]:
    return normalize_entries(load_json(ENTRIES_FILE, {"entries": []}))


def save_entries(data: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_entries(data)
    save_json(ENTRIES_FILE, normalized)
    return normalized


def load_secrets() -> dict[str, dict[str, str]]:
    data = load_json(SECRETS_FILE, {})
    if not isinstance(data, dict):
        return {}
    cleaned = {}
    for key, value in data.items():
        if not isinstance(value, dict):
            continue
        cleaned[str(key)] = {
            "username": str(value.get("username", "")).strip(),
            "password": str(value.get("password", "")),
        }
    return cleaned


def save_secrets(data: dict[str, dict[str, str]]) -> None:
    save_json(SECRETS_FILE, data)
    try:
        SECRETS_FILE.chmod(0o600)
    except Exception:
        pass


def get_entry_secret(entry_id: str) -> dict[str, str]:
    return load_secrets().get(entry_id, {"username": "", "password": ""})


def set_entry_secret(entry_id: str, username: str, password: str | None = None) -> None:
    secrets_map = load_secrets()
    current = secrets_map.get(entry_id, {"username": "", "password": ""})
    current["username"] = username.strip()
    if password is not None:
        current["password"] = password
    secrets_map[entry_id] = current
    save_secrets(secrets_map)


def delete_entry_secret(entry_id: str) -> None:
    secrets_map = load_secrets()
    if entry_id in secrets_map:
        del secrets_map[entry_id]
        save_secrets(secrets_map)


def load_status() -> dict[str, Any]:
    data = load_json(
        STATUS_FILE,
        {
            "current_public_ip": "",
            "current_public_ipv4": "",
            "current_public_ipv6": "",
            "last_check_at": "",
            "last_change_at": "",
            "last_run_summary": "",
            "entries": {},
        },
    )
    if not isinstance(data, dict):
        data = {}
    data.setdefault("current_public_ip", "")
    data.setdefault("current_public_ipv4", data.get("current_public_ip", ""))
    data.setdefault("current_public_ipv6", "")
    data.setdefault("last_check_at", "")
    data.setdefault("last_change_at", "")
    data.setdefault("last_run_summary", "")
    data.setdefault("entries", {})
    if not isinstance(data["entries"], dict):
        data["entries"] = {}
    return data


def save_status(data: dict[str, Any]) -> None:
    save_json(STATUS_FILE, data)


def find_entry(entry_id: str) -> dict[str, Any] | None:
    for entry in load_entries()["entries"]:
        if entry["id"] == entry_id:
            return entry
    return None


def ensure_runtime_layout() -> None:
    for path in (APP_DIR, CONFIG_DIR, ETC_DIR, STATE_DIR):
        path.mkdir(parents=True, exist_ok=True)
    if not ENTRIES_FILE.exists():
        save_entries({"entries": []})
    if not SETUP_FILE.exists():
        save_setup(DEFAULT_SETUP)
    if not STATUS_FILE.exists():
        save_status(load_status())
    if not SECRETS_FILE.exists():
        save_secrets({})


def run_cmd(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, check=check)


def get_primary_lan_ip() -> str:
    candidates = []
    try:
        result = subprocess.run(
            ["ip", "-4", "route", "get", "1.1.1.1"],
            text=True,
            capture_output=True,
            check=True,
        )
        parts = result.stdout.split()
        if "src" in parts:
            value = parts[parts.index("src") + 1]
            candidates.append(value)
    except Exception:
        pass

    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM):
            value = info[4][0]
            candidates.append(value)
    except Exception:
        pass

    for value in candidates:
        try:
            ip = ipaddress.ip_address(value)
            if ip.is_loopback:
                continue
            return str(ip)
        except Exception:
            continue
    return "127.0.0.1"


def sync_avahi_host(setup: dict[str, Any] | None = None) -> None:
    setup = normalize_setup(setup or load_setup())
    if not AVAHI_HOSTS_FILE.exists():
        return

    marker = "# ddns-panel managed"
    lines = []
    try:
        lines = AVAHI_HOSTS_FILE.read_text(encoding="utf-8").splitlines()
    except Exception:
        return

    filtered = [line for line in lines if marker not in line]
    if setup["mdns_enabled"]:
        filtered.append(f"{get_primary_lan_ip()} {setup['mdns_hostname']} {marker}")

    content = "\n".join(filtered).rstrip() + "\n"
    AVAHI_HOSTS_FILE.write_text(content, encoding="utf-8")
    try:
        subprocess.run(["systemctl", "restart", "avahi-daemon"], check=False)
    except Exception:
        pass


def sync_local_hosts(setup: dict[str, Any] | None = None) -> None:
    setup = normalize_setup(setup or load_setup())
    marker = "# ddns-panel managed"
    try:
        lines = LOCAL_HOSTS_FILE.read_text(encoding="utf-8").splitlines()
    except Exception:
        return

    filtered = [line for line in lines if marker not in line]
    filtered.append(f"{get_primary_lan_ip()} {setup['mdns_hostname']} {marker}")
    LOCAL_HOSTS_FILE.write_text("\n".join(filtered).rstrip() + "\n", encoding="utf-8")


def npm_container_exists() -> bool:
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            text=True,
            capture_output=True,
            check=True,
        )
        return "npm" in result.stdout.splitlines()
    except Exception:
        return False


def render_local_proxy_conf(hostname: str) -> str:
    target_ip = get_primary_lan_ip()
    return f"""# ------------------------------------------------------------
# {hostname}
# ------------------------------------------------------------

server {{
  listen 80;
  listen [::]:80;
  server_name {hostname};

  access_log /data/logs/ddns-local_access.log proxy;
  error_log /data/logs/ddns-local_error.log warn;

  location / {{
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_http_version 1.1;
    proxy_pass http://{target_ip}:{PANEL_PORT};
  }}
}}
"""


def sync_local_proxy(setup: dict[str, Any] | None = None) -> None:
    setup = normalize_setup(setup or load_setup())
    if not NPM_PROXY_DIR.exists():
        return

    if setup["local_proxy_enabled"]:
        NPM_PROXY_DIR.mkdir(parents=True, exist_ok=True)
        NPM_PROXY_FILE.write_text(render_local_proxy_conf(setup["mdns_hostname"]), encoding="utf-8")
    elif NPM_PROXY_FILE.exists():
        NPM_PROXY_FILE.unlink()

    if npm_container_exists():
        subprocess.run(["docker", "restart", "npm"], check=False)


def render_timer_unit(setup: dict[str, Any] | None = None) -> str:
    setup = normalize_setup(setup or load_setup())
    return f"""[Unit]
Description=DDNS Panel Update Timer

[Timer]
OnBootSec={setup['boot_delay_seconds']}s
OnUnitActiveSec={setup['interval_minutes']}min
Unit=ddns-panel-update.service
Persistent=true

[Install]
WantedBy=timers.target
"""


def sync_timer_unit(setup: dict[str, Any] | None = None) -> None:
    content = render_timer_unit(setup)
    SYSTEMD_TIMER_FILE.write_text(content, encoding="utf-8")
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    subprocess.run(["systemctl", "enable", "--now", "ddns-panel-update.timer"], check=False)


def sync_local_access(setup: dict[str, Any] | None = None) -> None:
    setup = normalize_setup(setup or load_setup())
    sync_local_hosts(setup)
    sync_avahi_host(setup)
    sync_local_proxy(setup)


def build_update_command(force: bool = False, entry_id: str = "") -> list[str]:
    cmd = [str(APP_DIR / "venv" / "bin" / "python"), str(UPDATE_SCRIPT), "--once"]
    if force:
        cmd.append("--force")
    if entry_id:
        cmd.extend(["--entry-id", entry_id])
    return cmd


def run_panel_update(force: bool = False, entry_id: str = "") -> tuple[bool, str]:
    try:
        result = subprocess.run(
            build_update_command(force=force, entry_id=entry_id),
            text=True,
            capture_output=True,
            check=True,
        )
        output = (result.stdout or "").strip()
        return True, output or "Update erfolgreich."
    except subprocess.CalledProcessError as exc:
        text = "\n".join(part for part in [(exc.stdout or "").strip(), (exc.stderr or "").strip()] if part)
        return False, text or "Update fehlgeschlagen."


def request_public_ip(sources: list[str], timeout_seconds: int) -> tuple[str, str]:
    for source in sources:
        req = urllib.request.Request(source, headers={"User-Agent": "ddns-panel/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
                value = response.read().decode("utf-8").strip()
            ipaddress.ip_address(value)
            return value, source
        except (urllib.error.URLError, ValueError, TimeoutError):
            continue
        except Exception:
            continue
    raise RuntimeError("Keine öffentliche IP ermittelbar.")


def request_public_ip_version(sources: list[str], timeout_seconds: int, version: int) -> tuple[str, str]:
    for source in sources:
        req = urllib.request.Request(source, headers={"User-Agent": "ddns-panel/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
                value = response.read().decode("utf-8").strip()
            ip = ipaddress.ip_address(value)
            if ip.version != version:
                continue
            return value, source
        except (urllib.error.URLError, ValueError, TimeoutError):
            continue
        except Exception:
            continue
    raise RuntimeError(f"Keine öffentliche IPv{version}-Adresse ermittelbar.")


def dynu_update(hostname: str, username: str, password: str, ipv4: str, ipv6: str, timeout_seconds: int) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    params = {"hostname": hostname}
    if ipv4:
        params["myip"] = ipv4
    elif ipv6:
        params["myip"] = "no"
    if ipv6:
        params["myipv6"] = ipv6
    elif ipv4:
        params["myipv6"] = "no"
    req = urllib.request.Request(
        f"https://api.dynu.com/nic/update?{urllib.parse.urlencode(params)}",
        headers={
            "Authorization": f"Basic {token}",
            "User-Agent": "ddns-panel/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
        return response.read().decode("utf-8").strip()


def normalize_duckdns_domain(hostname: str) -> str:
    domain = hostname.strip().lower()
    if domain.endswith(".duckdns.org"):
        domain = domain[: -len(".duckdns.org")]
    return domain.strip(".")


def duckdns_update(hostname: str, token: str, ipv4: str, ipv6: str, timeout_seconds: int) -> str:
    domain = normalize_duckdns_domain(hostname)
    if not domain:
        raise ValueError("DuckDNS-Subdomain fehlt.")
    params_map = {"domains": domain, "token": token, "verbose": "true"}
    if ipv4:
        params_map["ip"] = ipv4
    elif ipv6:
        params_map["ip"] = ""
    if ipv6:
        params_map["ipv6"] = ipv6
    params = urllib.parse.urlencode(params_map)
    req = urllib.request.Request(
        f"https://www.duckdns.org/update?{params}",
        headers={"User-Agent": "ddns-panel/1.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
        body = response.read().decode("utf-8").strip()
    if not body.startswith("OK"):
        raise RuntimeError(body or "DuckDNS-Update fehlgeschlagen.")
    return body


def noip_update(hostname: str, username: str, password: str, ip_value: str, timeout_seconds: int) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    params = urllib.parse.urlencode({"hostname": hostname, "myip": ip_value})
    req = urllib.request.Request(
        f"https://dynupdate.no-ip.com/nic/update?{params}",
        headers={
            "Authorization": f"Basic {token}",
            "User-Agent": "ddns-panel/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
        body = response.read().decode("utf-8").strip()
    if not body:
        raise RuntimeError("No-IP-Update lieferte keine Antwort.")
    return body


def freedns_update(hostname: str, token_or_url: str, ip_mode: str, timeout_seconds: int) -> str:
    value = token_or_url.strip()
    if not value:
        raise ValueError("FreeDNS-Token fehlt.")
    if value.startswith(("http://", "https://")):
        update_url = value
    else:
        base = "https://v6.sync.afraid.org/u/" if ip_mode == "ipv6" else "https://sync.afraid.org/u/"
        update_url = f"{base}{value.strip('/')}/"
    req = urllib.request.Request(update_url, headers={"User-Agent": "ddns-panel/1.0"})
    with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
        body = response.read().decode("utf-8").strip()
    if not body:
        raise RuntimeError("FreeDNS-Update lieferte keine Antwort.")
    return body


def dynv6_update(hostname: str, token: str, ipv4: str, ipv6: str, timeout_seconds: int) -> str:
    params_map = {"zone": hostname, "token": token}
    if ipv4:
        params_map["ipv4"] = ipv4
    if ipv6:
        params_map["ipv6"] = ipv6
    params = urllib.parse.urlencode(params_map)
    req = urllib.request.Request(f"https://dynv6.com/api/update?{params}", headers={"User-Agent": "ddns-panel/1.0"})
    with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
        body = response.read().decode("utf-8").strip()
    if not body:
        raise RuntimeError("dynv6-Update lieferte keine Antwort.")
    return body


def desec_update(hostname: str, token: str, ipv4: str, ipv6: str, timeout_seconds: int) -> str:
    params_map = {"hostname": hostname}
    params_map["myipv4"] = ipv4 if ipv4 else ""
    params_map["myipv6"] = ipv6 if ipv6 else "preserve"
    params = urllib.parse.urlencode(params_map)
    req = urllib.request.Request(
        f"https://update.dedyn.io/?{params}",
        headers={"User-Agent": "ddns-panel/1.0", "Authorization": f"Token {token}"},
    )
    with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
        body = response.read().decode("utf-8").strip()
    if not body:
        raise RuntimeError("deSEC-Update lieferte keine Antwort.")
    return body


def he_update(hostname: str, password: str, ipv4: str, ipv6: str, timeout_seconds: int) -> str:
    responses = []
    for ip_value in [ipv4, ipv6]:
        if not ip_value:
            continue
        params = urllib.parse.urlencode({"hostname": hostname, "password": password, "myip": ip_value})
        req = urllib.request.Request(
            f"https://dyn.dns.he.net/nic/update?{params}",
            headers={"User-Agent": "ddns-panel/1.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
            body = response.read().decode("utf-8").strip()
        if not body:
            raise RuntimeError("Hurricane-Electric-Update lieferte keine Antwort.")
        responses.append(body)
    return " | ".join(responses)


def cloudns_update(hostname: str, token_or_url: str, ip_mode: str, timeout_seconds: int) -> str:
    value = token_or_url.strip()
    if not value:
        raise ValueError("ClouDNS Dynamic URL fehlt.")
    if value.startswith(("http://", "https://")):
        update_url = value
    else:
        base = "https://ipv6.cloudns.net/api/dynamicURL/?q=" if ip_mode == "ipv6" else "https://ipv4.cloudns.net/api/dynamicURL/?q="
        update_url = f"{base}{urllib.parse.quote(value, safe='')}"
    req = urllib.request.Request(update_url, headers={"User-Agent": "ddns-panel/1.0"})
    with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
        body = response.read().decode("utf-8").strip()
    if not body:
        raise RuntimeError("ClouDNS-Update lieferte keine Antwort.")
    return body


def ydns_update(hostname: str, username: str, password: str, ip_value: str, timeout_seconds: int) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    params = urllib.parse.urlencode({"host": hostname, "ip": ip_value})
    req = urllib.request.Request(
        f"https://ydns.io/api/v1/update/?{params}",
        headers={"Authorization": f"Basic {token}", "User-Agent": "ddns-panel/1.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
        body = response.read().decode("utf-8").strip()
    if not body:
        raise RuntimeError("YDNS-Update lieferte keine Antwort.")
    return body


def ddnss_update(hostname: str, username: str, password: str, ipv4: str, ipv6: str, timeout_seconds: int) -> str:
    params_map = {"user": username, "pwd": password, "host": hostname}
    if ipv4:
        params_map["ip"] = ipv4
    if ipv6:
        params_map["ip6"] = ipv6
    params = urllib.parse.urlencode(params_map)
    req = urllib.request.Request(
        f"https://www.ddnss.de/upd.php?{params}",
        headers={"User-Agent": "ddns-panel/1.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
        body = response.read().decode("utf-8").strip()
    if not body:
        raise RuntimeError("ddnss.de-Update lieferte keine Antwort.")
    return body


def cloudflare_api_request(
    method: str,
    path: str,
    api_token: str,
    timeout_seconds: int,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body = None
    headers = {
        "Authorization": f"Bearer {api_token}",
        "User-Agent": "ddns-panel/1.0",
        "Accept": "application/json",
    }
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4{path}",
        data=body,
        method=method,
        headers=headers,
    )
    with urllib.request.urlopen(req, timeout=timeout_seconds) as response:
        data = json.loads(response.read().decode("utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError("Cloudflare-Antwort ungültig.")
    if not data.get("success", False):
        errors = data.get("errors") or []
        if errors and isinstance(errors, list):
            first = errors[0]
            if isinstance(first, dict) and first.get("message"):
                raise RuntimeError(str(first["message"]))
        raise RuntimeError("Cloudflare-API-Fehler.")
    return data


def cloudflare_upsert_record(hostname: str, zone_id: str, api_token: str, record_type: str, content: str, timeout_seconds: int) -> str:
    encoded_name = urllib.parse.quote(hostname, safe="")
    list_data = cloudflare_api_request(
        "GET",
        f"/zones/{zone_id}/dns_records?type={record_type}&name={encoded_name}",
        api_token,
        timeout_seconds,
    )
    records = list_data.get("result") or []
    if records:
        record = records[0]
        record_id = str(record.get("id", "")).strip()
        if not record_id:
            raise RuntimeError("Cloudflare-Record-ID fehlt.")
        payload = {
            "type": record_type,
            "name": hostname,
            "content": content,
            "ttl": int(record.get("ttl", 120) or 120),
            "proxied": bool(record.get("proxied", False)),
        }
        cloudflare_api_request(
            "PATCH",
            f"/zones/{zone_id}/dns_records/{record_id}",
            api_token,
            timeout_seconds,
            payload=payload,
        )
        return f"updated {record_type} {hostname} -> {content}"
    cloudflare_api_request(
        "POST",
        f"/zones/{zone_id}/dns_records",
        api_token,
        timeout_seconds,
        payload={
            "type": record_type,
            "name": hostname,
            "content": content,
            "ttl": 120,
            "proxied": False,
        },
    )
    return f"created {record_type} {hostname} -> {content}"


def cloudflare_update(hostname: str, zone_id: str, api_token: str, ipv4: str, ipv6: str, timeout_seconds: int) -> str:
    responses = []
    if ipv4:
        responses.append(cloudflare_upsert_record(hostname, zone_id, api_token, "A", ipv4, timeout_seconds))
    if ipv6:
        responses.append(cloudflare_upsert_record(hostname, zone_id, api_token, "AAAA", ipv6, timeout_seconds))
    return " | ".join(responses)


def tail_audit_log(limit: int) -> list[str]:
    if not AUDIT_LOG_FILE.exists():
        return []
    lines = AUDIT_LOG_FILE.read_text(encoding="utf-8").splitlines()
    return lines[-limit:]


def remove_panel_runtime() -> None:
    for path in [AUTH_FILE, SECRET_FILE, AUDIT_LOG_FILE, IP_BLOCK_FILE, ENTRIES_FILE, SETUP_FILE]:
        try:
            if path.exists():
                path.unlink()
        except Exception:
            pass
    for path in [ETC_DIR, STATE_DIR]:
        try:
            if path.exists():
                shutil.rmtree(path)
        except Exception:
            pass
    if NPM_PROXY_FILE.exists():
        try:
            NPM_PROXY_FILE.unlink()
        except Exception:
            pass
