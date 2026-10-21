#!/usr/bin/env python3
from __future__ import annotations

import argparse
import time

from lib.ddns_core import (
    ensure_runtime_layout,
    find_entry,
    get_entry_secret,
    get_primary_lan_ip,
    freedns_update,
    dynv6_update,
    desec_update,
    he_update,
    cloudns_update,
    ydns_update,
    ddnss_update,
    entry_hostnames,
    load_entries,
    load_setup,
    load_status,
    noip_update,
    now_iso,
    request_public_ip_version,
    save_status,
    sync_local_access,
    sync_timer_unit,
    cloudflare_update,
    duckdns_update,
    dynu_update,
    netcup_rest_update,
)


SUPPORTED_PROVIDERS = {
    "dynu",
    "duckdns",
    "noip",
    "cloudflare",
    "freedns",
    "dynv6",
    "desec",
    "he",
    "cloudns",
    "ydns",
    "ddnss",
    "netcup_rest",
}


def update_provider(
    provider: str,
    hostname: str,
    username: str,
    password: str,
    ip_mode: str,
    target_ipv4: str,
    target_ipv6: str,
    timeout_seconds: int,
) -> str:
    if provider == "dynu":
        return dynu_update(hostname, username, password, target_ipv4, target_ipv6, timeout_seconds)
    if provider == "duckdns":
        return duckdns_update(hostname, password, target_ipv4, target_ipv6, timeout_seconds)
    if provider == "noip":
        return noip_update(hostname, username, password, target_ipv6 or target_ipv4, timeout_seconds)
    if provider == "freedns":
        return freedns_update(hostname, password, ip_mode, timeout_seconds)
    if provider == "dynv6":
        return dynv6_update(hostname, password, target_ipv4, target_ipv6, timeout_seconds)
    if provider == "desec":
        return desec_update(hostname, password, target_ipv4, target_ipv6, timeout_seconds)
    if provider == "he":
        return he_update(hostname, password, target_ipv4, target_ipv6, timeout_seconds)
    if provider == "cloudns":
        return cloudns_update(hostname, password, ip_mode, timeout_seconds)
    if provider == "ydns":
        return ydns_update(hostname, username, password, target_ipv6 or target_ipv4, timeout_seconds)
    if provider == "ddnss":
        return ddnss_update(hostname, username, password, target_ipv4, target_ipv6, timeout_seconds)
    if provider == "netcup_rest":
        return netcup_rest_update(hostname, username, password, target_ipv4, target_ipv6, timeout_seconds)
    if provider == "cloudflare":
        return cloudflare_update(hostname, username, password, target_ipv4, target_ipv6, timeout_seconds)
    raise ValueError("Provider aktuell nicht unterstützt.")


def host_status(entry_status: dict, hostname: str) -> dict:
    hosts = entry_status.setdefault("hosts", {})
    if not isinstance(hosts, dict):
        hosts = {}
        entry_status["hosts"] = hosts
    return hosts.setdefault(hostname, {})


def run_update(force: bool = False, entry_id: str = "") -> int:
    ensure_runtime_layout()
    setup = load_setup()
    sync_timer_unit(setup)
    sync_local_access(setup)

    status = load_status()
    status["local_ip"] = get_primary_lan_ip()

    public_ipv4 = ""
    public_ipv6 = ""
    used_ipv4_source = ""
    used_ipv6_source = ""
    last_error = ""
    for attempt in range(setup["retry_count"] + 1):
        ipv4_error = ""
        ipv6_error = ""
        try:
            public_ipv4, used_ipv4_source = request_public_ip_version(setup["ipv4_sources"], setup["request_timeout_seconds"], 4)
        except Exception as exc:
            ipv4_error = str(exc)
        try:
            public_ipv6, used_ipv6_source = request_public_ip_version(setup["ipv6_sources"], setup["request_timeout_seconds"], 6)
        except Exception as exc:
            ipv6_error = str(exc)
        if public_ipv4 or public_ipv6:
            break
        last_error = " / ".join(part for part in [ipv4_error, ipv6_error] if part) or "Keine öffentliche IP ermittelbar."
        if attempt < setup["retry_count"]:
            time.sleep(setup["retry_delay_seconds"])
    if not public_ipv4 and not public_ipv6:
        status["last_check_at"] = now_iso()
        status["last_run_summary"] = last_error or "Keine öffentliche IP ermittelbar."
        save_status(status)
        print(status["last_run_summary"])
        return 1

    previous_ipv4 = str(status.get("current_public_ipv4", "")).strip()
    previous_ipv6 = str(status.get("current_public_ipv6", "")).strip()
    ipv4_changed = bool(public_ipv4) and public_ipv4 != previous_ipv4
    ipv6_changed = bool(public_ipv6) and public_ipv6 != previous_ipv6
    ip_changed = ipv4_changed or ipv6_changed
    status["current_public_ip"] = public_ipv4 or public_ipv6
    status["current_public_ipv4"] = public_ipv4
    status["current_public_ipv6"] = public_ipv6
    status["last_check_at"] = now_iso()

    entries = load_entries()["entries"]
    if entry_id:
        entries = [entry for entry in entries if entry["id"] == entry_id]

    if not entries:
        status["last_run_summary"] = "Keine passenden DDNS-Dienste gefunden."
        save_status(status)
        print(status["last_run_summary"])
        return 0

    if setup["only_update_on_change"] and not ip_changed and not force:
        unchanged_parts = []
        if public_ipv4:
            unchanged_parts.append(f"IPv4 {public_ipv4}" + (f" via {used_ipv4_source}" if used_ipv4_source else ""))
        if public_ipv6:
            unchanged_parts.append(f"IPv6 {public_ipv6}" + (f" via {used_ipv6_source}" if used_ipv6_source else ""))
        status["last_run_summary"] = f"Öffentliche IP unverändert ({'; '.join(unchanged_parts)})"
        for entry in entries:
            current = status["entries"].setdefault(entry["id"], {})
            current["ok"] = True
            current["last_error"] = ""
            current["last_checked_at"] = now_iso()
            current["last_public_ip"] = public_ipv4 or public_ipv6
            current["last_public_ipv4"] = public_ipv4
            current["last_public_ipv6"] = public_ipv6
            current["last_result"] = "unchanged"
            for hostname in entry_hostnames(entry):
                host = host_status(current, hostname)
                host["ok"] = True
                host["last_error"] = ""
                host["last_public_ip"] = public_ipv4 or public_ipv6
                host["last_public_ipv4"] = public_ipv4
                host["last_public_ipv6"] = public_ipv6
                host["last_result"] = "unchanged"
                host["last_checked_at"] = now_iso()
        save_status(status)
        print(status["last_run_summary"])
        return 0

    if ip_changed:
        status["last_change_at"] = now_iso()

    ok_count = 0
    error_count = 0
    for entry in entries:
        entry_status = status["entries"].setdefault(entry["id"], {})
        hostnames = entry_hostnames(entry)
        entry_status["last_checked_at"] = now_iso()
        entry_status["last_public_ip"] = public_ipv4 or public_ipv6
        entry_status["last_public_ipv4"] = public_ipv4
        entry_status["last_public_ipv6"] = public_ipv6

        if not hostnames:
            entry_status["ok"] = False
            entry_status["last_result"] = "error"
            entry_status["last_error"] = "Keine Hostnamen konfiguriert."
            error_count += 1
            continue

        if not entry.get("enabled", True):
            entry_status["ok"] = True
            entry_status["last_error"] = ""
            entry_status["last_result"] = "disabled"
            for hostname in hostnames:
                host = host_status(entry_status, hostname)
                host["ok"] = True
                host["last_error"] = ""
                host["last_result"] = "disabled"
                host["last_checked_at"] = now_iso()
            continue

        ip_mode = entry.get("ip_mode", "ipv4")
        target_ipv4 = public_ipv4 if ip_mode in {"ipv4", "dual"} else ""
        target_ipv6 = public_ipv6 if ip_mode in {"ipv6", "dual"} else ""
        validation_error = ""
        if ip_mode == "ipv4" and not target_ipv4:
            validation_error = "Keine öffentliche IPv4-Adresse verfügbar."
        elif ip_mode == "ipv6" and not target_ipv6:
            validation_error = "Keine öffentliche IPv6-Adresse verfügbar."
        elif ip_mode == "dual" and (not target_ipv4 or not target_ipv6):
            validation_error = "Für Dual Stack werden öffentliche IPv4 und IPv6 benötigt."

        secret = get_entry_secret(entry["id"])
        username = secret.get("username", "").strip()
        password = secret.get("password", "")
        provider = entry["provider"]
        host_results = []
        host_errors = []
        for hostname in hostnames:
            host = host_status(entry_status, hostname)
            host["last_checked_at"] = now_iso()
            host["last_public_ip"] = public_ipv4 or public_ipv6
            host["last_public_ipv4"] = public_ipv4
            host["last_public_ipv6"] = public_ipv6
            try:
                if validation_error:
                    raise ValueError(validation_error)
                if provider not in SUPPORTED_PROVIDERS:
                    raise ValueError("Provider aktuell nicht unterstützt.")
                if provider == "dynu" and (not username or not password):
                    raise ValueError("Dynu-Zugangsdaten fehlen.")
                if provider == "duckdns" and not password:
                    raise ValueError("DuckDNS-Token fehlt.")
                if provider == "noip" and (not username or not password):
                    raise ValueError("No-IP-Zugangsdaten fehlen.")
                if provider in {"freedns", "dynv6", "desec", "he", "cloudns"} and not password:
                    raise ValueError("Zugangsdaten für den Anbieter fehlen.")
                if provider == "ydns" and (not username or not password):
                    raise ValueError("YDNS-Zugangsdaten fehlen.")
                if provider == "ddnss" and (not username or not password):
                    raise ValueError("ddnss.de-Zugangsdaten fehlen.")
                if provider == "netcup_rest" and not password:
                    raise ValueError("Netcup API-Key fehlt.")
                if provider == "cloudflare" and (not username or not password):
                    raise ValueError("Cloudflare Zone-ID oder API-Token fehlt.")
                response = update_provider(
                    provider,
                    hostname,
                    username,
                    password,
                    ip_mode,
                    target_ipv4,
                    target_ipv6,
                    setup["request_timeout_seconds"],
                )
                host["ok"] = True
                host["last_error"] = ""
                host["last_result"] = response
                host["last_update_at"] = now_iso()
                host_results.append(f"{hostname}: {response}")
            except Exception as exc:
                host["ok"] = False
                host["last_error"] = str(exc)
                host["last_result"] = "error"
                host_errors.append(f"{hostname}: {exc}")
        entry_status["ok"] = not host_errors
        entry_status["last_error"] = "; ".join(host_errors)
        entry_status["last_result"] = "; ".join(host_results) if host_results else "error"
        entry_status["last_update_at"] = now_iso()
        if host_errors:
            error_count += 1
        else:
            ok_count += 1

    summary_parts = []
    if public_ipv4:
        summary_parts.append(f"IPv4 {public_ipv4}" + (f" via {used_ipv4_source}" if used_ipv4_source else ""))
    if public_ipv6:
        summary_parts.append(f"IPv6 {public_ipv6}" + (f" via {used_ipv6_source}" if used_ipv6_source else ""))
    status["last_run_summary"] = f"{'; '.join(summary_parts)} geprüft, {ok_count} erfolgreich, {error_count} Fehler"
    save_status(status)
    print(status["last_run_summary"])
    return 0 if error_count == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--entry-id", default="")
    args = parser.parse_args()
    return run_update(force=args.force, entry_id=args.entry_id)


if __name__ == "__main__":
    raise SystemExit(main())
