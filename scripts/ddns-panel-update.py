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
)


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
            current["last_checked_at"] = now_iso()
            current["last_public_ip"] = public_ipv4 or public_ipv6
            current["last_public_ipv4"] = public_ipv4
            current["last_public_ipv6"] = public_ipv6
            current["last_result"] = "unchanged"
        save_status(status)
        print(status["last_run_summary"])
        return 0

    if ip_changed:
        status["last_change_at"] = now_iso()

    ok_count = 0
    error_count = 0
    for entry in entries:
        entry_status = status["entries"].setdefault(entry["id"], {})
        entry_status["last_checked_at"] = now_iso()
        entry_status["last_public_ip"] = public_ipv4 or public_ipv6
        entry_status["last_public_ipv4"] = public_ipv4
        entry_status["last_public_ipv6"] = public_ipv6

        if not entry.get("enabled", True):
            entry_status["ok"] = True
            entry_status["last_result"] = "disabled"
            continue

        ip_mode = entry.get("ip_mode", "ipv4")
        target_ipv4 = public_ipv4 if ip_mode in {"ipv4", "dual"} else ""
        target_ipv6 = public_ipv6 if ip_mode in {"ipv6", "dual"} else ""
        if ip_mode == "ipv4" and not target_ipv4:
            entry_status["ok"] = False
            entry_status["last_error"] = "Keine öffentliche IPv4-Adresse verfügbar."
            entry_status["last_result"] = "error"
            error_count += 1
            continue
        if ip_mode == "ipv6" and not target_ipv6:
            entry_status["ok"] = False
            entry_status["last_error"] = "Keine öffentliche IPv6-Adresse verfügbar."
            entry_status["last_result"] = "error"
            error_count += 1
            continue
        if ip_mode == "dual" and (not target_ipv4 or not target_ipv6):
            entry_status["ok"] = False
            entry_status["last_error"] = "Für Dual Stack werden öffentliche IPv4 und IPv6 benötigt."
            entry_status["last_result"] = "error"
            error_count += 1
            continue

        secret = get_entry_secret(entry["id"])
        username = secret.get("username", "").strip()
        password = secret.get("password", "")
        if entry["provider"] not in {"dynu", "duckdns", "noip", "cloudflare", "freedns", "dynv6", "desec", "he", "cloudns", "ydns", "ddnss"}:
            entry_status["ok"] = False
            entry_status["last_error"] = "Provider aktuell nicht unterstützt."
            error_count += 1
            continue
        try:
            if entry["provider"] == "dynu":
                if not username or not password:
                    raise ValueError("Dynu-Zugangsdaten fehlen.")
                response = dynu_update(entry["hostname"], username, password, target_ipv4, target_ipv6, setup["request_timeout_seconds"])
            elif entry["provider"] == "duckdns":
                if not password:
                    raise ValueError("DuckDNS-Token fehlt.")
                response = duckdns_update(entry["hostname"], password, target_ipv4, target_ipv6, setup["request_timeout_seconds"])
            elif entry["provider"] == "noip":
                if not username or not password:
                    raise ValueError("No-IP-Zugangsdaten fehlen.")
                response = noip_update(entry["hostname"], username, password, target_ipv6 or target_ipv4, setup["request_timeout_seconds"])
            elif entry["provider"] == "freedns":
                if not password:
                    raise ValueError("FreeDNS-Token oder Update-URL fehlt.")
                response = freedns_update(entry["hostname"], password, ip_mode, setup["request_timeout_seconds"])
            elif entry["provider"] == "dynv6":
                if not password:
                    raise ValueError("dynv6-Token fehlt.")
                response = dynv6_update(entry["hostname"], password, target_ipv4, target_ipv6, setup["request_timeout_seconds"])
            elif entry["provider"] == "desec":
                if not password:
                    raise ValueError("deSEC-Token fehlt.")
                response = desec_update(entry["hostname"], password, target_ipv4, target_ipv6, setup["request_timeout_seconds"])
            elif entry["provider"] == "he":
                if not password:
                    raise ValueError("Hurricane-Electric-Passwort fehlt.")
                response = he_update(entry["hostname"], password, target_ipv4, target_ipv6, setup["request_timeout_seconds"])
            elif entry["provider"] == "cloudns":
                if not password:
                    raise ValueError("ClouDNS Dynamic URL fehlt.")
                response = cloudns_update(entry["hostname"], password, ip_mode, setup["request_timeout_seconds"])
            elif entry["provider"] == "ydns":
                if not username or not password:
                    raise ValueError("YDNS-Zugangsdaten fehlen.")
                response = ydns_update(entry["hostname"], username, password, target_ipv6 or target_ipv4, setup["request_timeout_seconds"])
            elif entry["provider"] == "ddnss":
                if not username or not password:
                    raise ValueError("ddnss.de-Zugangsdaten fehlen.")
                response = ddnss_update(entry["hostname"], username, password, target_ipv4, target_ipv6, setup["request_timeout_seconds"])
            else:
                if not username or not password:
                    raise ValueError("Cloudflare Zone-ID oder API-Token fehlt.")
                response = cloudflare_update(entry["hostname"], username, password, target_ipv4, target_ipv6, setup["request_timeout_seconds"])
            entry_status["ok"] = True
            entry_status["last_error"] = ""
            entry_status["last_result"] = response
            entry_status["last_update_at"] = now_iso()
            ok_count += 1
        except Exception as exc:
            entry_status["ok"] = False
            entry_status["last_error"] = str(exc)
            entry_status["last_result"] = "error"
            error_count += 1

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
