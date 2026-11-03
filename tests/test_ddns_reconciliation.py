import importlib.util
import io
import sys
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import lib.ddns_core as core

spec = importlib.util.spec_from_file_location(
    "ddns_panel_update", ROOT / "scripts" / "ddns-panel-update.py"
)
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        timer_patch = patch.object(updater, "sync_timer_unit")
        access_patch = patch.object(updater, "sync_local_access")
        timer_patch.start()
        access_patch.start()
        self.addCleanup(timer_patch.stop)
        self.addCleanup(access_patch.stop)

    def test_reconciliation_is_due_when_missing_or_at_least_one_hour_old(self):
        now = datetime(2026, 11, 3, 18, 0, 0)

        self.assertTrue(core.netcup_reconciliation_due("", now))
        self.assertTrue(core.netcup_reconciliation_due("2026-11-03 16:59:59", now))
        self.assertFalse(core.netcup_reconciliation_due("2026-11-03 17:30:00", now))

    def test_due_unchanged_ip_triggers_a_provider_reconciliation(self):
        old_attempt = (datetime.now() - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
        status = {
            "current_public_ipv4": "95.88.164.203",
            "current_public_ipv6": "",
            "entries": {"entry-1": {"last_reconcile_attempt_at": old_attempt}},
        }
        entry = {
            "id": "entry-1",
            "name": "Knittel Cloud",
            "provider": "netcup_rest",
            "ip_mode": "ipv4",
            "hostname": "knittel-cloud.de",
            "hostnames": ["knittel-cloud.de"],
            "enabled": True,
        }
        setup = {
            "only_update_on_change": True,
            "retry_count": 0,
            "retry_delay_seconds": 1,
            "request_timeout_seconds": 5,
            "ipv4_sources": [],
            "ipv6_sources": [],
        }

        with (
            patch.object(updater, "ensure_runtime_layout"),
            patch.object(updater, "load_setup", return_value=setup),
            patch.object(updater, "load_status", return_value=status),
            patch.object(updater, "load_entries", return_value={"entries": [entry]}),
            patch.object(updater, "get_primary_lan_ip", return_value="192.168.0.111"),
            patch.object(updater, "request_public_ip_version", side_effect=[("95.88.164.203", "ip-check"), RuntimeError("no IPv6")]),
            patch.object(updater, "get_entry_secret", return_value={"username": "", "password": "test-api-key"}),
            patch.object(updater, "update_provider", return_value="unchanged A knittel-cloud.de -> 95.88.164.203") as update_provider,
            patch.object(updater, "save_status"),
        ):
            result = updater.run_update()

        self.assertEqual(result, 0)
        update_provider.assert_called_once()
        self.assertEqual(update_provider.call_args.args[0:2], ("netcup_rest", "knittel-cloud.de"))
        self.assertEqual(update_provider.call_args.args[5], "95.88.164.203")

    def test_recent_failed_reconciliation_remains_visible_until_next_attempt(self):
        recent_attempt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status = {
            "current_public_ipv4": "95.88.164.203",
            "current_public_ipv6": "",
            "entries": {
                "entry-1": {
                    "ok": False,
                    "last_error": "Netcup API is unavailable",
                    "last_result": "error",
                    "last_reconcile_attempt_at": recent_attempt,
                    "hosts": {
                        "knittel-cloud.de": {
                            "ok": False,
                            "last_error": "Netcup API is unavailable",
                            "last_result": "error",
                        }
                    },
                }
            },
        }
        entry = {
            "id": "entry-1",
            "name": "Knittel Cloud",
            "provider": "netcup_rest",
            "ip_mode": "ipv4",
            "hostname": "knittel-cloud.de",
            "hostnames": ["knittel-cloud.de"],
            "enabled": True,
        }
        setup = {
            "only_update_on_change": True,
            "retry_count": 0,
            "retry_delay_seconds": 1,
            "request_timeout_seconds": 5,
            "ipv4_sources": [],
            "ipv6_sources": [],
        }

        with (
            patch.object(updater, "ensure_runtime_layout"),
            patch.object(updater, "load_setup", return_value=setup),
            patch.object(updater, "load_status", return_value=status),
            patch.object(updater, "load_entries", return_value={"entries": [entry]}),
            patch.object(updater, "get_primary_lan_ip", return_value="192.168.0.111"),
            patch.object(updater, "request_public_ip_version", side_effect=[("95.88.164.203", "ip-check"), RuntimeError("no IPv6")]),
            patch.object(updater, "update_provider") as update_provider,
            patch.object(updater, "save_status"),
        ):
            result = updater.run_update()

        self.assertEqual(result, 0)
        update_provider.assert_not_called()
        current = status["entries"]["entry-1"]
        self.assertFalse(current["ok"])
        self.assertEqual(current["last_error"], "Netcup API is unavailable")
        self.assertEqual(current["last_result"], "error")
        self.assertEqual(current["hosts"]["knittel-cloud.de"]["last_error"], "Netcup API is unavailable")
        self.assertIn("Netcup API is unavailable", status["last_run_summary"])

    def test_netcup_hourly_limit_applies_even_when_update_on_change_is_disabled(self):
        recent_attempt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status = {
            "current_public_ipv4": "95.88.164.203",
            "current_public_ipv6": "",
            "entries": {"entry-1": {"last_reconcile_attempt_at": recent_attempt}},
        }
        entry = {
            "id": "entry-1",
            "name": "Knittel Cloud",
            "provider": "netcup_rest",
            "ip_mode": "ipv4",
            "hostname": "knittel-cloud.de",
            "hostnames": ["knittel-cloud.de"],
            "enabled": True,
        }
        setup = {
            "only_update_on_change": False,
            "retry_count": 0,
            "retry_delay_seconds": 1,
            "request_timeout_seconds": 5,
            "ipv4_sources": [],
            "ipv6_sources": [],
        }

        with (
            patch.object(updater, "ensure_runtime_layout"),
            patch.object(updater, "load_setup", return_value=setup),
            patch.object(updater, "load_status", return_value=status),
            patch.object(updater, "load_entries", return_value={"entries": [entry]}),
            patch.object(updater, "get_primary_lan_ip", return_value="192.168.0.111"),
            patch.object(updater, "request_public_ip_version", side_effect=[("95.88.164.203", "ip-check"), RuntimeError("no IPv6")]),
            patch.object(updater, "get_entry_secret", return_value={"username": "", "password": "test-api-key"}),
            patch.object(updater, "update_provider") as update_provider,
            patch.object(updater, "save_status"),
        ):
            updater.run_update()

        update_provider.assert_not_called()

    def test_manual_run_summary_contains_provider_error_details(self):
        old_attempt = (datetime.now() - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
        status = {
            "current_public_ipv4": "95.88.164.203",
            "current_public_ipv6": "",
            "entries": {"entry-1": {"last_reconcile_attempt_at": old_attempt}},
        }
        entry = {
            "id": "entry-1",
            "name": "Knittel Cloud",
            "provider": "netcup_rest",
            "ip_mode": "ipv4",
            "hostname": "knittel-cloud.de",
            "hostnames": ["knittel-cloud.de"],
            "enabled": True,
        }
        setup = {
            "only_update_on_change": True,
            "retry_count": 0,
            "retry_delay_seconds": 1,
            "request_timeout_seconds": 5,
            "ipv4_sources": [],
            "ipv6_sources": [],
        }
        output = io.StringIO()

        with (
            patch.object(updater, "ensure_runtime_layout"),
            patch.object(updater, "load_setup", return_value=setup),
            patch.object(updater, "load_status", return_value=status),
            patch.object(updater, "load_entries", return_value={"entries": [entry]}),
            patch.object(updater, "get_primary_lan_ip", return_value="192.168.0.111"),
            patch.object(updater, "request_public_ip_version", side_effect=[("95.88.164.203", "ip-check"), RuntimeError("no IPv6")]),
            patch.object(updater, "get_entry_secret", return_value={"username": "", "password": "test-api-key"}),
            patch.object(updater, "update_provider", side_effect=RuntimeError("Netcup CloudDNS POST failed: unexpectedError")),
            patch.object(updater, "save_status"),
            redirect_stdout(output),
        ):
            result = updater.run_update()

        self.assertEqual(result, 1)
        self.assertIn("unexpectedError", output.getvalue())
        self.assertNotIn("test-api-key", output.getvalue())


if __name__ == "__main__":
    unittest.main()
