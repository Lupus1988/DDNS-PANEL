import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lib.ddns_core import entry_hostnames, normalize_entries


UPDATE_PATH = ROOT / "scripts" / "ddns-panel-update.py"
UPDATE_SPEC = importlib.util.spec_from_file_location("ddns_panel_update", UPDATE_PATH)
assert UPDATE_SPEC and UPDATE_SPEC.loader
ddns_panel_update = importlib.util.module_from_spec(UPDATE_SPEC)
UPDATE_SPEC.loader.exec_module(ddns_panel_update)


class MultiHostEntryTests(unittest.TestCase):
    def test_legacy_entry_remains_compatible(self):
        data = normalize_entries(
            {
                "entries": [
                    {
                        "id": "legacy",
                        "name": "Netcup",
                        "provider": "netcup_rest",
                        "hostname": "KNITTEL-CLOUD.DE",
                    }
                ]
            }
        )

        entry = data["entries"][0]
        self.assertEqual(entry["hostname"], "knittel-cloud.de")
        self.assertEqual(entry["hostnames"], ["knittel-cloud.de"])
        self.assertEqual(entry_hostnames(entry), ["knittel-cloud.de"])

    def test_hostnames_are_normalized_and_deduplicated(self):
        data = normalize_entries(
            {
                "entries": [
                    {
                        "id": "multi",
                        "name": "Netcup",
                        "provider": "netcup_rest",
                        "hostnames": [
                            " mail.knittel-cloud.de ",
                            "KNITTEL-CLOUD.DE",
                            "mail.knittel-cloud.de",
                            "",
                        ],
                    }
                ]
            }
        )

        entry = data["entries"][0]
        self.assertEqual(entry["hostnames"], ["mail.knittel-cloud.de", "knittel-cloud.de"])
        self.assertEqual(entry["hostname"], "mail.knittel-cloud.de")


class MultiHostUpdateTests(unittest.TestCase):
    def test_provider_dispatch_receives_exact_hostname(self):
        with patch.object(ddns_panel_update, "netcup_rest_update", return_value="unchanged") as updater:
            result = ddns_panel_update.update_provider(
                "netcup_rest",
                "mail.knittel-cloud.de",
                "",
                "api-key",
                "ipv4",
                "95.88.164.203",
                "",
                5,
            )

        self.assertEqual(result, "unchanged")
        updater.assert_called_once_with(
            "mail.knittel-cloud.de",
            "",
            "api-key",
            "95.88.164.203",
            "",
            5,
        )


if __name__ == "__main__":
    unittest.main()
