import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib.ddns_core as core


class FakeResponse:
    def __init__(self, body):
        self.body = json.dumps(body).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.body


class NetcupRestUpdateTests(unittest.TestCase):
    def test_posts_api_key_and_exact_hostname_to_netcup_dynamic_dns_api(self):
        response = {
            "status": "success",
            "message": "Record(s) have been saved.",
        }

        with patch.object(core.urllib.request, "urlopen", return_value=FakeResponse(response)) as urlopen:
            result = core.netcup_rest_update(
                "knittel-cloud.de", "", "test-api-key", "95.88.164.203", "", 5
            )

        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://customercontrolpanel.de/wsDynDns.php")
        self.assertEqual(request.get_method(), "POST")
        self.assertNotIn("test-api-key", request.full_url)
        self.assertEqual(
            request.data.decode("ascii"),
            "action=update&token=test-api-key&fqdn=knittel-cloud.de&ipv4Address=95.88.164.203",
        )
        self.assertGreaterEqual(urlopen.call_args.kwargs["timeout"], 15)
        self.assertEqual(
            result,
            "Netcup CloudDNS: Record(s) have been saved. (knittel-cloud.de -> 95.88.164.203)",
        )

    def test_rejects_error_response_without_exposing_api_key(self):
        response = {
            "status": "error",
            "message": "Unable to authenticate test-api-key",
        }

        with patch.object(core.urllib.request, "urlopen", return_value=FakeResponse(response)):
            with self.assertRaisesRegex(RuntimeError, "Unable to authenticate \\[redacted\\]") as raised:
                core.netcup_rest_update(
                    "knittel-cloud.de", "", "test-api-key", "95.88.164.203", "", 20
                )

        self.assertNotIn("test-api-key", str(raised.exception))

    def test_reports_timeout_against_dynamic_dns_endpoint(self):
        with patch.object(core.urllib.request, "urlopen", side_effect=TimeoutError("timed out")):
            with self.assertRaisesRegex(RuntimeError, "Netcup DynDNS timeout.*knittel-cloud.de"):
                core.netcup_rest_update(
                    "knittel-cloud.de", "", "test-api-key", "95.88.164.203", "", 5
                )


if __name__ == "__main__":
    unittest.main()
