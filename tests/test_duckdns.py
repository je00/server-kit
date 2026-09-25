#!/usr/bin/env python3
"""验证动态 DNS 凭据不会回显，且错误候选不会覆盖有效配置。"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
HELPER = REPO / "lib/server_kit_duckdns.py"


class DuckDnsHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.config = root / "etc/server-kit/duckdns.json"
        self.state = root / "var/lib/server-kit/duckdns-state.json"
        self.node_domains = root / "etc/server-kit/node-domains.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_helper(
        self, operation: str, *, provider: str = "duckdns", token: str = "",
        secret_id: str = "", secret_key: str = "", zone: str = "",
        fqdn: str = "gateway-demo.duckdns.org", response: str = "OK",
        dnspod_responses: dict[str, object] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        arguments = [
            sys.executable, str(HELPER), operation,
            "--config", str(self.config), "--state", str(self.state),
        ]
        if operation == "configure":
            arguments += [
                "--fqdn", fqdn, "--node-domains-config", str(self.node_domains),
            ]
        environment = {
            **os.environ,
            "PYTHONPATH": str(REPO),
            "SERVER_KIT_TESTING": "1",
            # This mocked fixture must pass the production is_global check.
            # API/DNS results below are injected; no request goes to this IP.
            "SERVER_KIT_PUBLIC_IPV4": "1.1.1.1",
            "SERVER_KIT_DUCKDNS_API_RESPONSE": response,
            "SERVER_KIT_DNS_IPV4S": "1.1.1.1",
        }
        if dnspod_responses is not None:
            environment["SERVER_KIT_DNSPOD_API_RESPONSES"] = json.dumps(dnspod_responses)
        return subprocess.run(
            arguments, input=json.dumps({
                "provider": provider, "token": token, "secret_id": secret_id,
                "secret_key": secret_key, "zone": zone,
                "fqdn": fqdn if provider == "dnspod" else "",
            }) if operation == "configure" else None,
            text=True, capture_output=True, check=False, env=environment,
        )

    def test_configure_status_and_delete_never_return_token(self) -> None:
        token = "12345678-1234-1234-1234-123456789abc"
        configured = self.run_helper("configure", token=token)
        self.assertEqual(configured.returncode, 0, configured.stderr)
        self.assertNotIn(token, configured.stdout)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(self.config.read_text())["token"], token)

        status = self.run_helper("status")
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertNotIn(token, status.stdout)
        payload = json.loads(status.stdout)
        self.assertEqual(payload["provider"], "duckdns")
        self.assertTrue(payload["token_present"])
        self.assertTrue(payload["credentials_present"])
        self.assertTrue(payload["dns_matches_last_ipv4"])

        deleted = self.run_helper("delete")
        self.assertEqual(deleted.returncode, 0, deleted.stderr)
        self.assertFalse(self.config.exists())
        self.assertFalse(self.state.exists())

    def test_rejected_candidate_does_not_replace_existing_token(self) -> None:
        original = "12345678-1234-1234-1234-123456789abc"
        self.assertEqual(self.run_helper("configure", token=original).returncode, 0)
        rejected = self.run_helper(
            "configure", token="abcdefab-cdef-abcd-efab-cdefabcdefab", response="KO"
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertNotIn("abcdefab-cdef-abcd-efab-cdefabcdefab", rejected.stderr)
        self.assertEqual(json.loads(self.config.read_text())["token"], original)

    def test_requires_duckdns_stable_endpoint(self) -> None:
        result = subprocess.run(
            [sys.executable, str(HELPER), "configure", "--config", str(self.config),
             "--state", str(self.state), "--fqdn", "vpn.example.com"],
            input=json.dumps({
                "provider": "duckdns", "token": "12345678-1234-1234-1234-123456789abc",
                "secret_id": "", "secret_key": "", "zone": "", "fqdn": "",
            }),
            text=True, capture_output=True, check=False,
            env={**os.environ, "PYTHONPATH": str(REPO), "SERVER_KIT_TESTING": "1",
                 "SERVER_KIT_PUBLIC_IPV4": "1.1.1.1",
                 "SERVER_KIT_DUCKDNS_API_RESPONSE": "OK"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("不是 duckdns.org", result.stderr)

    def test_rejects_provider_domain_covered_by_subscription_wildcard(self) -> None:
        self.node_domains.parent.mkdir(parents=True, exist_ok=True)
        self.node_domains.write_text(json.dumps({
            "version": 1, "nodes": {"home-nas": ["*.duckdns.org"]},
        }), encoding="utf-8")
        result = self.run_helper(
            "configure", provider="duckdns",
            token="12345678-1234-1234-1234-123456789abc",
            fqdn="gateway-demo.duckdns.org",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("覆盖 VPS 域名", result.stderr)
        self.assertFalse(self.config.exists())

    def test_dnspod_configure_updates_matching_a_record_without_returning_secrets(self) -> None:
        secret_id = "AKIDEXAMPLE1234567890123456789012"
        secret_key = "example-secret-key-value-1234567890"
        responses = {
            "DescribeRecordList": {"Response": {"RecordList": [{
                "RecordId": 42, "Name": "gateway-demo", "Type": "A", "Line": "默认",
            }], "RequestId": "describe"}},
            "ModifyDynamicDNS": {"Response": {"RecordId": 42, "RequestId": "modify"}},
        }
        configured = self.run_helper(
            "configure", provider="dnspod", secret_id=secret_id, secret_key=secret_key,
            zone="managed.example.com", fqdn="gateway-demo.managed.example.com", dnspod_responses=responses,
        )
        self.assertEqual(configured.returncode, 0, configured.stderr)
        self.assertNotIn(secret_id, configured.stdout)
        self.assertNotIn(secret_key, configured.stdout)
        saved = json.loads(self.config.read_text())
        self.assertEqual(saved["provider"], "dnspod")
        self.assertEqual(saved["record_id"], 42)
        self.assertEqual(saved["record_line"], "默认")
        self.assertFalse(json.loads(configured.stdout)["record_created"])

        status = self.run_helper("status")
        payload = json.loads(status.stdout)
        self.assertEqual(payload["provider_label"], "腾讯云 DNSPod")
        self.assertTrue(payload["credentials_present"])
        self.assertFalse(payload["token_present"])

    def test_rejected_dnspod_candidate_does_not_replace_existing_config(self) -> None:
        original = "12345678-1234-1234-1234-123456789abc"
        self.assertEqual(self.run_helper("configure", token=original).returncode, 0)
        before = self.config.read_bytes()
        responses = {
            "DescribeRecordList": {"Response": {"Error": {
                "Code": "AuthFailure.SignatureFailure", "Message": "secret details",
            }, "RequestId": "failed"}},
        }
        rejected = self.run_helper(
            "configure", provider="dnspod", secret_id="AKIDEXAMPLE1234567890123456789012",
            secret_key="candidate-secret-key-value-123456", zone="managed.example.com",
            fqdn="gateway-demo.managed.example.com", dnspod_responses=responses,
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertNotIn("candidate-secret", rejected.stderr)
        self.assertEqual(self.config.read_bytes(), before)

    def test_dnspod_configure_creates_missing_default_a_record(self) -> None:
        responses = {
            "DescribeRecordList": {"Response": {"RecordList": [], "RequestId": "describe"}},
            "CreateRecord": {"Response": {"RecordId": 43, "RequestId": "create"}},
            "ModifyDynamicDNS": {"Response": {"RecordId": 43, "RequestId": "modify"}},
        }
        configured = self.run_helper(
            "configure", provider="dnspod",
            secret_id="AKIDEXAMPLE1234567890123456789012",
            secret_key="example-secret-key-value-1234567890",
            zone="managed.example.com", fqdn="gateway-demo.managed.example.com",
            dnspod_responses=responses,
        )
        self.assertEqual(configured.returncode, 0, configured.stderr)
        self.assertTrue(json.loads(configured.stdout)["record_created"])
        saved = json.loads(self.config.read_text())
        self.assertEqual(saved["record"], "gateway-demo")
        self.assertEqual(saved["record_id"], 43)
        self.assertEqual(saved["record_line"], "默认")

    def test_dnspod_configure_rejects_ambiguous_same_name_records(self) -> None:
        responses = {
            "DescribeRecordList": {"Response": {"RecordList": [
                {"RecordId": 42, "Name": "gateway-demo", "Type": "A", "Line": "默认"},
                {"RecordId": 43, "Name": "gateway-demo", "Type": "A", "Line": "境外"},
            ], "RequestId": "describe"}},
        }
        configured = self.run_helper(
            "configure", provider="dnspod",
            secret_id="AKIDEXAMPLE1234567890123456789012",
            secret_key="example-secret-key-value-1234567890",
            zone="managed.example.com", fqdn="gateway-demo.managed.example.com",
            dnspod_responses=responses,
        )
        self.assertNotEqual(configured.returncode, 0)
        self.assertIn("多条同名记录", configured.stderr)
        self.assertFalse(self.config.exists())

    def test_reads_legacy_v1_duckdns_config(self) -> None:
        self.config.parent.mkdir(parents=True)
        self.config.write_text(json.dumps({
            "schema_version": 1, "enabled": True, "fqdn": "gateway-demo.duckdns.org",
            "token": "12345678-1234-1234-1234-123456789abc",
        }))
        status = self.run_helper("status")
        self.assertEqual(status.returncode, 0, status.stderr)
        payload = json.loads(status.stdout)
        self.assertEqual(payload["schema_version"], 2)
        self.assertEqual(payload["provider"], "duckdns")


if __name__ == "__main__":
    unittest.main()
