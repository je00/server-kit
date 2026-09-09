#!/usr/bin/env python3
"""验证浏览器本地密钥生成器不联网、不签名且不泄露私钥。"""

from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path


class BrowserExtensionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[1] / "browser_extension"

    def test_manifest_v3_has_no_network_or_page_access(self) -> None:
        manifest = json.loads((self.root / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["manifest_version"], 3)
        self.assertEqual(manifest["permissions"], ["alarms", "storage"])
        self.assertNotIn("host_permissions", manifest)
        self.assertNotIn("externally_connectable", manifest)
        self.assertNotIn("content_scripts", manifest)
        self.assertNotIn("default_popup", manifest["action"])

    def test_toolbar_action_opens_a_stable_tab_instead_of_an_ephemeral_popup(self) -> None:
        worker = (self.root / "service_worker.js").read_text(encoding="utf-8")
        self.assertIn("chrome.action.onClicked.addListener", worker)
        self.assertIn('chrome.tabs.create({ url: chrome.runtime.getURL("popup.html") })', worker)

    def test_signing_and_pairing_are_completely_absent(self) -> None:
        self.assertFalse((self.root / "signing.js").exists())
        self.assertFalse((self.root / "key_store.js").exists())
        combined = "\n".join(path.read_text(encoding="utf-8") for path in self.root.glob("*.js"))
        for forbidden in ("pairing", "ECDSA", "fetch(", "onMessageExternal"):
            self.assertNotIn(forbidden, combined)
        worker = (self.root / "service_worker.js").read_text(encoding="utf-8")
        self.assertIn('indexedDB.deleteDatabase("server-kit-signer")', worker)

    def test_extension_has_no_remote_script_or_broad_web_access(self) -> None:
        for path in self.root.glob("*.js"):
            content = path.read_text(encoding="utf-8")
            self.assertNotIn("eval(", content)
            self.assertNotIn("new Function", content)
            self.assertNotIn("https://", content)
            self.assertNotIn("<all_urls>", content)

    def test_awg_key_and_three_profiles_use_expiring_session_memory(self) -> None:
        awg = (self.root / "awg.js").read_text(encoding="utf-8")
        popup = (self.root / "popup.js").read_text(encoding="utf-8")
        key_store = (self.root / "session_store.js").read_text(encoding="utf-8")
        html = (self.root / "popup.html").read_text(encoding="utf-8")
        self.assertIn("crypto.getRandomValues", awg)
        self.assertIn("function x25519", awg)
        self.assertIn("PrivateKey = ${keys.privateKey}", awg)
        self.assertIn("context.endpoints.map", popup)
        self.assertIn("savePendingBundle", popup)
        self.assertIn("readPendingBundle", popup)
        self.assertIn("clearPendingBundle", popup)
        self.assertIn("chrome.storage.session", key_store)
        self.assertNotIn("chrome.storage.local", key_store)
        self.assertNotIn("chrome.storage.sync", key_store)
        self.assertIn("enrollmentToken", popup)
        self.assertIn("preshared_key: keys.presharedKey", awg)
        self.assertIn('src="vendor/qrcode.js"', html)
        self.assertIn("qrcode(0, \"M\")", popup)
        self.assertNotIn("/api/", popup)
        self.assertNotIn("fetch(", popup)
        css = (self.root / "popup.css").read_text(encoding="utf-8")
        self.assertIn("[hidden] { display: none !important; }", css)

    def test_pending_profile_bundle_expires_from_session_memory(self) -> None:
        key_store_path = self.root / "session_store.js"
        script = (
            "const memory={};let alarm=null;let now=1000;Date.now=()=>now;"
            "globalThis.chrome={storage:{session:{"
            "set:async(value)=>Object.assign(memory,value),"
            "get:async(key)=>({[key]:memory[key]}),"
            "remove:async(key)=>{delete memory[key]}}},"
            "alarms:{create:async(name,options)=>{alarm={name,options}},clear:async()=>true}};"
            f"require({json.dumps(str(key_store_path))});"
            "(async()=>{const saved=await serverKitKeyStore.savePendingBundle({bundle:{name:'desk',profiles:[]}},30);"
            "const restored=await serverKitKeyStore.readPendingBundle();"
            "now=32000;const expired=await serverKitKeyStore.readPendingBundle();"
            "console.log(JSON.stringify({saved,restored,expired,alarm,memory}));})()"
        )
        completed = subprocess.run(
            ["node", "-e", script], check=True, capture_output=True, text=True
        )
        value = json.loads(completed.stdout)
        self.assertEqual(value["saved"]["expiresAt"], 31000)
        self.assertEqual(value["restored"]["bundle"]["name"], "desk")
        self.assertIsNone(value["expired"])
        self.assertEqual(value["memory"], {})

    def test_enrollment_token_interoperates_with_server_decoder_without_private_key(self) -> None:
        awg_path = self.root / "awg.js"
        script = (
            "globalThis.crypto=require('crypto').webcrypto;"
            f"require({json.dumps(str(awg_path))});"
            "const keys={privateKey:'PRIVATE-MUST-STAY-LOCAL',"
            "publicKey:Buffer.alloc(32,1).toString('base64'),"
            "presharedKey:Buffer.alloc(32,2).toString('base64')};"
            "console.log(serverKitAwg.enrollmentToken('admin-home','10.20.0.2',keys));"
        )
        completed = subprocess.run(
            ["node", "-e", script], check=True, capture_output=True, text=True
        )
        token = completed.stdout.strip()
        from lib.server_kit_bootstrap import decode_enrollment_token

        enrollment = decode_enrollment_token(token, "admin-home")
        self.assertEqual(enrollment.address, "10.20.0.2")
        padding = "=" * (-len(token) % 4)
        import base64

        payload = json.loads(base64.urlsafe_b64decode(token + padding))
        self.assertEqual(payload["format"], "server-kit-awg-enrollment-v1")
        self.assertNotIn("private_key", payload)
        self.assertNotIn("PRIVATE-MUST-STAY-LOCAL", json.dumps(payload))

    def test_local_x25519_matches_standard_implementation(self) -> None:
        script = (
            "globalThis.crypto=require('crypto').webcrypto;"
            f"require({json.dumps(str(self.root / 'awg.js'))});"
            "const k=serverKitAwg.generateKeyMaterial();"
            "console.log(JSON.stringify(k));"
        )
        completed = subprocess.run(
            ["node", "-e", script], check=True, capture_output=True, text=True
        )
        values = json.loads(completed.stdout)
        self.assertEqual(len(values["privateKey"]), 44)
        self.assertEqual(len(values["publicKey"]), 44)
        self.assertEqual(len(values["presharedKey"]), 44)

    def test_endpoint_migration_changes_only_host_and_keeps_private_material_local(self) -> None:
        awg_path = self.root / "awg.js"
        config = "[Interface]\nPrivateKey = PRIVATE\nAddress = 10.20.0.2/24\n\n[Peer]\nPresharedKey = PSK\nEndpoint = 203.0.113.10:8443\nAllowedIPs = 10.20.0.0/24\n"
        script = (
            f"require({json.dumps(str(awg_path))});"
            f"console.log(serverKitAwg.migrateEndpointHost({json.dumps(config)},'vpn.example.com'));"
        )
        completed = subprocess.run(["node", "-e", script], check=True, capture_output=True, text=True)
        expected = config.replace("Endpoint = 203.0.113.10:8443", "Endpoint = vpn.example.com:8443")
        self.assertEqual(completed.stdout, expected + "\n")
        popup = (self.root / "popup.js").read_text(encoding="utf-8")
        html = (self.root / "popup.html").read_text(encoding="utf-8")
        self.assertIn('id="endpoint-migration-form"', html)
        self.assertIn("serverKitAwg.migrateEndpointHost", popup)
        self.assertNotIn("savePendingBundle({ migrated", popup)

    def test_web_and_extension_awg_renderer_are_identical(self) -> None:
        web = Path(__file__).resolve().parents[1] / "web" / "static" / "awg.js"
        self.assertEqual(web.read_bytes(), (self.root / "awg.js").read_bytes())

    def test_vendored_qr_generator_is_pinned_and_mit_licensed(self) -> None:
        source = (self.root / "vendor" / "qrcode.js").read_text(encoding="utf-8")
        self.assertIn("Copyright (c) 2009 Kazuhiko Arase", source)
        self.assertIn("Licensed under the MIT license", source)
        self.assertNotIn("fetch(", source)
