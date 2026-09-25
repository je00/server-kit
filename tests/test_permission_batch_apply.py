"""Local-only shell integration: mocked nft/systemctl, real policy render/commit."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RULES = [{"target": "desk", "network": "tcp", "ports": "443,8000-8002"},
         {"target": "vps", "network": "udp", "ports": "53"}]
POLICY = {"version": 1, "clients": {
    "phone": {"mode": "restricted", "enabled": True, "uuid": "11111111-1111-4111-8111-111111111111", "email": "server-kit-vless:phone", "allow": [
        {"target": "vps", "network": "tcp", "ports": [22, 9080], "ip": "10.20.0.1"},
    ]}, "desk": {"mode": "unrestricted", "enabled": True, "uuid": "22222222-2222-4222-8222-222222222222", "email": "server-kit-vless:desk", "allow": []},
}}

AWG_SCRIPT = r'''
source "$1/amneziawg-setup.sh"
SCRIPT_DIR="$1"
test_root="$2"
failure_mode="$3"
AWG_ACCESS_PATH="$test_root/active.json"
AWG_ACCESS_PENDING_PATH="$test_root/pending.json"
PEER_DB="$test_root/peers.tsv"
NFT_RULES_PATH="$test_root/rules.nft"
AWG_PRIMARY_PORT=443
AWG_BACKUP_PORT1=1848
AWG_BACKUP_PORT2=""
DRY_RUN=0
load_state() { :; }
ensure_layout() { :; }
record_audit() { :; }
green() { :; }
systemctl() { echo 'UNEXPECTED_SYSTEMCTL' >&2; return 99; }
awg() { echo 'UNEXPECTED_AWG_RESTART' >&2; return 99; }
apply_count=0
check_count=0
commit_count=0
python3() {
  if [[ "${@: -1}" == commit ]]; then
    commit_count=$((commit_count + 1))
    command python3 "$@" || return 1
    # Simulate a post-replace failure, not just a pre-write rejection.
    [[ "$failure_mode" != commit && "$failure_mode" != rollback ]] || return 1
    return 0
  fi
  command python3 "$@"
}
nft() {
  if [[ "$1" == --check ]]; then
    check_count=$((check_count + 1))
    [[ "$failure_mode" != check ]]
    return
  fi
  apply_count=$((apply_count + 1))
  [[ "$failure_mode" != apply || "$apply_count" != 1 ]] || return 1
  [[ "$failure_mode" != rollback || "$apply_count" != 2 ]] || return 1
  cp -- "$NFT_RULES_PATH" "$test_root/live.nft"
}
render_nft_rules "$AWG_ACCESS_PATH"
cp -- "$NFT_RULES_PATH" "$test_root/old.nft"
cp -- "$NFT_RULES_PATH" "$test_root/live.nft"
status=0
change_access_policy allow-batch phone || status=$?
printf 'counts:%s:%s:%s\n' "$check_count" "$apply_count" "$commit_count"
exit "$status"
'''

VLESS_SCRIPT = r'''
source "$1/debian_vless_manager.sh"
test_root="$2"
failure_mode="$3"
CONFIG_DIR="$test_root"
CONFIG_PATH="$test_root/config.json"
VLESS_ACCESS_PATH="$test_root/active.json"
VLESS_ACCESS_PENDING_PATH="$test_root/pending.json"
VLESS_ACCESS_HELPER="$1/lib/vless_access.py"
AWG_PEER_DB="$test_root/peers.tsv"
AWG_STATE_FILE="$test_root/state"
NODE_DOMAINS_PATH="$test_root/domains.json"
VLESS_SKIP_SSH_GATE=1
XRAY_BIN=mock_xray
ensure_vless_access_helper() { :; }
record_vless_access_apply() { :; }
install() { cp -- "${@: -2:1}" "${@: -1}"; }
mock_xray() {
  [[ "$failure_mode" != check ]] || return 1
  command python3 -m json.tool "${@: -1}" >/dev/null
}
restart_count=0
systemctl() {
  case "$1" in
    show) id -un ;;
    restart)
      restart_count=$((restart_count + 1))
      [[ "$failure_mode" != restart || "$restart_count" != 1 ]] || return 1
      [[ "$failure_mode" != rollback || "$restart_count" != 2 ]] || return 1
      cp -- "$CONFIG_PATH" "$test_root/live.json"
      ;;
    is-active) return 0 ;;
    *) echo UNEXPECTED_SYSTEMCTL >&2; return 99 ;;
  esac
}
python3() {
  command python3 "$@" || return 1
  if [[ "${@: -1}" == commit && ( "$failure_mode" == commit || "$failure_mode" == rollback ) ]]; then
    return 1
  fi
}
cp -- "$CONFIG_PATH" "$test_root/old.json"
cp -- "$CONFIG_PATH" "$test_root/live.json"
status=0
if vless_access_helper allow-batch phone; then
  apply_vless_access || status=$?
else
  status=$?
fi
printf 'restarts:%s\n' "$restart_count"
exit "$status"
'''


class BatchApplyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.active = self.root / "active.json"
        self.active.write_text(json.dumps(POLICY))
        self.before = self.active.read_bytes()
        (self.root / "peers.tsv").write_text("phone\t10.20.0.2\ndesk\t10.20.0.3\n")
        (self.root / "state").write_text("AWG_SERVER_IP=10.20.0.1\n")
        (self.root / "config.json").write_text(json.dumps({
            "inbounds": [{"tag": "vless-public", "protocol": "vless", "settings": {"clients": []}}],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}],
            "routing": {"rules": []},
        }))

    def run_script(self, script, mode="success", rules=RULES):
        result = subprocess.run(["bash", "-c", script, "batch-test", str(ROOT), str(self.root), mode],
            input=json.dumps(rules), text=True, capture_output=True, timeout=20,
            env={**os.environ, "PATH": f"{Path(sys.executable).parent}{os.pathsep}{os.environ.get('PATH', '')}"})
        self.assertNotIn("UNEXPECTED", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        return result

    def test_awg_success_applies_all_once_without_interface_restart(self):
        result = self.run_script(AWG_SCRIPT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("counts:1:1:1", result.stdout)
        policy = json.loads(self.active.read_text())
        self.assertEqual(policy["clients"]["phone"]["allow"][0], POLICY["clients"]["phone"]["allow"][0])
        self.assertEqual(len(policy["clients"]["phone"]["allow"]), 3)
        self.assertFalse((self.root / "pending.json").exists())

    def test_awg_failed_final_row_has_no_live_or_persisted_changes(self):
        result = self.run_script(AWG_SCRIPT, rules=[RULES[0], {**RULES[1], "target": "missing"}])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("counts:0:0:0", result.stdout)
        self.assertEqual(self.active.read_bytes(), self.before)
        self.assertFalse((self.root / "pending.json").exists())

    def test_awg_check_apply_and_post_commit_failures_restore_policy_and_live_rules(self):
        for mode in ("check", "apply", "commit"):
            with self.subTest(mode=mode):
                result = self.run_script(AWG_SCRIPT, mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("已恢复原策略", result.stderr)
                self.assertEqual(self.active.read_bytes(), self.before)
                self.assertEqual((self.root / "live.nft").read_bytes(), (self.root / "old.nft").read_bytes())
                self.assertFalse((self.root / "pending.json").exists())
                self.assertEqual(list(self.root.glob("active.json.backup.*")), [])

    def test_awg_failed_rollback_keeps_backup_and_reports_uncertainty(self):
        result = self.run_script(AWG_SCRIPT, "rollback")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("需要人工核验", result.stderr)
        self.assertNotIn("已恢复原策略", result.stderr)
        self.assertEqual(self.active.read_bytes(), self.before)
        self.assertEqual(len(list(self.root.glob("active.json.backup.*"))), 1)

    def test_awg_existing_pending_policy_is_not_applied_or_changed(self):
        pending = self.root / "pending.json"
        pending.write_text('{"reserved":true}')
        result = self.run_script(AWG_SCRIPT)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("counts:0:0:0", result.stdout)
        self.assertEqual(self.active.read_bytes(), self.before)
        self.assertEqual(pending.read_text(), '{"reserved":true}')

    def test_vless_all_rows_one_restart_with_preserved_management_rule(self):
        result = self.run_script(VLESS_SCRIPT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("restarts:1", result.stdout)
        policy = json.loads(self.active.read_text())
        self.assertEqual(policy["clients"]["phone"]["allow"][0], POLICY["clients"]["phone"]["allow"][0])
        self.assertEqual(len(policy["clients"]["phone"]["allow"]), 3)

    def test_vless_bad_final_row_and_bad_xray_check_do_not_restart(self):
        for mode, rules in (("success", [RULES[0], {**RULES[1], "target": "missing"}]), ("check", RULES)):
            with self.subTest(mode=mode):
                result = self.run_script(VLESS_SCRIPT, mode, rules)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("restarts:0", result.stdout)
                self.assertEqual(self.active.read_bytes(), self.before)
                self.assertEqual((self.root / "live.json").read_bytes(), (self.root / "old.json").read_bytes())

    def test_vless_restart_and_post_commit_failure_restore_active_and_live(self):
        for mode in ("restart", "commit"):
            with self.subTest(mode=mode):
                (self.root / "pending.json").unlink(missing_ok=True)
                result = self.run_script(VLESS_SCRIPT, mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("restarts:2", result.stdout)
                self.assertEqual(self.active.read_bytes(), self.before)
                self.assertEqual((self.root / "live.json").read_bytes(), (self.root / "old.json").read_bytes())

    def test_vless_failed_rollback_preserves_policy_backup(self):
        result = self.run_script(VLESS_SCRIPT, "rollback")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("需要人工核验", result.stderr)
        self.assertNotIn("已恢复旧 Xray", result.stderr)
        self.assertEqual(self.active.read_bytes(), self.before)
        self.assertEqual(len(list(self.root.glob("active.json.backup.*"))), 1)


if __name__ == "__main__":
    unittest.main()
