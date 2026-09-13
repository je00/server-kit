"""Read-only platform tests; no real services or firewall changes."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAC = ROOT / 'web/dashboard/script_templates/server-kit-ssh-macos.sh'


class MacRecoveryTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('zsh'), 'requires zsh')
    def test_network_recovery_and_noop(self):
        with tempfile.TemporaryDirectory() as directory:
            script = r'''
set -e
source "$SOURCE"
CONFIG="$TEST_ROOT/sshd_config"; PLIST="$TEST_ROOT/service.plist"
AUTH_TRANSACTION="$TEST_ROOT/transaction"
PORT=22
print -r -- 'Port 22
ListenAddress 192.0.2.10
Match Address *,!192.0.2.0/24
    DenyUsers *
Match all' > "$CONFIG"
touch "$PLIST"
ips=192.0.2.10; live=192.0.2.10; disabled=0
managed_addresses() { print -r -- "$ips"; }
allowed_networks() { print 192.0.2.0/24; }
lsof() { [[ -z "$live" ]] || print "sshd 1 root 3u IPv4 0 0t0 TCP $live:22 (LISTEN)"; }
launchctl() { ((disabled == 0)) || print '"com.server-kit.sshd" => true'; return 0; }
require_root() { }
install_network_recovery() { }
systemsetup() { print 'unexpected systemsetup' >&2; return 99; }
network_applied
enable_ssh
repairs=0
enable_ssh() { repairs=$((repairs+1)); }
reconcile_network
((repairs == 0))
live=''; reconcile_network
((repairs == 1))
ips=''; reconcile_network
((repairs == 1))
ips=192.0.2.11; disabled=1; reconcile_network
((repairs == 1))
disabled=0; touch "$AUTH_TRANSACTION"; reconcile_network
((repairs == 1))
print 'PASS: macOS no-op and network recovery guards'
'''
            result = subprocess.run(['zsh', '-c', script], capture_output=True, text=True,
                                    env={**os.environ, 'SERVER_KIT_LIBRARY_ONLY': '1',
                                         'SOURCE': str(MAC), 'TEST_ROOT': directory})
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_script_syntax(self):
        if not shutil.which('zsh'):
            self.skipTest('requires zsh')
        subprocess.run(['zsh', '-n', str(MAC)], check=True)


if __name__ == '__main__':
    unittest.main()
