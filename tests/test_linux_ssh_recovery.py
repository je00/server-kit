"""Run under Linux Bash; isolate every service/firewall mutation in mocks."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'web/dashboard/script_templates/server-kit-ssh-linux.sh'

HARNESS = r'''
set -Eeuo pipefail
source "$SOURCE"
PORT=22
MANAGED_CONFIG="$TEST_ROOT/managed"
MAIN_CONFIG="$TEST_ROOT/main"
AUTH_STATE_DIR="$TEST_ROOT/state"
AUTH_TRANSACTION="$TEST_ROOT/auth"
NETWORKS_FILE="$TEST_ROOT/networks"
FIREWALL_STATE="$TEST_ROOT/firewall"
UNIT_DIR="$TEST_ROOT/units"
SOCKET_CONFIG="$UNIT_DIR/ssh.socket.d/zz-server-kit.conf"
RECOVERY_SCRIPT="$TEST_ROOT/recovery"
SSHD_RUNTIME_DIR="$TEST_ROOT/run"
SSHD_BIN="$TEST_ROOT/sshd"
SYSTEMCTL_BIN=mock_systemctl
mkdir -p "$UNIT_DIR/ssh.socket.d" "$AUTH_STATE_DIR"
printf '# original main\n' > "$MAIN_CONFIG"
printf '192.0.2.0/24\n' > "$NETWORKS_FILE"
printf '192.0.2.10\n' > "$TEST_ROOT/ips"
printf '192.0.2.10:22\n' > "$TEST_ROOT/live"
printf 'active\n' > "$TEST_ROOT/service"
printf 'enabled\n' > "$TEST_ROOT/enabled"
require_root() { :; }
apt-get() { echo unexpected-apt >> "$TEST_ROOT/log"; return 99; }
managed_addresses() { cat "$TEST_ROOT/ips"; }
ss() { awk '{print "LISTEN 0 128 " $0 " 0.0.0.0:*"}' "$TEST_ROOT/live"; }
sleep() { :; }
mock_systemctl() {
  echo "$*" >> "$TEST_ROOT/log"
  local unit="${*: -1}"
  case "$1" in
    is-active)
      if [[ "$unit" == ssh ]]; then grep -q active "$TEST_ROOT/service"
      elif [[ "$unit" == ssh.socket ]]; then [[ -f "$TEST_ROOT/socket" ]]
      else return 1; fi
      return $? ;;
    is-enabled)
      if [[ "$unit" == ssh ]]; then grep -q enabled "$TEST_ROOT/enabled"
      elif [[ "$unit" == ssh.socket ]]; then [[ -f "$TEST_ROOT/socket" ]]
      else return 1; fi
      return $? ;;
    show) echo loaded ;;
    restart)
      if [[ "$unit" == ssh ]]; then
        if [[ -f "$TEST_ROOT/fail-restart" ]]; then rm "$TEST_ROOT/fail-restart"; return 1; fi
        echo active > "$TEST_ROOT/service"
        if [[ ! -f "$TEST_ROOT/bad-listener" ]]; then
          awk '$1 == "Port" {port=$2} $1 == "ListenAddress" {print $2 ":" port}' "$MANAGED_CONFIG" > "$TEST_ROOT/live"
        fi
      fi ;;
    enable) [[ "$unit" != ssh ]] || echo enabled > "$TEST_ROOT/enabled" ;;
    disable)
      if [[ "$unit" == ssh ]]; then : > "$TEST_ROOT/enabled"; : > "$TEST_ROOT/service"; fi
      if [[ "$unit" == ssh.socket ]]; then rm -f "$TEST_ROOT/socket"; fi ;;
  esac
  return 0
}
apply_managed_firewall() {
  echo add-firewall >> "$TEST_ROOT/log"
  if [[ -f "$TEST_ROOT/fail-firewall" ]]; then rm "$TEST_ROOT/fail-firewall"; return 1; fi
  cp "$1" "$TEST_ROOT/applied-firewall"
}
remove_firewall_rule() { echo remove-firewall >> "$TEST_ROOT/log"; }
install_network_recovery() {
  echo install-recovery >> "$TEST_ROOT/log"
  [[ ! -f "$TEST_ROOT/fail-timer" ]]
}
write_network_config > "$MANAGED_CONFIG"
cp "$MANAGED_CONFIG" "$TEST_ROOT/original"
case "$CASE" in
  noop) enable_ssh; ! grep -qE 'restart|unexpected-apt|firewall' "$TEST_ROOT/log" ;;
  socket)
    touch "$TEST_ROOT/socket"
    enable_ssh
    grep -Fxq 'ListenStream=192.0.2.10:22' "$SOCKET_CONFIG"
    grep -Fxq 'restart ssh.socket' "$TEST_ROOT/log"
    : > "$TEST_ROOT/log"
    enable_ssh
    ! grep -q restart "$TEST_ROOT/log" ;;
  recovery)
    ACTION=reconcile
    echo 192.0.2.11 > "$TEST_ROOT/ips"
    reconcile_network
    grep -Fxq 'ListenAddress 192.0.2.11' "$MANAGED_CONFIG"
    ! grep -q install-recovery "$TEST_ROOT/log" ;;
  disabled|auth|no-address)
    ACTION=reconcile
    case "$CASE" in
      disabled) : > "$TEST_ROOT/enabled" ;;
      auth) touch "$AUTH_TRANSACTION" ;;
      no-address) : > "$TEST_ROOT/ips" ;;
    esac
    reconcile_network
    cmp "$MANAGED_CONFIG" "$TEST_ROOT/original"
    ! grep -q restart "$TEST_ROOT/log" ;;
  restart-fail|firewall-fail|timer-fail|listener-fail|config-fail)
    echo 192.0.2.11 > "$TEST_ROOT/ips"
    case "$CASE" in
      restart-fail) touch "$TEST_ROOT/fail-restart" ;;
      firewall-fail) touch "$TEST_ROOT/fail-firewall" ;;
      timer-fail) touch "$TEST_ROOT/fail-timer" ;;
      listener-fail) touch "$TEST_ROOT/bad-listener" ;;
      config-fail) touch "$TEST_ROOT/fail-config" ;;
    esac
    set +e
    (set -e; enable_ssh)
    result=$?
    set -e
    ((result != 0))
    cmp "$MANAGED_CONFIG" "$TEST_ROOT/original"
    grep -Fxq '# original main' "$MAIN_CONFIG"
    [[ ! -f "$SOCKET_CONFIG" ]]
    if [[ "$CASE" == config-fail ]]; then
      ! grep -qE 'restart ssh|firewall' "$TEST_ROOT/log"
    else cmp "$TEST_ROOT/applied-firewall" "$TEST_ROOT/original"; fi ;;
  network-rollback)
    touch "$TEST_ROOT/fail-config"
    set +e
    (set -e; PORT=198.51.100.0/24; add_network)
    result=$?
    set -e
    ((result != 0))
    [[ "$(cat "$NETWORKS_FILE")" == 192.0.2.0/24 ]] ;;
  disable)
    touch "$TEST_ROOT/socket"
    disable_ssh
    grep -Fxq 'disable --now ssh.socket' "$TEST_ROOT/log"
    grep -Fxq 'disable --now server-kit-node-ssh-network-recovery.timer' "$TEST_ROOT/log"
    [[ ! -f "$TEST_ROOT/socket" ]]
    [[ ! -s "$TEST_ROOT/service" ]] ;;
esac
'''


@unittest.skipUnless(os.uname().sysname == 'Linux', 'requires Linux Bash and coreutils')
class LinuxRecoveryTests(unittest.TestCase):
    def test_firewall_helpers_only_change_managed_rules(self):
        script = r'''
set -Eeuo pipefail
source "$SOURCE"
MANAGED_CONFIG="$TEST_ROOT/config"
FIREWALL_STATE="$TEST_ROOT/state/rules"
printf '%s\n' 'Port 22' 'ListenAddress 192.0.2.10' 'Match Address *,!192.0.2.0/24' > "$MANAGED_CONFIG"
SYSTEMCTL_BIN=systemctl
systemctl() { [[ "$BACKEND" == firewalld ]]; }
firewall-cmd() { echo "$*" >> "$TEST_ROOT/firewalld-log"; }
ufw() {
  echo "$*" >> "$TEST_ROOT/ufw-log"
  if [[ "$1" == status ]]; then
    echo 'Status: active'
    if [[ "${2:-}" == numbered ]]; then
      [[ ! -f "$TEST_ROOT/ufw-rule" ]] || echo '[ 1] 22 ALLOW IN 192.0.2.0/24 # server-kit SSH allowed'
      echo '[ 2] 443 ALLOW IN Anywhere # unrelated'
    fi
  elif [[ "$1" == allow ]]; then touch "$TEST_ROOT/ufw-rule"
  elif [[ "$*" == '--force delete 1' ]]; then rm "$TEST_ROOT/ufw-rule"
  else return 99; fi
}
apply_managed_firewall "$MANAGED_CONFIG"
remove_firewall_rule
if [[ "$BACKEND" == firewalld ]]; then
  grep -q -- '--add-rich-rule=rule family=ipv4 source address=192.0.2.0/24 destination address=192.0.2.10 port port=22' "$TEST_ROOT/firewalld-log"
  grep -q -- '--remove-rich-rule=' "$TEST_ROOT/firewalld-log"
  ! grep -q -- '--reload' "$TEST_ROOT/firewalld-log"
else
  grep -Fxq -- '--force delete 1' "$TEST_ROOT/ufw-log"
  [[ ! -f "$TEST_ROOT/ufw-rule" ]]
fi
'''
        for backend in ('ufw', 'firewalld'):
            with self.subTest(backend=backend), tempfile.TemporaryDirectory() as directory:
                run = subprocess.run(['bash', '-c', script], capture_output=True, text=True,
                    env={**os.environ, 'SERVER_KIT_LIBRARY_ONLY': '1', 'SOURCE': str(SOURCE),
                         'TEST_ROOT': directory, 'BACKEND': backend})
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_real_entrypoint_and_generated_units(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binaries = root / 'bin'
            binaries.mkdir()
            (root / 'main').write_text('# test main\n')
            (root / 'networks').write_text('192.0.2.0/24\n')
            (root / 'live').write_text('')
            scripts = {
                'apt-get': 'exit 99\n',
                'sshd': 'if [[ "$1" == -T ]]; then echo "listenaddress 192.0.2.10:22"; fi\n',
                'ip': 'echo "2: eth0 inet 192.0.2.10/24 scope global eth0"\n',
                'ss': 'cat "$TEST_ROOT/live"\n',
                'ufw': 'echo "Status: inactive"\n',
                'firewall-cmd': 'exit 99\n',
                'systemctl': r'''
echo "$*" >> "$TEST_ROOT/calls"
case "$1" in
  is-active|is-enabled)
    [[ "${*: -1}" == ssh || "${*: -1}" == ssh.socket ]] ;;
  restart)
    if [[ "$2" == ssh ]]; then
      echo 'LISTEN 0 128 192.0.2.10:22 0.0.0.0:*' > "$TEST_ROOT/live"
    fi ;;
  *) exit 0 ;;
esac
''',
            }
            for name, script in scripts.items():
                path = binaries / name
                path.write_text('#!/bin/bash\n' + script)
                path.chmod(0o700)
            env = {**os.environ, 'TEST_ROOT': directory, 'SERVER_KIT_TESTING': '1',
                   'PATH': str(binaries) + ':' + os.environ['PATH'],
                   'SERVER_KIT_SSH_CONFIG': str(root / 'managed'),
                   'SERVER_KIT_SSH_MAIN_CONFIG': str(root / 'main'),
                   'SERVER_KIT_SSH_NETWORKS_FILE': str(root / 'networks'),
                   'SERVER_KIT_SSH_FIREWALL_STATE': str(root / 'state/firewall'),
                   'SERVER_KIT_SSH_AUTH_STATE_DIR': str(root / 'state'),
                   'SERVER_KIT_SSH_UNIT_DIR': str(root / 'units'),
                   'SERVER_KIT_SSH_RECOVERY_SCRIPT': str(root / 'lib/recovery.sh'),
                   'SERVER_KIT_SSHD_RUNTIME_DIR': str(root / 'run'),
                   'SERVER_KIT_SSHD_BIN': str(binaries / 'sshd')}
            for iteration in range(2):
                (root / 'calls').write_text('')
                run = subprocess.run(['bash', str(SOURCE), 'enable', '22'], env=env,
                                     text=True, capture_output=True)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                if iteration:
                    self.assertNotIn('restart ssh', (root / 'calls').read_text())
            self.assertEqual((root / 'lib/recovery.sh').read_bytes(), SOURCE.read_bytes())
            units = list((root / 'units').glob('*.service')) + list((root / 'units').glob('*.timer'))
            self.assertEqual(len(units), 2)
            if shutil.which('systemd-analyze'):
                check = subprocess.run(['systemd-analyze', 'verify', *map(str, units)],
                                       text=True, capture_output=True)
                self.assertEqual(check.returncode, 0, check.stdout + check.stderr)

    def test_recovery_transactions(self):
        for case in ('noop', 'socket', 'recovery', 'disabled', 'auth', 'no-address',
                     'restart-fail', 'firewall-fail', 'timer-fail', 'listener-fail',
                     'config-fail', 'network-rollback', 'disable'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                helper = Path(directory) / 'sshd'
                helper.write_text('#!/bin/sh\n[ ! -f "$TEST_ROOT/fail-config" ] || exit 1\n'
                                  'if [ "$1" = -T ]; then\n'
                                  'awk \'$1 == "Port" {p=$2} $1 == "ListenAddress" '
                                  '{print "listenaddress " $2 ":" p}\' "$TEST_ROOT/managed"\nfi\n')
                helper.chmod(0o700)
                result = subprocess.run(['bash', '-c', HARNESS], text=True, capture_output=True,
                    env={**os.environ, 'SOURCE': str(SOURCE), 'TEST_ROOT': directory,
                         'SERVER_KIT_LIBRARY_ONLY': '1', 'CASE': case})
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
