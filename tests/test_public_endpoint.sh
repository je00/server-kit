#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary="$(mktemp -d)"
trap 'rm -rf -- "${temporary}"' EXIT

config="${temporary}/public-endpoint.json"
transaction_dir="${temporary}/transaction"
outcome="${temporary}/outcome.json"
clash_config="${temporary}/clash-config.json"
file_config="${temporary}/file-config.json"
certificate="${temporary}/server.crt"
key="${temporary}/server.key"
certificate_fact="${temporary}/certificate-ip"
file_data="${temporary}/data"
fake_file_manager="${temporary}/file-manager"
fake_systemctl="${temporary}/systemctl"
fake_systemd_run="${temporary}/systemd-run"
refresh_log="${temporary}/refresh.log"
scheduler_log="${temporary}/scheduler.log"
fail_reconcile="${temporary}/fail-reconcile"
mkdir -p "${file_data}/clash-subscriptions"
printf '{}\n' >"${clash_config}"
printf '{"server_address":"203.0.113.10"}\n' >"${file_config}"
printf 'certificate:203.0.113.10\n' >"${certificate}"
printf 'key:203.0.113.10\n' >"${key}"
printf '203.0.113.10\n' >"${certificate_fact}"
printf 'old publication\n' >"${file_data}/clash-subscriptions/client.yaml"

cat >"${fake_file_manager}" <<'EOF'
#!/usr/bin/env bash
[[ "$1" == "reconcile-public-ip" && "${2:-}" == "--yes" ]] || exit 2
current="$(python3 - "${PUBLIC_ENDPOINT_CONFIG}" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
if not path.exists():
    print("203.0.113.10")
else:
    print(json.loads(path.read_text(encoding="utf-8"))["fqdn"])
PY
)"
configured="$(python3 - "${FILE_CONFIG_PATH}" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
print(json.loads(path.read_text(encoding="utf-8")).get("server_address", "") if path.exists() else "")
PY
)"
if [[ "${configured}" != "${current}" || "$(tr -d '\r\n' <"${CERT_IP_PATH}" 2>/dev/null || true)" != "${current}" ]]; then
  if [[ -e "${CLASH_CONFIG_PATH}" ]]; then
    printf 'new publication for %s\n' "${current}" >"${FILE_DATA_DIR}/clash-subscriptions/client.yaml"
    printf '{"server_address":"%s","endpoint":"new"}\n' "${current}" >"${CLASH_CONFIG_PATH}"
  fi
  [[ ! -e "${FILE_CONFIG_PATH}" ]] || printf '{"server_address":"%s"}\n' "${current}" >"${FILE_CONFIG_PATH}"
  printf 'certificate:%s\n' "${current}" >"${CERT_PATH}"
  printf 'key:%s\n' "${current}" >"${KEY_PATH}"
  printf '%s\n' "${current}" >"${CERT_IP_PATH}"
  printf 'reconcile:%s\n' "${current}" >>"${SERVER_KIT_REFRESH_LOG}"
  [[ ! -e "${SERVER_KIT_FAIL_RECONCILE_FILE}" ]] || exit 1
else
  printf 'automation:%s\n' "${current}" >>"${SERVER_KIT_REFRESH_LOG}"
fi
EOF
cat >"${fake_systemctl}" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "restart" && -e "${SERVER_KIT_FAIL_RESTART_FILE}" ]]; then exit 1; fi
exit 0
EOF
cat >"${fake_systemd_run}" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${SERVER_KIT_SCHEDULER_LOG}"
[[ ! -e "${SERVER_KIT_FAIL_SCHEDULE_FILE}" ]]
EOF
chmod +x "${fake_file_manager}" "${fake_systemctl}" "${fake_systemd_run}"

export DRY_RUN=1 SERVER_KIT_TESTING=1 SERVER_KIT_CONTROL=1 SERVER_KIT_NETWORK_WRITES=1
export MANAGEMENT_LOCK_PATH="${temporary}/management.lock"
export PUBLIC_ENDPOINT_PATH="${config}" PUBLIC_ENDPOINT_TRANSACTION_DIR="${transaction_dir}"
export PUBLIC_ENDPOINT_OUTCOME_PATH="${outcome}" CLASH_CONFIG="${clash_config}"
export FILE_DATA_DIR="${file_data}" FILE_MANAGER="${fake_file_manager}"
export FILE_CONFIG="${file_config}" PUBLICATION_CERT_PATH="${certificate}"
export PUBLICATION_KEY_PATH="${key}" PUBLICATION_CERT_FACT_PATH="${certificate_fact}"
export SYSTEMCTL_BIN="${fake_systemctl}" SERVER_KIT_REFRESH_LOG="${refresh_log}"
export SYSTEMD_RUN_BIN="${fake_systemd_run}" SERVER_KIT_SCHEDULER_LOG="${scheduler_log}"
export SERVER_KIT_FAIL_SCHEDULE_FILE="${temporary}/fail-schedule"
export SERVER_KIT_FAIL_RESTART_FILE="${temporary}/fail-restart"
export SERVER_KIT_FAIL_RECONCILE_FILE="${fail_reconcile}"
origin="$(printf 'a%.0s' {1..64})"
independent="$(printf 'b%.0s' {1..64})"
request() {
  local fqdn="$1" session="$2"
  local transaction_id=""
  if [[ -r "${transaction_dir}/metadata.json" ]]; then
    transaction_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8")).get("transaction_id", ""))' "${transaction_dir}/metadata.json")"
  fi
  printf '{"fqdn":"%s","session_id":"%s","actor":"owner","transaction_id":"%s"}\n' "$fqdn" "$session" "$transaction_id"
}

# A direct legacy mutation must not bypass the rollback-window transaction.
if bash "${repo_dir}/server-kit-manager.sh" network public-endpoint set bypass.example.com --json >/dev/null 2>&1; then
  echo "legacy endpoint mutation bypassed transaction" >&2
  exit 1
fi

# User-facing transaction operations still require the web-control guards.
for guarded_operation in transaction-status apply confirm rollback; do
  if request guarded.example.com "$origin" | env -u SERVER_KIT_CONTROL -u SERVER_KIT_NETWORK_WRITES \
      bash "${repo_dir}/server-kit-manager.sh" network public-endpoint "${guarded_operation}" --json >/dev/null 2>&1; then
    echo "${guarded_operation} bypassed web-control guards" >&2
    exit 1
  fi
done

# A corrupt public fact must remain repairable through the same publication
# transaction used by the control plane. Status may surface it as unconfigured,
# but it must not abort before apply or clear can replace it.
printf '{not-json\n' >"${config}"
corrupt_status="$(request '' "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint transaction-status --json)"
python3 - "$corrupt_status" <<'PY'
import json, sys
value = json.loads(sys.argv[1])
assert value["state"] == "idle"
assert value["fqdn"] == ""
PY
repair="$(request repair.example.com "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint apply --json)"
python3 - "$repair" "$config" <<'PY'
import json, sys
response = json.loads(sys.argv[1])
assert response["state"] == "pending"
assert response["fqdn"] == "repair.example.com"
assert response["subscriptions_refreshed"] is True
assert json.load(open(sys.argv[2], encoding="utf-8"))["fqdn"] == "repair.example.com"
PY
request '' "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint rollback --json >/dev/null
grep -Fqx '{not-json' "${config}"
request '' "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint apply --json >/dev/null
request '' "$independent" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint confirm --json >/dev/null
[[ ! -e "${config}" ]]
printf 'old publication\n' >"${file_data}/clash-subscriptions/client.yaml"

# Apply writes the fact and publications, then remains pending.
apply="$(request vpn.example.com "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint apply --json)"
python3 - "$apply" <<'PY'
import json, sys
value = json.loads(sys.argv[1])
assert value["operation"] == "apply"
assert value["state"] == "pending"
assert len(value["transaction_id"]) == 64
assert set(value["transaction_id"]) <= set("0123456789abcdef")
assert value["fqdn"] == "vpn.example.com"
assert value["subscriptions_refreshed"] is True
assert value["independent_session"] is False
assert value["remaining_seconds"] > 0
PY
transaction_id="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["transaction_id"])' "$apply")"
[[ "$(stat -c '%a' "$config")" == "600" ]]
[[ "$(cat "${file_data}/clash-subscriptions/client.yaml")" == "new publication for vpn.example.com" ]]
grep -Fq '"server_address":"vpn.example.com"' "${clash_config}"
grep -Fq '"server_address":"vpn.example.com"' "${file_config}"
grep -Fqx 'certificate:vpn.example.com' "${certificate}"
grep -Fqx 'key:vpn.example.com' "${key}"
grep -Fqx 'vpn.example.com' "${certificate_fact}"
[[ -r "${transaction_dir}/metadata.json" ]]
grep -F -- "--unit=server-kit-public-endpoint-rollback --on-active=300s --timer-property=AccuracySec=1s --property=Restart=on-failure --property=RestartSec=10s ${repo_dir}/server-kit-manager.sh network public-endpoint automatic-rollback --json" "${scheduler_log}" >/dev/null

# Persist terminal outcomes before deleting transaction metadata, otherwise a
# crash can leave the task engine waiting forever without an outcome to read.
python3 - "${repo_dir}/server-kit-manager.sh" <<'PY'
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
restore = text.split("public_endpoint_restore() {", 1)[1].split("public_endpoint_render_transaction() {", 1)[0]
confirm = text.split('if [[ "${operation}" == "confirm" ]]', 1)[1].split('if [[ "${operation}" == "rollback"', 1)[0]
assert restore.index("public_endpoint_write_outcome") < restore.index("public_endpoint_remove_transaction")
assert confirm.index("public_endpoint_write_outcome confirmed") < confirm.index("public_endpoint_remove_transaction")
PY

# The originating login cannot commit the endpoint.
if request '' "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint confirm --json >/dev/null 2>&1; then
  echo "originating session confirmed endpoint" >&2
  exit 1
fi

# A confirm request is bound to the exact pending transaction.
if printf '{"fqdn":"","session_id":"%s","actor":"owner","transaction_id":"%064d"}\n' "$independent" 0 |
    bash "${repo_dir}/server-kit-manager.sh" network public-endpoint confirm --json >/dev/null 2>&1; then
  echo "confirmation accepted a stale transaction identity" >&2
  exit 1
fi

# Manual rollback restores both the old fact absence and old publications.
rollback="$(request '' "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint rollback --json)"
python3 - "$rollback" "$transaction_id" <<'PY'
import json, sys
value = json.loads(sys.argv[1])
assert value["state"] == "idle"
assert value["last_outcome"] == "rolled_back"
assert value["transaction_id"] == sys.argv[2]
assert value["fqdn"] == ""
PY
[[ ! -e "$config" ]]
[[ "$(cat "${file_data}/clash-subscriptions/client.yaml")" == "old publication" ]]
grep -Fq '"server_address":"203.0.113.10"' "${file_config}"
grep -Fqx 'certificate:203.0.113.10' "${certificate}"
grep -Fqx 'key:203.0.113.10' "${key}"
grep -Fqx '203.0.113.10' "${certificate_fact}"
[[ ! -e "$transaction_dir" ]]

# Manual rollback is restricted to the currently pending transaction.
if request '' "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint rollback --json >/dev/null 2>&1; then
  echo "manual rollback succeeded without a pending transaction" >&2
  exit 1
fi

# Re-apply and confirm from an independent login; confirmation cleans artifacts.
printf 'old publication\n' >"${file_data}/clash-subscriptions/client.yaml"
request edge.example.com "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint apply --json >/dev/null
if request '' "$independent" | SERVER_KIT_TEST_FAILPOINT=public_endpoint_confirm_after_commit \
    bash "${repo_dir}/server-kit-manager.sh" network public-endpoint confirm --json >/dev/null 2>&1; then
  echo "confirmation crash failpoint did not interrupt after durable commit" >&2
  exit 1
fi
committed_status="$(request '' "$independent" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint transaction-status --json)"
python3 - "$committed_status" <<'PY'
import json, sys
value = json.loads(sys.argv[1])
assert value["state"] == "idle"
assert value["last_outcome"] == "confirmed"
assert value["fqdn"] == "edge.example.com"
PY
[[ ! -e "$transaction_dir" ]]
env -u SERVER_KIT_CONTROL -u SERVER_KIT_NETWORK_WRITES \
  bash "${repo_dir}/server-kit-manager.sh" network public-endpoint automatic-rollback --json </dev/null >/dev/null
python3 - "$config" "$outcome" <<'PY'
import json, sys
assert json.load(open(sys.argv[1], encoding="utf-8"))["fqdn"] == "edge.example.com"
assert json.load(open(sys.argv[2], encoding="utf-8"))["last_outcome"] == "confirmed"
PY

request edge.example.com "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint apply --json >/dev/null
confirm="$(request '' "$independent" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint confirm --json)"
python3 - "$confirm" <<'PY'
import json, sys
value = json.loads(sys.argv[1])
assert value["state"] == "idle"
assert value["last_outcome"] == "confirmed"
assert value["fqdn"] == "edge.example.com"
PY
[[ ! -e "$transaction_dir" ]]

# A timer process racing after confirmation must be a strict no-op: it cannot
# overwrite the committed outcome after transaction artifacts are gone.
env -u SERVER_KIT_CONTROL -u SERVER_KIT_NETWORK_WRITES \
  bash "${repo_dir}/server-kit-manager.sh" network public-endpoint automatic-rollback --json </dev/null >/dev/null
python3 - "$config" "$outcome" <<'PY'
import json, sys
assert json.load(open(sys.argv[1], encoding="utf-8"))["fqdn"] == "edge.example.com"
assert json.load(open(sys.argv[2], encoding="utf-8"))["last_outcome"] == "confirmed"
PY

# Confirmation at or after the durable expiry is rejected and converges through rollback.
request expired.example.com "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint apply --json >/dev/null
python3 - "${transaction_dir}/metadata.json" <<'PY'
import json, os, sys
path = sys.argv[1]
with open(path, encoding="utf-8") as source: value = json.load(source)
value["expires_epoch"] = 0
with open(path, "w", encoding="utf-8") as output: json.dump(value, output)
os.chmod(path, 0o600)
PY
if request '' "$independent" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint confirm --json >/dev/null 2>&1; then
  echo "expired endpoint transaction was confirmed" >&2
  exit 1
fi
python3 - "$config" "$outcome" <<'PY'
import json, sys
assert json.load(open(sys.argv[1], encoding="utf-8"))["fqdn"] == "edge.example.com"
assert json.load(open(sys.argv[2], encoding="utf-8"))["last_outcome"] == "automatic_rollback"
PY

# After a host restart the transient timer may no longer exist. A status read
# must converge an expired durable transaction through the same rollback path.
request reboot-expired.example.com "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint apply --json >/dev/null
python3 - "${transaction_dir}/metadata.json" <<'PY'
import json, os, sys
path = sys.argv[1]
with open(path, encoding="utf-8") as source: value = json.load(source)
value["expires_epoch"] = 0
with open(path, "w", encoding="utf-8") as output: json.dump(value, output)
os.chmod(path, 0o600)
PY
expired_status="$(request '' "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint transaction-status --json)"
python3 - "$expired_status" <<'PY'
import json, sys
value = json.loads(sys.argv[1])
assert value["state"] == "idle"
assert value["last_outcome"] == "automatic_rollback"
assert value["fqdn"] == "edge.example.com"
PY
[[ ! -e "$transaction_dir" ]]

# The transient service can roll back without web-control environment or stdin.
request auto.example.com "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint apply --json >/dev/null
env -u SERVER_KIT_CONTROL -u SERVER_KIT_NETWORK_WRITES bash "${repo_dir}/server-kit-manager.sh" network public-endpoint automatic-rollback --json </dev/null >/dev/null
[[ ! -e "$transaction_dir" ]]
python3 - "$config" "$outcome" <<'PY'
import json, sys
assert json.load(open(sys.argv[1], encoding="utf-8"))["fqdn"] == "edge.example.com"
assert json.load(open(sys.argv[2], encoding="utf-8"))["last_outcome"] == "automatic_rollback"
PY
if printf 'unexpected\n' | env -u SERVER_KIT_CONTROL -u SERVER_KIT_NETWORK_WRITES bash "${repo_dir}/server-kit-manager.sh" network public-endpoint automatic-rollback --json >/dev/null 2>&1; then
  echo "automatic rollback accepted stdin" >&2
  exit 1
fi

# Failure to schedule the timer fails apply and restores all changed state.
cp -a "$config" "${temporary}/before-failed-schedule-endpoint.json"
cp -a "$clash_config" "${temporary}/before-failed-schedule-clash.json"
cp -a "${file_data}/clash-subscriptions" "${temporary}/before-failed-schedule-subscriptions"
touch "${SERVER_KIT_FAIL_SCHEDULE_FILE}"
if request failed.example.com "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint apply --json >/dev/null 2>&1; then
  echo "apply succeeded without a rollback timer" >&2
  exit 1
fi
rm -f "${SERVER_KIT_FAIL_SCHEDULE_FILE}"
cmp -s "$config" "${temporary}/before-failed-schedule-endpoint.json"
cmp -s "$clash_config" "${temporary}/before-failed-schedule-clash.json"
diff -qr "${file_data}/clash-subscriptions" "${temporary}/before-failed-schedule-subscriptions" >/dev/null
[[ ! -e "$transaction_dir" ]]

# A partial certificate/publication migration failure restores every linked
# artifact, not only the endpoint fact and Clash payload.
cp -a "$config" "${temporary}/before-failed-reconcile-endpoint.json"
cp -a "$clash_config" "${temporary}/before-failed-reconcile-clash.json"
cp -a "$file_config" "${temporary}/before-failed-reconcile-file.json"
cp -a "$certificate" "${temporary}/before-failed-reconcile-certificate"
cp -a "$key" "${temporary}/before-failed-reconcile-key"
cp -a "$certificate_fact" "${temporary}/before-failed-reconcile-certificate-fact"
cp -a "${file_data}/clash-subscriptions" "${temporary}/before-failed-reconcile-subscriptions"
touch "${fail_reconcile}"
if request partial-link.example.com "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint apply --json >/dev/null 2>&1; then
  echo "apply succeeded after a partial linked publication migration failure" >&2
  exit 1
fi
rm -f "${fail_reconcile}"
cmp -s "$config" "${temporary}/before-failed-reconcile-endpoint.json"
cmp -s "$clash_config" "${temporary}/before-failed-reconcile-clash.json"
cmp -s "$file_config" "${temporary}/before-failed-reconcile-file.json"
cmp -s "$certificate" "${temporary}/before-failed-reconcile-certificate"
cmp -s "$key" "${temporary}/before-failed-reconcile-key"
cmp -s "$certificate_fact" "${temporary}/before-failed-reconcile-certificate-fact"
diff -qr "${file_data}/clash-subscriptions" "${temporary}/before-failed-reconcile-subscriptions" >/dev/null
[[ ! -e "$transaction_dir" ]]

# Backups and durable metadata must exist before the timer, and the timer must
# exist before endpoint/publication mutation.
python3 - "${repo_dir}/server-kit-manager.sh" <<'PY'
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
apply = text.split('[[ ! -e "${metadata}" ]]', 1)[1]
schedule = apply.find('"${SYSTEMD_RUN_BIN}" --quiet')
metadata = apply.find('os.replace(tmp,path)')
mutation = apply.find('python3 "${PUBLIC_ENDPOINT_HELPER}" set')
refresh = apply.find('bash "${FILE_MANAGER}" reconcile-public-ip --yes')
assert min(schedule, metadata, mutation, refresh) >= 0, (metadata, schedule, mutation, refresh)
assert metadata < schedule < mutation < refresh
PY

# A Clash restart failure keeps the transaction and backups retryable.
printf 'old publication\n' >"${file_data}/clash-subscriptions/client.yaml"
request crash-restore.example.com "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint apply --json >/dev/null
if request '' "$origin" | SERVER_KIT_TEST_FAILPOINT=public_endpoint_restore_after_displace \
    bash "${repo_dir}/server-kit-manager.sh" network public-endpoint rollback --json >/dev/null 2>&1; then
  echo "Clash restore crash failpoint did not interrupt after displacement" >&2
  exit 1
fi
[[ -r "${transaction_dir}/metadata.json" ]]
[[ -d "${transaction_dir}/clash-subscriptions.backup" ]]
request '' "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint rollback --json >/dev/null
[[ "$(cat "${file_data}/clash-subscriptions/client.yaml")" == "old publication" ]]
[[ ! -e "$transaction_dir" ]]

# If a power loss makes the parent-directory rename non-durable, a retry may
# see a live new publication beside the saved displaced directory. It must
# re-publish the trusted backup instead of merely reporting an inconsistency.
printf 'old publication\n' >"${file_data}/clash-subscriptions/client.yaml"
request retry-live.example.com "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint apply --json >/dev/null
if request '' "$origin" | SERVER_KIT_TEST_FAILPOINT=public_endpoint_restore_after_displace \
    bash "${repo_dir}/server-kit-manager.sh" network public-endpoint rollback --json >/dev/null 2>&1; then
  echo "restore retry setup did not stop after displacement" >&2
  exit 1
fi
mkdir -p "${file_data}/clash-subscriptions"
printf 'new publication after simulated reboot\n' >"${file_data}/clash-subscriptions/client.yaml"
request '' "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint rollback --json >/dev/null
[[ "$(cat "${file_data}/clash-subscriptions/client.yaml")" == "old publication" ]]
[[ ! -e "$transaction_dir" ]]

request retry.example.com "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint apply --json >/dev/null
rm -f "$outcome"
touch "${SERVER_KIT_FAIL_RESTART_FILE}"
if request '' "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint rollback --json >/dev/null 2>&1; then
  echo "rollback succeeded despite Clash restart failure" >&2
  exit 1
fi
[[ -r "${transaction_dir}/metadata.json" ]]
[[ -r "${transaction_dir}/clash-config.backup" ]]
[[ -d "${transaction_dir}/clash-subscriptions.backup" ]]
[[ ! -e "$outcome" ]]
rm -f "${SERVER_KIT_FAIL_RESTART_FILE}"
request '' "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint rollback --json >/dev/null
[[ ! -e "$transaction_dir" ]]

# A partial Clash backup is indeterminate: retain every artifact until a complete retry.
printf 'old publication\n' >"${file_data}/clash-subscriptions/client.yaml"
request partial-backup.example.com "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint apply --json >/dev/null
mv "${transaction_dir}/clash-config.backup" "${temporary}/held-clash-config.backup"
rm -f "$outcome"
if request '' "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint rollback --json >/dev/null 2>&1; then
  echo "rollback silently accepted a partial Clash backup" >&2
  exit 1
fi
[[ -r "${transaction_dir}/metadata.json" ]]
[[ -d "${transaction_dir}/clash-subscriptions.backup" ]]
[[ ! -e "$outcome" ]]
mv "${temporary}/held-clash-config.backup" "${transaction_dir}/clash-config.backup"
request '' "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint rollback --json >/dev/null
[[ ! -e "$transaction_dir" ]]

# Existing backup paths are insufficient: content digests must detect truncation
# before rollback can publish a terminal success outcome.
printf 'old publication\n' >"${file_data}/clash-subscriptions/client.yaml"
request corrupt-backup.example.com "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint apply --json >/dev/null
cp -a "${transaction_dir}/clash-config.backup" "${temporary}/intact-clash-config.backup"
printf '{"truncated":true}\n' >"${transaction_dir}/clash-config.backup"
rm -f "$outcome"
if request '' "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint rollback --json >/dev/null 2>&1; then
  echo "rollback accepted corrupted Clash backup content" >&2
  exit 1
fi
[[ -r "${transaction_dir}/metadata.json" ]]
[[ ! -e "$outcome" ]]
mv "${temporary}/intact-clash-config.backup" "${transaction_dir}/clash-config.backup"
request '' "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint rollback --json >/dev/null
[[ ! -e "$transaction_dir" ]]

# An incomplete Clash publication layer must fail before changing endpoint facts.
cp -a "$config" "${temporary}/before-missing-publication-endpoint.json"
rm -rf "${file_data}/clash-subscriptions"
if request incomplete.example.com "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint apply --json >/dev/null 2>&1; then
  echo "apply accepted an incomplete Clash publication layer" >&2
  exit 1
fi
cmp -s "$config" "${temporary}/before-missing-publication-endpoint.json"
[[ ! -e "$transaction_dir" ]]
mkdir -p "${file_data}/clash-subscriptions"
printf 'old publication\n' >"${file_data}/clash-subscriptions/client.yaml"

# No Clash installation is valid and still rollback-protected.
rm -f "$clash_config"
rm -rf "$transaction_dir"
request '' "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint apply --json >/dev/null
[[ ! -e "$config" ]]
request '' "$origin" | bash "${repo_dir}/server-kit-manager.sh" network public-endpoint rollback --json >/dev/null
[[ -r "$config" ]]
python3 - "$config" <<'PY'
import json, sys
assert json.load(open(sys.argv[1], encoding="utf-8"))["fqdn"] == "edge.example.com"
PY

echo "通过：稳定公网入口、HTTPS 证书和发布链接联动回滚事务。"
