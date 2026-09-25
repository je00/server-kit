#!/usr/bin/env bash
# In a private mount namespace, verify cold-boot /run preparation without touching SSH.
set -euo pipefail
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
MANAGER="${ROOT_DIR}/web/dashboard/script_templates/server-kit-ssh-linux.sh"
unshare --mount --propagation private bash -c '
  set -euo pipefail
  mount -t tmpfs tmpfs /run
  export SERVER_KIT_LIBRARY_ONLY=1
  source "$1"
  prepare_sshd_runtime_dir
  [[ -d /run/sshd ]]
  [[ "$(stat -c %U:%G:%a /run/sshd)" == "root:root:755" ]]
' _ "$MANAGER"
echo "通过：冷启动时会准备 /run/sshd；未修改 SSH 配置、服务或防火墙。"
