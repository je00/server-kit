#!/usr/bin/env bash
# server-kit Debian / Ubuntu 用户目录语言管理器
set -euo pipefail

declare -a USERDIR_TYPES=(DESKTOP DOWNLOAD TEMPLATES PUBLICSHARE DOCUMENTS MUSIC PICTURES VIDEOS)
declare -A USERDIR_ENGLISH=(
  [DESKTOP]="Desktop" [DOWNLOAD]="Downloads" [TEMPLATES]="Templates" [PUBLICSHARE]="Public"
  [DOCUMENTS]="Documents" [MUSIC]="Music" [PICTURES]="Pictures" [VIDEOS]="Videos"
)
declare -A USERDIR_CHINESE=(
  [DESKTOP]="桌面" [DOWNLOAD]="下载" [TEMPLATES]="模板" [PUBLICSHARE]="公共"
  [DOCUMENTS]="文档" [MUSIC]="音乐" [PICTURES]="图片" [VIDEOS]="视频"
)

TARGET_USER=""
TARGET_HOME=""
TARGET_GROUP=""

require_supported_system() {
  [[ -r /etc/os-release ]] || { echo "无法识别 Linux 发行版。" >&2; return 1; }
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "debian" || "${ID:-}" == "ubuntu" ]] || {
    echo "用户目录语言管理仅支持 Debian 和 Ubuntu。" >&2
    return 1
  }
}

resolve_target_user() {
  TARGET_USER="${SERVER_KIT_USERDIRS_USER:-${SUDO_USER:-${USER:-root}}}"
  id "$TARGET_USER" >/dev/null 2>&1 || { echo "目标用户不存在：$TARGET_USER" >&2; return 1; }
  TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
  TARGET_GROUP="$(id -gn "$TARGET_USER")"
  [[ -n "$TARGET_HOME" && "$TARGET_HOME" == /* && -d "$TARGET_HOME" ]] || {
    echo "无法确定目标用户的主目录：$TARGET_USER" >&2
    return 1
  }
}

safe_home_path() {
  local path="$1" canonical
  canonical="$(realpath -m -- "$path")"
  case "$canonical" in
    "$TARGET_HOME"|"$TARGET_HOME"/*) printf '%s\n' "$canonical" ;;
    *) echo "拒绝处理主目录以外的 XDG 路径：$path" >&2; return 1 ;;
  esac
}

configured_dir() {
  local kind="$1" config_file line value suffix fallback
  config_file="$TARGET_HOME/.config/user-dirs.dirs"
  line="$(grep -m1 -E "^XDG_${kind}_DIR=" "$config_file" 2>/dev/null || true)"
  if [[ -n "$line" ]]; then
    value="${line#*=}"
    value="${value#\"}"
    value="${value%\"}"
    case "$value" in
      '$HOME') safe_home_path "$TARGET_HOME"; return ;;
      '$HOME/'*)
        suffix="${value#\$HOME/}"
        safe_home_path "$TARGET_HOME/$suffix"
        return
        ;;
      /*) safe_home_path "$value"; return ;;
    esac
  fi
  fallback="$TARGET_HOME/${USERDIR_CHINESE[$kind]}"
  [[ -e "$fallback" ]] || fallback="$TARGET_HOME/${USERDIR_ENGLISH[$kind]}"
  safe_home_path "$fallback"
}

show_status() {
  local kind current target state
  require_supported_system
  resolve_target_user
  echo "用户目录状态"
  echo
  echo "用户：$TARGET_USER"
  echo "主目录：$TARGET_HOME"
  echo
  printf '  %-13s %-28s %s\n' "类型" "当前目录" "目标英文目录"
  for kind in "${USERDIR_TYPES[@]}"; do
    current="$(configured_dir "$kind")"
    target="$TARGET_HOME/${USERDIR_ENGLISH[$kind]}"
    state=""
    [[ "$current" == "$target" ]] && state="（已是英文）"
    printf '  %-13s %-28s %s%s\n' "$kind" "${current#$TARGET_HOME/}" "${target#$TARGET_HOME/}" "$state"
  done
}

append_plan_header() {
  local plan_file="$1"
  cat >"$plan_file" <<PLAN
#!/usr/bin/env bash
set -euo pipefail
(( EUID == 0 )) || { echo "请使用 sudo 执行用户目录变更。" >&2; exit 1; }
TARGET_USER=$(printf '%q' "$TARGET_USER")
TARGET_HOME=$(printf '%q' "$TARGET_HOME")
TARGET_GROUP=$(printf '%q' "$TARGET_GROUP")

# 安装 freedesktop.org 标准 XDG 用户目录工具（已安装时跳过）
if ! command -v xdg-user-dirs-update >/dev/null 2>&1; then
  apt-get update
  apt-get install -y xdg-user-dirs
fi

CONFIG_DIR="\$TARGET_HOME/.config"
CONFIG_FILE="\$CONFIG_DIR/user-dirs.dirs"
install -d -m 0755 -o "\$TARGET_USER" -g "\$TARGET_GROUP" "\$CONFIG_DIR"
if [[ -f "\$CONFIG_FILE" ]]; then
  cp -a -- "\$CONFIG_FILE" "\$CONFIG_FILE.server-kit.bak.\$(date +%Y%m%d%H%M%S)"
fi

run_as_target() {
  if [[ "\$TARGET_USER" == "root" ]]; then
    HOME="\$TARGET_HOME" "\$@"
  else
    runuser -u "\$TARGET_USER" -- env HOME="\$TARGET_HOME" "\$@"
  fi
}

migrate_dir() {
  local kind="\$1" source="\$2" target="\$3" item
  if [[ "\$source" != "\$TARGET_HOME" && "\$source" != "\$target" && -e "\$source" ]]; then
    if [[ ! -e "\$target" ]]; then
      mv -- "\$source" "\$target"
    elif [[ -d "\$source" && -d "\$target" ]]; then
      while IFS= read -r -d '' item; do
        # 不覆盖目标目录中的同名文件；冲突项继续留在原中文目录。
        mv -n -- "\$item" "\$target/"
      done < <(find "\$source" -mindepth 1 -maxdepth 1 -print0)
      rmdir -- "\$source" 2>/dev/null || echo "保留含冲突文件的旧目录：\$source"
    else
      echo "源目录或目标路径类型冲突：\$source -> \$target" >&2
      exit 1
    fi
  fi
  install -d -m 0755 -o "\$TARGET_USER" -g "\$TARGET_GROUP" "\$target"
  run_as_target xdg-user-dirs-update --set "\$kind" "\$target"
}
PLAN
}

build_plan() {
  local plan_file="$1" kind current target
  append_plan_header "$plan_file"
  {
    echo
    echo "# 迁移已有内容，并把 XDG 默认用户目录切换为英文"
  } >>"$plan_file"
  for kind in "${USERDIR_TYPES[@]}"; do
    current="$(configured_dir "$kind")"
    target="$(safe_home_path "$TARGET_HOME/${USERDIR_ENGLISH[$kind]}")"
    printf 'migrate_dir %q %q %q\n' "$kind" "$current" "$target" >>"$plan_file"
  done
  cat >>"$plan_file" <<'PLAN'
echo "用户目录已切换为英文；桌面文件管理器可能需要重新登录后才刷新名称。"
PLAN
  chmod 0700 "$plan_file"
}

show_plan() {
  local plan_file="$1"
  echo
  echo "即将执行以下命令"
  echo "说明：已有文件会迁移；不覆盖目标目录中的同名文件，冲突项保留在旧中文目录。"
  echo "────────────────────────────────────────"
  cat "$plan_file"
  echo "────────────────────────────────────────"
  echo
}

prepare_plan() {
  local plan_file="$1"
  require_supported_system
  resolve_target_user
  build_plan "$plan_file"
  show_plan "$plan_file"
}

preview_english() {
  local plan_file
  plan_file="$(mktemp)"
  if ! prepare_plan "$plan_file"; then
    rm -f "$plan_file"
    return 1
  fi
  rm -f "$plan_file"
  echo "这里只显示计划，没有执行变更。"
}

apply_english() {
  local confirm_option="${1:-}" plan_file confirmation operation_status
  [[ -z "$confirm_option" || "$confirm_option" == "--yes" ]] || {
    echo "仅支持确认参数 --yes。" >&2
    return 2
  }
  plan_file="$(mktemp)"
  if ! prepare_plan "$plan_file"; then
    rm -f "$plan_file"
    return 1
  fi
  if [[ "$confirm_option" == "--yes" ]]; then
    echo "已指定 --yes，跳过交互确认并执行以上计划。"
  else
    if ! read -r -p "输入 yes 确认执行：" confirmation; then
      rm -f "$plan_file"
      return 1
    fi
    if [[ "$confirmation" != "yes" ]]; then
      rm -f "$plan_file"
      echo "已取消，没有执行任何命令。"
      return 0
    fi
  fi
  set +e
  bash "$plan_file"
  operation_status=$?
  set -e
  rm -f "$plan_file"
  return "$operation_status"
}

show_menu() {
  local choice
  while true; do
    clear 2>/dev/null || true
    echo "server-kit · 用户目录语言管理"
    echo
    echo "  1. 查看当前用户目录"
    echo "  2. 切换为英文目录"
    echo "  0. 返回"
    echo
    read -r -p ">: " choice || return 0
    case "$choice" in
      1) show_status || true ;;
      2) apply_english || true ;;
      0) return 0 ;;
      *) echo "无效选项。" ;;
    esac
    echo
    read -r -p "按回车继续..." _ || true
  done
}

main() {
  local action="${1:-menu}" confirm_option="${2:-}"
  case "$action" in
    menu) show_menu ;;
    status) show_status ;;
    plan) preview_english ;;
    english) apply_english "$confirm_option" ;;
    *) echo "未知用户目录操作：$action" >&2; return 2 ;;
  esac
}

[[ "${SERVER_KIT_USERDIRS_LIBRARY_ONLY:-0}" == "1" ]] || main "$@"
