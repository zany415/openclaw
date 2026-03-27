# Started by Cursor ubuntu 20260327074132903
# Started by Cursor ubuntu 20260327075826608
# Android 端部分 sh（尤其被 CRLF 污染时）会在 set 选项解析上异常，启动阶段不启用 set -u，改用显式参数与变量校验确保健壮性。
# Ended by Cursor ubuntu 20260327075826608

SCRIPT_NAME="openclaw-android-security-check.sh"
VERSION="2026.03.27"

CRITICAL_COUNT=0
WARN_COUNT=0
INFO_COUNT=0
OK_COUNT=0

HAS_JQ=0
JQ_MODE=0

print_usage() {
  echo "用法: sh ${SCRIPT_NAME} <openclaw.json 路径>"
  echo "示例: sh ${SCRIPT_NAME} /sdcard/openclaw/openclaw.json"
  echo "退出码: 0=通过, 1=仅警告, 2=存在高危"
}

log_critical() {
  CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
  echo "[CRITICAL] $1"
}

log_warn() {
  WARN_COUNT=$((WARN_COUNT + 1))
  echo "[WARN] $1"
}

log_info() {
  INFO_COUNT=$((INFO_COUNT + 1))
  echo "[INFO] $1"
}

log_ok() {
  OK_COUNT=$((OK_COUNT + 1))
  echo "[OK] $1"
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

safe_trim() {
  # 使用 awk 做跨平台 trim，避免依赖 bash 扩展。
  printf "%s" "$1" | awk '{$1=$1; print}'
}

jq_bool() {
  # jq 表达式返回 true/false，true=exit 0。
  jq -e "$1" "$CONFIG_PATH" >/dev/null 2>&1
}

jq_str() {
  jq -r "$1 // empty" "$CONFIG_PATH" 2>/dev/null
}

detect_jq_mode() {
  if command_exists jq; then
    HAS_JQ=1
    if jq -e "." "$CONFIG_PATH" >/dev/null 2>&1; then
      JQ_MODE=1
      log_ok "检测到 jq 且配置可被 JSON 解析，将执行精准检查"
    else
      JQ_MODE=0
      log_warn "检测到 jq 但配置不是严格 JSON（可能是 JSON5），降级为文本扫描模式"
    fi
  else
    HAS_JQ=0
    JQ_MODE=0
    log_warn "未检测到 jq，降级为文本扫描模式（准确度较低）"
  fi
}

get_mode_octal() {
  # Android/toybox 常见为 stat -c %a；BSD/macOS 常见为 stat -f %OLp。
  mode="$(stat -c %a "$1" 2>/dev/null || true)"
  if [ -z "$mode" ]; then
    mode="$(stat -f %OLp "$1" 2>/dev/null || true)"
  fi
  printf "%s" "$mode"
}

check_file_permission_risk() {
  mode_raw="$(get_mode_octal "$CONFIG_PATH")"
  if [ -z "$mode_raw" ]; then
    log_warn "无法读取文件权限位，跳过 openclaw.json 权限检查"
    return 0
  fi

  # 只取后 3 位权限位（忽略特殊位）。
  case "$mode_raw" in
    ?????*) mode3="$(printf "%s" "$mode_raw" | sed 's/.*\(...\)$/\1/')" ;;
    ????) mode3="${mode_raw#?}" ;;
    ???) mode3="$mode_raw" ;;
    *) mode3="" ;;
  esac

  if [ -z "$mode3" ]; then
    log_warn "权限位格式无法识别: ${mode_raw}"
    return 0
  fi

  owner_digit="${mode3%??}"
  rest="${mode3#?}"
  group_digit="${rest%?}"
  other_digit="${mode3#??}"

  if [ $((other_digit & 2)) -ne 0 ] || [ $((group_digit & 2)) -ne 0 ]; then
    log_critical "openclaw.json 可被组用户或其他用户写入（当前权限 ${mode3}），存在配置篡改风险"
  else
    log_ok "openclaw.json 不可被组/其他用户写入（当前权限 ${mode3}）"
  fi

  if [ $((other_digit & 4)) -ne 0 ]; then
    log_critical "openclaw.json 对其他用户可读（当前权限 ${mode3}），可能泄露 token/密钥"
  elif [ $((group_digit & 4)) -ne 0 ]; then
    log_warn "openclaw.json 对组用户可读（当前权限 ${mode3}），建议收敛为 600"
  else
    log_ok "openclaw.json 读取权限较安全（当前权限 ${mode3}）"
  fi
}

check_insecure_flags_jq() {
  if jq_bool '.gateway.controlUi.allowInsecureAuth? == true'; then
    log_warn "gateway.controlUi.allowInsecureAuth=true（兼容模式，建议关闭）"
  fi

  if jq_bool '.gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback? == true'; then
    if jq_bool '(.gateway.bind? // "loopback") != "loopback"'; then
      log_critical "gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback=true 且非 loopback 暴露"
    else
      log_warn "gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback=true（建议关闭）"
    fi
  fi

  if jq_bool '.gateway.controlUi.dangerouslyDisableDeviceAuth? == true'; then
    log_critical "gateway.controlUi.dangerouslyDisableDeviceAuth=true（高危）"
  fi

  if jq_bool '.hooks.gmail.allowUnsafeExternalContent? == true'; then
    log_warn "hooks.gmail.allowUnsafeExternalContent=true（外部内容安全包装被绕过）"
  fi

  if jq_bool '.hooks.mappings? | arrays and any(.allowUnsafeExternalContent? == true)'; then
    log_warn "hooks.mappings[].allowUnsafeExternalContent=true（存在外部内容绕过）"
  fi

  if jq_bool '.tools.exec.applyPatch.workspaceOnly? == false'; then
    log_warn "tools.exec.applyPatch.workspaceOnly=false（允许越过工作区写入）"
  fi
}

check_gateway_auth_jq() {
  bind="$(jq_str '.gateway.bind' )"
  bind="$(safe_trim "${bind:-loopback}")"
  if [ -z "$bind" ]; then
    bind="loopback"
  fi

  auth_mode="$(jq_str '.gateway.auth.mode')"
  auth_mode="$(safe_trim "${auth_mode:-}")"
  if [ -z "$auth_mode" ]; then
    auth_mode="token"
  fi

  has_token=0
  if jq_bool '(.gateway.auth.token? // null) as $t | (($t|type) == "string" and (($t|gsub("^\\s+|\\s+$";""))|length) > 0) or (($t|type) == "object")'; then
    has_token=1
  fi

  has_password=0
  if jq_bool '(.gateway.auth.password? // null) as $p | (($p|type) == "string" and (($p|gsub("^\\s+|\\s+$";""))|length) > 0) or (($p|type) == "object")'; then
    has_password=1
  fi

  has_remote_token=0
  if jq_bool '(.gateway.remote.token? // null) as $t | (($t|type) == "string" and (($t|gsub("^\\s+|\\s+$";""))|length) > 0) or (($t|type) == "object")'; then
    has_remote_token=1
  fi

  has_shared_secret=0
  if [ "$auth_mode" = "token" ]; then
    if [ "$has_token" -eq 1 ] || [ "$has_remote_token" -eq 1 ]; then
      has_shared_secret=1
    fi
  elif [ "$auth_mode" = "password" ]; then
    if [ "$has_password" -eq 1 ]; then
      has_shared_secret=1
    fi
  elif [ "$auth_mode" = "none" ] || [ "$auth_mode" = "trusted-proxy" ]; then
    has_shared_secret=0
  else
    if [ "$has_token" -eq 1 ] || [ "$has_password" -eq 1 ] || [ "$has_remote_token" -eq 1 ]; then
      has_shared_secret=1
    fi
  fi

  if [ "$bind" != "loopback" ] && [ "$auth_mode" != "trusted-proxy" ] && [ "$has_shared_secret" -ne 1 ]; then
    log_critical "gateway.bind=${bind} 但缺少有效 auth token/password（对应 gateway.bind_no_auth 风险）"
  else
    log_ok "gateway.bind/auth 组合未命中明显高危模式"
  fi

  if [ "$bind" = "loopback" ] && [ "$auth_mode" != "trusted-proxy" ] && [ "$has_shared_secret" -ne 1 ]; then
    log_critical "loopback 模式下未配置有效 gateway.auth，反代场景可能出现未鉴权访问"
  fi

  if jq_bool '.gateway.auth.mode? == "token" and (.gateway.auth.token? | type == "string") and ((.gateway.auth.token|length) > 0) and ((.gateway.auth.token|length) < 24)'; then
    token_len="$(jq_str '.gateway.auth.token | length')"
    log_warn "gateway.auth.token 长度较短（${token_len}），建议至少 24 位随机串"
  fi
}

check_gateway_exposure_jq() {
  if jq_bool '.gateway.tailscale.mode? == "funnel"'; then
    log_critical "gateway.tailscale.mode=funnel（公网暴露）"
  elif jq_bool '.gateway.tailscale.mode? == "serve"'; then
    log_info "gateway.tailscale.mode=serve（tailnet 暴露，需保证凭据安全）"
  fi

  if jq_bool '(.gateway.controlUi.enabled? // true) == true and (.gateway.controlUi.allowedOrigins? | arrays and any(. == "*"))'; then
    if jq_bool '(.gateway.bind? // "loopback") != "loopback"'; then
      log_critical 'gateway.controlUi.allowedOrigins 包含 "*" 且网关非 loopback'
    else
      log_warn 'gateway.controlUi.allowedOrigins 包含 "*"（建议改为显式来源）'
    fi
  fi

  if jq_bool '(.gateway.bind? // "loopback") != "loopback" and (.gateway.controlUi.enabled? // true) == true and ((.gateway.controlUi.allowedOrigins? // []) | length == 0) and (.gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback? != true)'; then
    log_critical "非 loopback 且 control UI 未设置 allowedOrigins（缺失严格来源限制）"
  fi
}

check_tool_policy_jq() {
  # 对齐 src/security/dangerous-tools.ts 默认高危清单
  if jq_bool '(.gateway.tools.allow? // []) | arrays and any(. == "sessions_spawn" or . == "sessions_send" or . == "cron" or . == "gateway" or . == "whatsapp_login")'; then
    hit_list="$(jq -r '(.gateway.tools.allow? // []) | map(select(. == "sessions_spawn" or . == "sessions_send" or . == "cron" or . == "gateway" or . == "whatsapp_login")) | unique | join(",")' "$CONFIG_PATH" 2>/dev/null)"
    log_critical "gateway.tools.allow 重新放开了 HTTP 默认拒绝高危工具: ${hit_list}"
  fi

  if jq_bool '.tools.exec.security? == "full"'; then
    log_warn "tools.exec.security=full（执行面过宽）"
  fi

  if jq_bool '.agents.list? | arrays and any(.tools.exec.security? == "full")'; then
    log_warn "agents.list[].tools.exec.security 存在 full（建议收敛到 allowlist）"
  fi

  if jq_bool '.tools.elevated.enabled? != false and (.tools.elevated.allowFrom? | type == "object") and ([.tools.elevated.allowFrom[]? | arrays | any(. == "*")] | any)'; then
    log_critical "tools.elevated.allowFrom 存在通配符 *（高危提权面）"
  fi
}

check_channel_policy_jq() {
  if jq_bool '.channels? | type == "object" and ([.channels[]? | objects | .dmPolicy? // empty | select(. == "open")] | length > 0)'; then
    log_warn "存在 channels.*.dmPolicy=open（外部可直接触发）"
  fi

  if jq_bool '.channels? | type == "object" and ([.channels[]? | objects | .groupPolicy? // empty | select(. == "open")] | length > 0)'; then
    log_warn "存在 channels.*.groupPolicy=open（群组触发面较大）"
  fi

  if jq_bool '.channels? | type == "object" and ([.channels[]? | objects | .accounts? | objects | .[]? | objects | .groupPolicy? // empty | select(. == "open")] | length > 0)'; then
    log_warn "存在 channels.*.accounts.*.groupPolicy=open"
  fi
}

check_misc_hygiene_jq() {
  if jq_bool '.logging.redactSensitive? == "off"'; then
    log_warn 'logging.redactSensitive="off"（日志可能泄露敏感信息）'
  else
    log_ok "日志脱敏未发现显式关闭"
  fi

  if jq_bool '.discovery.mdns.mode? == "full"'; then
    if jq_bool '(.gateway.bind? // "loopback") != "loopback"'; then
      log_critical "discovery.mdns.mode=full 且非 loopback（可能泄露主机元数据）"
    else
      log_warn "discovery.mdns.mode=full（建议 minimal/off）"
    fi
  fi
}

check_text_scan_fallback() {
  raw="$(cat "$CONFIG_PATH" 2>/dev/null || true)"
  if [ -z "$raw" ]; then
    log_critical "无法读取配置内容"
    return 0
  fi

  # 文本扫描不保证精确，仅用于低依赖环境兜底。
  case "$raw" in
    *'"dangerouslyDisableDeviceAuth"'*:*true*) log_critical "命中 dangerouslyDisableDeviceAuth=true（文本扫描）" ;;
  esac
  case "$raw" in
    *'"dangerouslyAllowHostHeaderOriginFallback"'*:*true*) log_warn "命中 dangerouslyAllowHostHeaderOriginFallback=true（文本扫描）" ;;
  esac
  case "$raw" in
    *'"allowInsecureAuth"'*:*true*) log_warn "命中 allowInsecureAuth=true（文本扫描）" ;;
  esac
  case "$raw" in
    *'"allowUnsafeExternalContent"'*:*true*) log_warn "命中 allowUnsafeExternalContent=true（文本扫描）" ;;
  esac
  case "$raw" in
    *'"workspaceOnly"'*:*false*) log_warn "命中 workspaceOnly=false（文本扫描）" ;;
  esac
  case "$raw" in
    *'"groupPolicy"'*:*'"open"'*) log_warn "命中 groupPolicy=open（文本扫描）" ;;
  esac
  case "$raw" in
    *'"dmPolicy"'*:*'"open"'*) log_warn "命中 dmPolicy=open（文本扫描）" ;;
  esac
  case "$raw" in
    *'"security"'*:*'"full"'*) log_warn "命中 exec security=full（文本扫描）" ;;
  esac
  case "$raw" in
    *'"tailscale"'*'"mode"'*'"funnel"'*) log_critical "命中 tailscale funnel 暴露（文本扫描）" ;;
  esac
  case "$raw" in
    *'"allowedOrigins"'*'"*"'*) log_warn '命中 controlUi allowedOrigins="*"（文本扫描）' ;;
  esac
  case "$raw" in
    *'"gateway"'*'"tools"'*'"allow"'*'"sessions_spawn"'*) log_critical "命中 gateway.tools.allow 高危项 sessions_spawn（文本扫描）" ;;
  esac
}

print_summary_and_exit() {
  echo
  echo "========== 安全检查汇总 =========="
  echo "CRITICAL: ${CRITICAL_COUNT}"
  echo "WARN:     ${WARN_COUNT}"
  echo "INFO:     ${INFO_COUNT}"
  echo "OK:       ${OK_COUNT}"
  echo "版本:     ${VERSION}"
  echo "=================================="

  if [ "$CRITICAL_COUNT" -gt 0 ]; then
    exit 2
  fi
  if [ "$WARN_COUNT" -gt 0 ]; then
    exit 1
  fi
  exit 0
}

main() {
  if [ "$#" -ne 1 ]; then
    print_usage
    exit 2
  fi

  CONFIG_PATH="$1"

  if [ "$CONFIG_PATH" = "-h" ] || [ "$CONFIG_PATH" = "--help" ]; then
    print_usage
    exit 0
  fi

  if [ ! -e "$CONFIG_PATH" ]; then
    echo "错误: 文件不存在: $CONFIG_PATH"
    exit 2
  fi

  if [ ! -f "$CONFIG_PATH" ]; then
    echo "错误: 目标不是普通文件: $CONFIG_PATH"
    exit 2
  fi

  if [ ! -r "$CONFIG_PATH" ]; then
    echo "错误: 文件不可读: $CONFIG_PATH"
    exit 2
  fi

  log_info "开始检查: $CONFIG_PATH"
  check_file_permission_risk
  detect_jq_mode

  if [ "$JQ_MODE" -eq 1 ]; then
    check_insecure_flags_jq
    check_gateway_auth_jq
    check_gateway_exposure_jq
    check_tool_policy_jq
    check_channel_policy_jq
    check_misc_hygiene_jq
  else
    check_text_scan_fallback
  fi

  print_summary_and_exit
}

main "$@"
# Ended by Cursor ubuntu 20260327074132903
