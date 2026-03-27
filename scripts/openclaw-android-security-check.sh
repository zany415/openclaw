#!/system/bin/sh
# Started by Cursor ubuntu 20260327080618173
SCRIPT_NAME="${0##*/}"
VERSION="2026.03.27-adb"
SQ=$(printf "'")

CRITICAL_COUNT=0
WARN_COUNT=0
INFO_COUNT=0
OK_COUNT=0

# Started by Cursor ubuntu 20260327083413687
FIX_CONFIG_PERM=0
FIX_GATEWAY=0
FIX_TOOLS=0
FIX_CHANNELS=0
FIX_LOGGING=0
FIX_DISCOVERY=0
# Ended by Cursor ubuntu 20260327083413687

NORM=""
ROOT_OBJ=""
GATEWAY_OBJ=""
AUTH_OBJ=""
REMOTE_OBJ=""
CONTROL_UI_OBJ=""
TAILSCALE_OBJ=""
GATEWAY_TOOLS_OBJ=""
HOOKS_OBJ=""
HOOKS_GMAIL_OBJ=""
LOGGING_OBJ=""
DISCOVERY_OBJ=""
MDNS_OBJ=""

print_usage() {
  echo "用法: sh ${SCRIPT_NAME} <openclaw.json 路径>"
  echo "示例: sh ${SCRIPT_NAME} /data/openclaw/home/.openclaw/openclaw.json"
  echo "适配环境: Android adb shell（无 jq）"
  echo "退出码: 0=通过, 1=仅警告, 2=存在高危/输入错误"
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

perm_triplet_to_digit() {
  trip="$1"
  d=0
  case "$trip" in
    *r*) d=$((d + 4)) ;;
  esac
  case "$trip" in
    *w*) d=$((d + 2)) ;;
  esac
  case "$trip" in
    *x*|*s*|*t*) d=$((d + 1)) ;;
  esac
  printf "%s" "$d"
}

get_mode_octal() {
  target="$1"
  mode="$(stat -c %a "$target" 2>/dev/null || true)"
  if [ -z "$mode" ]; then
    mode="$(stat -f %OLp "$target" 2>/dev/null || true)"
  fi
  if [ -n "$mode" ]; then
    printf "%s" "$mode"
    return 0
  fi

  if command_exists ls && command_exists awk; then
    perms="$(ls -ld "$target" 2>/dev/null | awk 'NR==1{print $1}')"
    if [ -n "$perms" ] && [ "$(printf "%s" "$perms" | awk '{print length($0)}')" -ge 10 ]; then
      u="$(printf "%s" "$perms" | awk '{print substr($0,2,3)}')"
      g="$(printf "%s" "$perms" | awk '{print substr($0,5,3)}')"
      o="$(printf "%s" "$perms" | awk '{print substr($0,8,3)}')"
      printf "%s%s%s" "$(perm_triplet_to_digit "$u")" "$(perm_triplet_to_digit "$g")" "$(perm_triplet_to_digit "$o")"
      return 0
    fi
  fi

  printf ""
}

check_file_permission_risk() {
  mode_raw="$(get_mode_octal "$CONFIG_PATH")"
  if [ -z "$mode_raw" ]; then
    log_warn "无法读取文件权限位，跳过 openclaw.json 权限检查"
    return 0
  fi

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
    # Started by Cursor ubuntu 20260327083413687
    FIX_CONFIG_PERM=1
    # Ended by Cursor ubuntu 20260327083413687
  else
    log_ok "openclaw.json 不可被组/其他用户写入（当前权限 ${mode3}）"
  fi

  if [ $((other_digit & 4)) -ne 0 ]; then
    log_critical "openclaw.json 对其他用户可读（当前权限 ${mode3}），可能泄露 token/密钥"
    # Started by Cursor ubuntu 20260327083413687
    FIX_CONFIG_PERM=1
    # Ended by Cursor ubuntu 20260327083413687
  elif [ $((group_digit & 4)) -ne 0 ]; then
    log_warn "openclaw.json 对组用户可读（当前权限 ${mode3}），建议收敛为 600"
    # Started by Cursor ubuntu 20260327083413687
    FIX_CONFIG_PERM=1
    # Ended by Cursor ubuntu 20260327083413687
  else
    log_ok "openclaw.json 读取权限较安全（当前权限 ${mode3}）"
  fi
}

sanitize_json5_with_awk() {
  awk '
BEGIN {
  in_block = 0
  in_string = 0
  quote = ""
  escaped = 0
}
{
  line = $0
  gsub(/\r/, "", line)
  out = ""
  i = 1
  while (i <= length(line)) {
    c = substr(line, i, 1)
    n = (i < length(line) ? substr(line, i + 1, 1) : "")

    if (in_block == 1) {
      if (c == "*" && n == "/") {
        in_block = 0
        i += 2
        continue
      }
      i++
      continue
    }

    if (in_string == 1) {
      out = out c
      if (escaped == 1) {
        escaped = 0
      } else if (c == "\\") {
        escaped = 1
      } else if (c == quote) {
        in_string = 0
        quote = ""
      }
      i++
      continue
    }

    if (c == "\"" || c == sprintf("%c", 39)) {
      in_string = 1
      quote = c
      out = out c
      i++
      continue
    }

    if (c == "/" && n == "*") {
      in_block = 1
      i += 2
      continue
    }

    if (c == "/" && n == "/") {
      break
    }

    out = out c
    i++
  }
  print out
}' "$CONFIG_PATH"
}

build_normalized_text() {
  if command_exists awk; then
    raw="$(sanitize_json5_with_awk 2>/dev/null || true)"
  else
    raw="$(tr -d '\r' < "$CONFIG_PATH" 2>/dev/null || true)"
    log_warn "系统无 awk，注释剥离能力受限，结果可能偏保守"
  fi

  NORM="$(printf "%s" "$raw" | tr -d ' \t\r\n')"
  if [ -z "$NORM" ]; then
    log_critical "配置内容为空或无法解析（预处理后为空）"
    return 1
  fi

  ROOT_OBJ="$NORM"
  return 0
}

extract_object_from_text() {
  text="$1"
  key="$2"
  if [ -z "$text" ] || [ -z "$key" ] || ! command_exists awk; then
    printf ""
    return 1
  fi
  printf "%s" "$text" | awk -v key="$key" '
function min3(a, b, c,   m) {
  m = 0
  if (a > 0) m = a
  if (b > 0 && (m == 0 || b < m)) m = b
  if (c > 0 && (m == 0 || c < m)) m = c
  return m
}
{
  s = $0
  sq = sprintf("%c", 39)
  p1 = index(s, "\"" key "\":{")
  p2 = index(s, sq key sq ":{")
  p3 = index(s, key ":{")
  p = min3(p1, p2, p3)
  if (p == 0) exit 1

  if (p == p1) start = p + length("\"" key "\":")
  else if (p == p2) start = p + length(sq key sq ":")
  else start = p + length(key ":")

  depth = 0
  in_str = 0
  q = ""
  esc = 0
  out = ""
  for (i = start; i <= length(s); i++) {
    c = substr(s, i, 1)
    out = out c
    if (in_str == 1) {
      if (esc == 1) esc = 0
      else if (c == "\\") esc = 1
      else if (c == q) {
        in_str = 0
        q = ""
      }
    } else {
      if (c == "\"" || c == sq) {
        in_str = 1
        q = c
      } else if (c == "{") depth++
      else if (c == "}") {
        depth--
        if (depth == 0) {
          print out
          exit 0
        }
      }
    }
  }
  exit 1
}'
}

extract_array_from_text() {
  text="$1"
  key="$2"
  if [ -z "$text" ] || [ -z "$key" ] || ! command_exists awk; then
    printf ""
    return 1
  fi
  printf "%s" "$text" | awk -v key="$key" '
function min3(a, b, c,   m) {
  m = 0
  if (a > 0) m = a
  if (b > 0 && (m == 0 || b < m)) m = b
  if (c > 0 && (m == 0 || c < m)) m = c
  return m
}
{
  s = $0
  sq = sprintf("%c", 39)
  p1 = index(s, "\"" key "\":[")
  p2 = index(s, sq key sq ":[")
  p3 = index(s, key ":[")
  p = min3(p1, p2, p3)
  if (p == 0) exit 1

  if (p == p1) start = p + length("\"" key "\":")
  else if (p == p2) start = p + length(sq key sq ":")
  else start = p + length(key ":")

  depth = 0
  in_str = 0
  q = ""
  esc = 0
  out = ""
  for (i = start; i <= length(s); i++) {
    c = substr(s, i, 1)
    out = out c
    if (in_str == 1) {
      if (esc == 1) esc = 0
      else if (c == "\\") esc = 1
      else if (c == q) {
        in_str = 0
        q = ""
      }
    } else {
      if (c == "\"" || c == sq) {
        in_str = 1
        q = c
      } else if (c == "[") depth++
      else if (c == "]") {
        depth--
        if (depth == 0) {
          print out
          exit 0
        }
      }
    }
  }
  exit 1
}'
}

extract_scalar_from_text() {
  text="$1"
  key="$2"
  if [ -z "$text" ] || [ -z "$key" ] || ! command_exists awk; then
    printf ""
    return 1
  fi
  printf "%s" "$text" | awk -v key="$key" '
function try(prefix,   pos, rest, c, q, i, ch, out) {
  pos = index(s, prefix)
  if (pos == 0) return 0
  rest = substr(s, pos + length(prefix))
  c = substr(rest, 1, 1)
  sq = sprintf("%c", 39)
  if (c == "\"" || c == sq) {
    q = c
    out = ""
    for (i = 2; i <= length(rest); i++) {
      ch = substr(rest, i, 1)
      if (ch == "\\") {
        i++
        if (i <= length(rest)) out = out substr(rest, i, 1)
        continue
      }
      if (ch == q) {
        print out
        return 1
      }
      out = out ch
    }
    return 0
  }
  if (match(rest, /^[A-Za-z0-9_.-]+/)) {
    print substr(rest, RSTART, RLENGTH)
    return 1
  }
  return 0
}
{
  s = $0
  sq = sprintf("%c", 39)
  if (try("\"" key "\":")) exit 0
  if (try(sq key sq ":")) exit 0
  if (try(key ":")) exit 0
  exit 1
}'
}

contains_key_true_in_text() {
  text="$1"
  key="$2"
  case "$text" in
    *"\"$key\":true"*|*"$SQ$key$SQ:true"*|*"$key:true"*) return 0 ;;
  esac
  return 1
}

contains_key_value_in_text() {
  text="$1"
  key="$2"
  value="$3"
  case "$text" in
    *"\"$key\":\"$value\""*|*"$SQ$key$SQ:$SQ$value$SQ"*|*"\"$key\":$value"*|*"$SQ$key$SQ:$value"*|*"$key:\"$value\""*|*"$key:$value"*) return 0 ;;
  esac
  return 1
}

key_has_nonempty_value_in_text() {
  text="$1"
  key="$2"
  case "$text" in
    *"\"$key\":{"*|*"$SQ$key$SQ:{"*|*"$key:{"*) return 0 ;;
  esac
  val="$(extract_scalar_from_text "$text" "$key")"
  if [ -n "$val" ] && [ "$val" != "null" ]; then
    return 0
  fi
  return 1
}

array_contains_item() {
  arr="$1"
  item="$2"
  case "$arr" in
    *"\"$item\""*|*"$SQ$item$SQ"*|*"[$item,"*|*",$item,"*|*",$item]"*|*"[$item]"*) return 0 ;;
  esac
  return 1
}

array_is_empty() {
  arr="$1"
  case "$arr" in
    ""|"[]") return 0 ;;
  esac
  return 1
}

prepare_sections() {
  GATEWAY_OBJ="$(extract_object_from_text "$ROOT_OBJ" "gateway")"
  if [ -z "$GATEWAY_OBJ" ]; then
    GATEWAY_OBJ="$ROOT_OBJ"
    log_warn "未明确解析出 gateway 对象，将按全局保守规则检查"
  fi
  AUTH_OBJ="$(extract_object_from_text "$GATEWAY_OBJ" "auth")"
  REMOTE_OBJ="$(extract_object_from_text "$GATEWAY_OBJ" "remote")"
  CONTROL_UI_OBJ="$(extract_object_from_text "$GATEWAY_OBJ" "controlUi")"
  TAILSCALE_OBJ="$(extract_object_from_text "$GATEWAY_OBJ" "tailscale")"
  GATEWAY_TOOLS_OBJ="$(extract_object_from_text "$GATEWAY_OBJ" "tools")"
  HOOKS_OBJ="$(extract_object_from_text "$ROOT_OBJ" "hooks")"
  HOOKS_GMAIL_OBJ="$(extract_object_from_text "$HOOKS_OBJ" "gmail")"
  LOGGING_OBJ="$(extract_object_from_text "$ROOT_OBJ" "logging")"
  DISCOVERY_OBJ="$(extract_object_from_text "$ROOT_OBJ" "discovery")"
  MDNS_OBJ="$(extract_object_from_text "$DISCOVERY_OBJ" "mdns")"
}

check_insecure_flags_adb() {
  if contains_key_true_in_text "$CONTROL_UI_OBJ" "allowInsecureAuth"; then
    log_warn "gateway.controlUi.allowInsecureAuth=true（兼容模式，建议关闭）"
    # Started by Cursor ubuntu 20260327083413687
    FIX_GATEWAY=1
    # Ended by Cursor ubuntu 20260327083413687
  fi

  if contains_key_true_in_text "$CONTROL_UI_OBJ" "dangerouslyAllowHostHeaderOriginFallback"; then
    if [ "$GATEWAY_BIND" != "loopback" ]; then
      log_critical "gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback=true 且非 loopback 暴露"
      # Started by Cursor ubuntu 20260327083413687
      FIX_GATEWAY=1
      # Ended by Cursor ubuntu 20260327083413687
    else
      log_warn "gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback=true（建议关闭）"
      # Started by Cursor ubuntu 20260327083413687
      FIX_GATEWAY=1
      # Ended by Cursor ubuntu 20260327083413687
    fi
  fi

  if contains_key_true_in_text "$CONTROL_UI_OBJ" "dangerouslyDisableDeviceAuth"; then
    log_critical "gateway.controlUi.dangerouslyDisableDeviceAuth=true（高危）"
    # Started by Cursor ubuntu 20260327083413687
    FIX_GATEWAY=1
    # Ended by Cursor ubuntu 20260327083413687
  fi

  if contains_key_true_in_text "$HOOKS_GMAIL_OBJ" "allowUnsafeExternalContent"; then
    log_warn "hooks.gmail.allowUnsafeExternalContent=true（外部内容安全包装被绕过）"
  fi

  if contains_key_true_in_text "$HOOKS_OBJ" "allowUnsafeExternalContent"; then
    log_warn "hooks.mappings 或其他 hooks 区域存在 allowUnsafeExternalContent=true"
  fi

  if contains_key_value_in_text "$ROOT_OBJ" "workspaceOnly" "false"; then
    log_warn "检测到 workspaceOnly=false（可能扩大文件写入边界）"
  fi
}

check_gateway_auth_adb() {
  GATEWAY_BIND="$(extract_scalar_from_text "$GATEWAY_OBJ" "bind")"
  if [ -z "$GATEWAY_BIND" ]; then
    GATEWAY_BIND="loopback"
  fi

  AUTH_MODE="$(extract_scalar_from_text "$AUTH_OBJ" "mode")"
  if [ -z "$AUTH_MODE" ]; then
    AUTH_MODE="token"
  fi

  HAS_TOKEN=0
  HAS_PASSWORD=0
  HAS_REMOTE_TOKEN=0

  if key_has_nonempty_value_in_text "$AUTH_OBJ" "token"; then
    HAS_TOKEN=1
  fi
  if key_has_nonempty_value_in_text "$AUTH_OBJ" "password"; then
    HAS_PASSWORD=1
  fi
  if key_has_nonempty_value_in_text "$REMOTE_OBJ" "token"; then
    HAS_REMOTE_TOKEN=1
  fi

  HAS_SHARED_SECRET=0
  if [ "$AUTH_MODE" = "token" ]; then
    if [ "$HAS_TOKEN" -eq 1 ] || [ "$HAS_REMOTE_TOKEN" -eq 1 ]; then
      HAS_SHARED_SECRET=1
    fi
  elif [ "$AUTH_MODE" = "password" ]; then
    if [ "$HAS_PASSWORD" -eq 1 ]; then
      HAS_SHARED_SECRET=1
    fi
  elif [ "$AUTH_MODE" = "none" ] || [ "$AUTH_MODE" = "trusted-proxy" ]; then
    HAS_SHARED_SECRET=0
  else
    if [ "$HAS_TOKEN" -eq 1 ] || [ "$HAS_PASSWORD" -eq 1 ] || [ "$HAS_REMOTE_TOKEN" -eq 1 ]; then
      HAS_SHARED_SECRET=1
    fi
  fi

  if [ "$GATEWAY_BIND" != "loopback" ] && [ "$AUTH_MODE" != "trusted-proxy" ] && [ "$HAS_SHARED_SECRET" -ne 1 ]; then
    log_critical "gateway.bind=${GATEWAY_BIND} 但缺少有效 auth token/password（对应 bind_no_auth 风险）"
    # Started by Cursor ubuntu 20260327083413687
    FIX_GATEWAY=1
    # Ended by Cursor ubuntu 20260327083413687
  else
    log_ok "gateway.bind/auth 组合未命中明显高危模式"
  fi

  if [ "$GATEWAY_BIND" = "loopback" ] && [ "$AUTH_MODE" != "trusted-proxy" ] && [ "$HAS_SHARED_SECRET" -ne 1 ]; then
    log_critical "loopback 模式下未配置有效 gateway.auth，反代场景可能出现未鉴权访问"
    # Started by Cursor ubuntu 20260327083413687
    FIX_GATEWAY=1
    # Ended by Cursor ubuntu 20260327083413687
  fi

  TOKEN_VALUE="$(extract_scalar_from_text "$AUTH_OBJ" "token")"
  if [ "$AUTH_MODE" = "token" ] && [ -n "$TOKEN_VALUE" ]; then
    token_len="${#TOKEN_VALUE}"
    if [ "$token_len" -gt 0 ] && [ "$token_len" -lt 24 ]; then
      log_warn "gateway.auth.token 长度较短（${token_len}），建议至少 24 位随机串"
      # Started by Cursor ubuntu 20260327083413687
      FIX_GATEWAY=1
      # Ended by Cursor ubuntu 20260327083413687
    fi
  fi
}

check_gateway_exposure_adb() {
  tailscale_mode="$(extract_scalar_from_text "$TAILSCALE_OBJ" "mode")"
  if [ "$tailscale_mode" = "funnel" ]; then
    log_critical "gateway.tailscale.mode=funnel（公网暴露）"
    # Started by Cursor ubuntu 20260327083413687
    FIX_GATEWAY=1
    # Ended by Cursor ubuntu 20260327083413687
  elif [ "$tailscale_mode" = "serve" ]; then
    log_info "gateway.tailscale.mode=serve（tailnet 暴露，需保证凭据安全）"
    # Started by Cursor ubuntu 20260327083413687
    FIX_GATEWAY=1
    # Ended by Cursor ubuntu 20260327083413687
  fi

  control_ui_enabled="$(extract_scalar_from_text "$CONTROL_UI_OBJ" "enabled")"
  if [ "$control_ui_enabled" = "false" ]; then
    control_ui_enabled="false"
  else
    control_ui_enabled="true"
  fi

  allowed_origins_arr="$(extract_array_from_text "$CONTROL_UI_OBJ" "allowedOrigins")"
  if [ "$control_ui_enabled" = "true" ]; then
    if array_contains_item "$allowed_origins_arr" "*"; then
      if [ "$GATEWAY_BIND" != "loopback" ]; then
        log_critical 'gateway.controlUi.allowedOrigins 包含 "*" 且网关非 loopback'
        # Started by Cursor ubuntu 20260327083413687
        FIX_GATEWAY=1
        # Ended by Cursor ubuntu 20260327083413687
      else
        log_warn 'gateway.controlUi.allowedOrigins 包含 "*"（建议改为显式来源）'
        # Started by Cursor ubuntu 20260327083413687
        FIX_GATEWAY=1
        # Ended by Cursor ubuntu 20260327083413687
      fi
    fi

    if [ "$GATEWAY_BIND" != "loopback" ] && array_is_empty "$allowed_origins_arr" && ! contains_key_true_in_text "$CONTROL_UI_OBJ" "dangerouslyAllowHostHeaderOriginFallback"; then
      log_critical "非 loopback 且 controlUi.allowedOrigins 为空（缺失严格来源限制）"
      # Started by Cursor ubuntu 20260327083413687
      FIX_GATEWAY=1
      # Ended by Cursor ubuntu 20260327083413687
    fi
  fi

  if contains_key_true_in_text "$GATEWAY_OBJ" "allowRealIpFallback"; then
    if [ "$GATEWAY_BIND" != "loopback" ]; then
      log_critical "gateway.allowRealIpFallback=true 且网关非 loopback（存在源 IP 伪造风险）"
      # Started by Cursor ubuntu 20260327083413687
      FIX_GATEWAY=1
      # Ended by Cursor ubuntu 20260327083413687
    else
      log_warn "gateway.allowRealIpFallback=true（仅在可信反代严格覆写头时使用）"
      # Started by Cursor ubuntu 20260327083413687
      FIX_GATEWAY=1
      # Ended by Cursor ubuntu 20260327083413687
    fi
  fi
}

check_tool_policy_adb() {
  hit_list=""
  allow_arr="$(extract_array_from_text "$GATEWAY_TOOLS_OBJ" "allow")"
  for item in sessions_spawn sessions_send cron gateway whatsapp_login; do
    if array_contains_item "$allow_arr" "$item"; then
      if [ -z "$hit_list" ]; then
        hit_list="$item"
      else
        hit_list="${hit_list},${item}"
      fi
    fi
  done
  if [ -n "$hit_list" ]; then
    log_critical "gateway.tools.allow 重新放开了 HTTP 默认拒绝高危工具: ${hit_list}"
    # Started by Cursor ubuntu 20260327083413687
    FIX_TOOLS=1
    # Ended by Cursor ubuntu 20260327083413687
  fi

  if contains_key_value_in_text "$ROOT_OBJ" "security" "full"; then
    log_warn "检测到 security=full（可能扩大 exec 权限面）"
    # Started by Cursor ubuntu 20260327083413687
    FIX_TOOLS=1
    # Ended by Cursor ubuntu 20260327083413687
  fi

  if contains_key_true_in_text "$ROOT_OBJ" "autoAllowSkills"; then
    log_warn "检测到 autoAllowSkills=true（执行授权面增大）"
    # Started by Cursor ubuntu 20260327083413687
    FIX_TOOLS=1
    # Ended by Cursor ubuntu 20260327083413687
  fi

  if contains_key_true_in_text "$ROOT_OBJ" "strictInlineEval"; then
    log_info "检测到 strictInlineEval=true（解释器内联执行防护已开启）"
  fi

  if contains_key_value_in_text "$ROOT_OBJ" "allowFrom" "*" || contains_key_value_in_text "$ROOT_OBJ" "groupAllowFrom" "*"; then
    log_critical "检测到 allowFrom/groupAllowFrom 含通配符 *（可能过度放开）"
    # Started by Cursor ubuntu 20260327083413687
    FIX_TOOLS=1
    # Ended by Cursor ubuntu 20260327083413687
  fi
}

check_channel_policy_adb() {
  if contains_key_value_in_text "$ROOT_OBJ" "dmPolicy" "open"; then
    log_warn "存在 dmPolicy=open（外部可直接触发）"
    # Started by Cursor ubuntu 20260327083413687
    FIX_CHANNELS=1
    # Ended by Cursor ubuntu 20260327083413687
  fi

  if contains_key_value_in_text "$ROOT_OBJ" "groupPolicy" "open"; then
    log_warn "存在 groupPolicy=open（群组触发面较大）"
    # Started by Cursor ubuntu 20260327083413687
    FIX_CHANNELS=1
    # Ended by Cursor ubuntu 20260327083413687
  fi
}

check_misc_hygiene_adb() {
  if contains_key_value_in_text "$LOGGING_OBJ" "redactSensitive" "off"; then
    log_warn 'logging.redactSensitive="off"（日志可能泄露敏感信息）'
    # Started by Cursor ubuntu 20260327083413687
    FIX_LOGGING=1
    # Ended by Cursor ubuntu 20260327083413687
  else
    log_ok "日志脱敏未发现显式关闭"
  fi

  mdns_mode="$(extract_scalar_from_text "$MDNS_OBJ" "mode")"
  if [ "$mdns_mode" = "full" ]; then
    if [ "$GATEWAY_BIND" != "loopback" ]; then
      log_critical "discovery.mdns.mode=full 且非 loopback（可能泄露主机元数据）"
      # Started by Cursor ubuntu 20260327083413687
      FIX_DISCOVERY=1
      # Ended by Cursor ubuntu 20260327083413687
    else
      log_warn "discovery.mdns.mode=full（建议 minimal/off）"
      # Started by Cursor ubuntu 20260327083413687
      FIX_DISCOVERY=1
      # Ended by Cursor ubuntu 20260327083413687
    fi
  fi
}

# Started by Cursor ubuntu 20260327083413687
print_short_remediation() {
  if [ "$CRITICAL_COUNT" -eq 0 ] && [ "$WARN_COUNT" -eq 0 ]; then
    return 0
  fi

  echo
  echo "========== 最短修复建议 =========="

  if [ "$FIX_CONFIG_PERM" -eq 1 ]; then
    echo "- 收紧配置文件权限:"
    echo "  chmod 600 \"$CONFIG_PATH\""
  fi

  if [ "$FIX_GATEWAY" -eq 1 ]; then
    cat <<'EOF'
- 建议最短 gateway 安全片段（合并到 openclaw.json）:
  {
    "gateway": {
      "bind": "loopback",
      "auth": { "mode": "token", "token": "REPLACE_WITH_LONG_RANDOM_TOKEN_24_PLUS" },
      "controlUi": {
        "allowedOrigins": ["https://control.example.com"],
        "dangerouslyAllowHostHeaderOriginFallback": false,
        "dangerouslyDisableDeviceAuth": false,
        "allowInsecureAuth": false
      },
      "allowRealIpFallback": false,
      "tailscale": { "mode": "off" }
    }
  }
EOF
  fi

  if [ "$FIX_TOOLS" -eq 1 ]; then
    cat <<'EOF'
- 建议最短 tools 收敛片段:
  {
    "gateway": { "tools": { "allow": [] } },
    "tools": {
      "exec": { "security": "allowlist", "strictInlineEval": true },
      "elevated": { "enabled": false }
    }
  }
EOF
  fi

  if [ "$FIX_CHANNELS" -eq 1 ]; then
    cat <<'EOF'
- 建议最短渠道策略片段:
  {
    "channels": {
      "whatsapp": { "dmPolicy": "pairing", "groupPolicy": "allowlist" }
    }
  }
EOF
  fi

  if [ "$FIX_LOGGING" -eq 1 ]; then
    echo '- 建议最短日志脱敏片段: { "logging": { "redactSensitive": "tools" } }'
  fi

  if [ "$FIX_DISCOVERY" -eq 1 ]; then
    echo '- 建议最短发现面片段: { "discovery": { "mdns": { "mode": "minimal" } } }'
  fi

  echo "=================================="
}
# Ended by Cursor ubuntu 20260327083413687

print_summary_and_exit() {
  echo
  echo "========== 安全检查汇总 =========="
  echo "CRITICAL: ${CRITICAL_COUNT}"
  echo "WARN:     ${WARN_COUNT}"
  echo "INFO:     ${INFO_COUNT}"
  echo "OK:       ${OK_COUNT}"
  echo "版本:     ${VERSION}"
  echo "=================================="
  # Started by Cursor ubuntu 20260327083413687
  print_short_remediation
  # Ended by Cursor ubuntu 20260327083413687

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

  if ! build_normalized_text; then
    print_summary_and_exit
  fi
  prepare_sections
  check_gateway_auth_adb
  check_insecure_flags_adb
  check_gateway_exposure_adb
  check_tool_policy_adb
  check_channel_policy_adb
  check_misc_hygiene_adb

  print_summary_and_exit
}

main "$@"
# Ended by Cursor ubuntu 20260327080618173
