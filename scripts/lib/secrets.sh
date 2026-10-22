#!/usr/bin/env bash
# Shared helpers for demo scripts that need a secret such as an API key.
#
# A secret lives in an owner-only file with one `NAME=value` line, or in an already-exported
# environment variable of the same name. The file is parsed, never sourced, so it cannot run
# code, and values are never printed. Source this file; it defines functions only.
#
#   rg_secret_status FILE NAME          prints one line: "filled in", "from environment" or "empty or missing"
#   rg_secret_check  FILE NAME          returns 0 if usable; otherwise explains on stderr and returns 1
#   rg_with_secret   FILE NAME cmd...   runs cmd with NAME exported for that command only

rg_secret_file_value() {
  # Prints the value of the last `NAME=value` line, with optional surrounding quotes removed.
  local value
  value="$(sed -n "s/^$2=//p" "$1" 2>/dev/null | tail -n 1)"
  value="${value%\"}"; value="${value#\"}"; value="${value%\'}"; value="${value#\'}"
  printf '%s' "$value"
}

rg_secret_status() {
  local file="$1" name="$2"
  if [[ -f "$file" && -n "$(rg_secret_file_value "$file" "$name")" ]]; then echo "filled in"
  elif [[ -n "${!name:-}" ]]; then echo "from environment"
  else echo "empty or missing"
  fi
}

rg_secret_check() {
  local file="$1" name="$2"
  if [[ -f "$file" ]]; then
    case "$(stat -c %a "$file")" in
      400|600) ;;
      *) echo "$file must be readable only by you (chmod 600)" >&2; return 1 ;;
    esac
    [[ -n "$(rg_secret_file_value "$file" "$name")" || -n "${!name:-}" ]] && return 0
    echo "$name is empty in $file; paste the value after the = sign" >&2; return 1
  fi
  [[ -n "${!name:-}" ]] && return 0
  echo "no $name: create $file with a line $name=..., or export $name" >&2; return 1
}

rg_with_secret() {
  local file="$1" name="$2" value; shift 2
  value="$(rg_secret_file_value "$file" "$name")"
  [[ -n "$value" ]] || value="${!name:-}"
  [[ -n "$value" ]] || { echo "no value for $name" >&2; return 1; }
  env "$name=$value" "$@"
}
