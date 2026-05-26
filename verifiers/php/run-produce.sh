#!/usr/bin/env bash
# Wrapper that auto-loads openssl + sodium for produce.php, mirroring run.sh.

set -e
EXT_DIR=$(php -r 'echo dirname(PHP_BINARY) . DIRECTORY_SEPARATOR . "ext";' 2>/dev/null || true)
ARGS=()
if [ -n "$EXT_DIR" ] && [ -d "$EXT_DIR" ]; then
  if ! php -r 'exit(extension_loaded("openssl") && extension_loaded("sodium") ? 0 : 1);' >/dev/null 2>&1; then
    ARGS+=("-d" "extension_dir=$EXT_DIR" "-d" "extension=openssl" "-d" "extension=sodium")
  fi
fi
exec php "${ARGS[@]}" "$(dirname "$0")/produce.php" "$@"
