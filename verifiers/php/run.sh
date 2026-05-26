#!/usr/bin/env bash
# Wrapper that auto-loads openssl + sodium extensions if not already in php.ini.
# Useful on environments (e.g. WinGet-installed PHP on Windows) where the
# crypto extensions ship in the install ext/ dir but aren't enabled by default.

set -e

# Auto-detect PHP ext dir from `php -r`.
EXT_DIR=$(php -r 'echo dirname(PHP_BINARY) . DIRECTORY_SEPARATOR . "ext";' 2>/dev/null || true)

ARGS=()
if [ -n "$EXT_DIR" ] && [ -d "$EXT_DIR" ]; then
  # Only inject if extensions aren't already loaded.
  if ! php -r 'exit(extension_loaded("openssl") && extension_loaded("sodium") ? 0 : 1);' >/dev/null 2>&1; then
    ARGS+=("-d" "extension_dir=$EXT_DIR" "-d" "extension=openssl" "-d" "extension=sodium")
  fi
fi

exec php "${ARGS[@]}" "$(dirname "$0")/verify.php" "$@"
