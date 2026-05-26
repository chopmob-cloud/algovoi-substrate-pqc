#!/usr/bin/env bash
# Download the Bouncy Castle + org.json jars the Java verifier depends on.
# Idempotent — re-runs are no-ops if files already exist.

set -e
cd "$(dirname "$0")"
mkdir -p lib

BC_VER="1.84"
JSON_VER="20240303"

declare -a JARS=(
  "org/bouncycastle/bcprov-jdk18on/${BC_VER}/bcprov-jdk18on-${BC_VER}.jar"
  "org/bouncycastle/bcutil-jdk18on/${BC_VER}/bcutil-jdk18on-${BC_VER}.jar"
  "org/bouncycastle/bcpkix-jdk18on/${BC_VER}/bcpkix-jdk18on-${BC_VER}.jar"
  "org/json/json/${JSON_VER}/json-${JSON_VER}.jar"
)

for path in "${JARS[@]}"; do
  jar=$(basename "$path")
  if [ -f "lib/$jar" ]; then
    echo "  ok  lib/$jar (already present)"
    continue
  fi
  url="https://repo1.maven.org/maven2/${path}"
  echo "  fetch $url"
  curl -sLo "lib/$jar" "$url"
done

echo
echo "Java verifier dependency jars:"
ls -lh lib/*.jar
