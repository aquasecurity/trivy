#!/bin/sh
# install_test.sh — self-contained smoke tests for contrib/install.sh helpers.
# Exercises checksum verification without contacting GitHub or downloading a release.
set -eu

dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
script="$dir/install.sh"

if [ ! -f "$script" ]; then
  echo "FAIL: cannot locate install.sh next to install_test.sh" >&2
  exit 1
fi

# install.sh executes the install flow on source, so extract only the helpers.
helpers=$(mktemp)
work=$(mktemp -d)
trap 'rm -f "$helpers"; rm -rf "$work"' EXIT

awk '
  /^is_command\(\) \{/ || /^hash_sha256\(\) \{/ || /^hash_sha256_verify\(\) \{/ || /^hash_sha256_verify_value\(\) \{/ { in_blk=1 }
  in_blk { print }
  in_blk && /^\}$/ { in_blk=0 }
' "$script" > "$helpers"

# shellcheck disable=SC1090
. "$helpers"

if ! command -v hash_sha256_verify_value >/dev/null 2>&1; then
  echo "FAIL: hash_sha256_verify_value was not loaded" >&2
  exit 1
fi

fixture="$work/payload"
printf '%s\n' 'trivy install.sh checksum test fixture' > "$fixture"
expected=$(hash_sha256 "$fixture")
uppercase=$(printf '%s' "$expected" | tr '[:lower:]' '[:upper:]')
zeroes=0000000000000000000000000000000000000000000000000000000000000000

pass=0
fail=0
expect() {
  description=$1
  expected_status=$2
  shift 2
  if "$@" >/dev/null 2>&1; then
    actual=ok
  else
    actual=fail
  fi
  if [ "$actual" = "$expected_status" ]; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    echo "FAIL: $description (expected=$expected_status actual=$actual)" >&2
  fi
}

expect 'accepts a correct lowercase SHA-256' ok hash_sha256_verify_value "$fixture" "$expected"
expect 'accepts a correct uppercase SHA-256' ok hash_sha256_verify_value "$fixture" "$uppercase"
expect 'rejects an incorrect SHA-256' fail hash_sha256_verify_value "$fixture" "$zeroes"
expect 'rejects an empty SHA-256' fail hash_sha256_verify_value "$fixture" ''
expect 'rejects a missing target file' fail hash_sha256_verify_value "$work/missing" "$expected"

# Invalid user input must fail before the installer performs a network lookup.
expect 'rejects an invalid -s value before release lookup' fail "$script" -s short
expect 'rejects an invalid TRIVY_CHECKSUM before release lookup' fail env TRIVY_CHECKSUM=short "$script"

printf 'install_test.sh: pass=%s fail=%s\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
