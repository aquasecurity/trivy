#!/bin/sh
# install_test.sh — self-contained smoke tests for contrib/install.sh helpers.
# Exercises hash_sha256_verify_value (network-free) so it can run in CI.
set -e

dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
script="$dir/install.sh"

if [ ! -f "$script" ]; then
  echo "FAIL: cannot locate install.sh next to install_test.sh" >&2
  exit 1
fi

# install.sh executes the install flow on source, so extract just the helpers.
helpers=$(mktemp)
trap 'rm -f "$helpers"' EXIT

awk '
  /^is_command\(\) \{/        { in_blk=1 }
  /^hash_sha256\(\) \{/        { in_blk=1 }
  /^hash_sha256_verify_value\(\) \{/ { in_blk=1 }
  in_blk { print }
  in_blk && /^\}$/ { in_blk=0 }
' "$script" > "$helpers"

# Stub log_* so the helpers do not need install.sh main logger.
log_err()   { echo "ERR: $*" >&2; }
log_crit()  { echo "CRIT: $*" >&2; }
log_info()  { echo "INFO: $*" >&2; }
log_debug() { :; }

# shellcheck disable=SC1090
. "$helpers"

if ! command -v hash_sha256_verify_value >/dev/null 2>&1; then
  echo "FAIL: hash_sha256_verify_value not loaded" >&2
  exit 1
fi

work=$(mktemp -d)
fixture="$work/payload"
printf 'trivy install.sh test fixture\n' > "$fixture"
expected=$(hash_sha256 "$fixture")

pass=0
fail=0
expect() {
  desc=$1
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
    echo "FAIL: $desc (expected=$expected_status actual=$actual)" >&2
  fi
}

expect "verifies a correct sha256"               ok   hash_sha256_verify_value "$fixture" "$expected"
expect "rejects an incorrect sha256"             fail hash_sha256_verify_value "$fixture" "0000000000000000000000000000000000000000000000000000000000000000"
expect "rejects an empty sha256"                 fail hash_sha256_verify_value "$fixture" ""
expect "rejects a missing target file"           fail hash_sha256_verify_value "$work/missing" "$expected"

rm -rf "$work"

echo "install_test.sh: pass=$pass fail=$fail"
[ "$fail" = 0 ]
