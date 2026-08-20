#!/bin/sh
# Test: the MDM pkg postinstall script surfaces ctrld's provisioning
# failure identifier in its output without leaking the provision token,
# and still reports success once the plist exists.
#
# Self-contained and root-free: every path postinstall touches is
# redirected into a throwaway temp directory via the
# CTRLD_POSTINSTALL_{PLIST,CTRLD,PREFS} overrides, and 'defaults' is
# stubbed on PATH so the profile-wait loop resolves on its first attempt.
#
# Out of scope: the upgrade path (plist already exists) calls the real
# launchctl and is not exercised here.
#
# Run: sh test-postinstall-provision-failure.sh

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
POSTINSTALL="$SCRIPT_DIR/../../scripts/pkg/postinstall"

WORKDIR=$(mktemp -d -t ctrld-postinstall-test) || {
    echo "FAIL: could not create test work directory" >&2
    exit 1
}
trap 'rm -rf "$WORKDIR"' EXIT

FAKE_TOKEN="FAKE-PROVISION-TOKEN-DO-NOT-LEAK-93af0c"
export FAKE_TOKEN

STUBBIN="$WORKDIR/stubbin"
mkdir -p "$STUBBIN"

cat > "$STUBBIN/defaults" <<'STUB'
#!/bin/sh
# Stand-in for macOS 'defaults read <domain> <key>': answers ProvisionToken
# immediately, like a profile that only sets that one key, so the
# postinstall wait loop never has to sleep.
if [ "$1" = "read" ] && [ "$3" = "ProvisionToken" ]; then
    echo "$FAKE_TOKEN"
    exit 0
fi
exit 1
STUB
chmod +x "$STUBBIN/defaults"

FAILURES=0

fail() {
    echo "FAIL: $1" >&2
    FAILURES=$((FAILURES + 1))
}

assert_eq() {
    # assert_eq <actual> <expected> <description>
    if [ "$1" != "$2" ]; then
        fail "$3 (expected '$2', got '$1')"
    fi
}

assert_contains() {
    # assert_contains <haystack> <needle> <description>
    case "$1" in
        *"$2"*) ;;
        *) fail "$3 (expected to find '$2')" ;;
    esac
}

assert_not_contains() {
    # assert_not_contains <haystack> <needle> <description>
    case "$1" in
        *"$2"*) fail "$3 (must not contain '$2')" ;;
        *) ;;
    esac
}

# run_postinstall runs postinstall with the given plist/ctrld overrides and
# a private TMPDIR, so the caller can check that the postinstall's own
# capture file (created inside that TMPDIR via mktemp) does not survive.
run_postinstall() {
    plist_override=$1
    ctrld_override=$2
    capture_tmpdir=$3
    output=$(PATH="$STUBBIN:$PATH" \
        TMPDIR="$capture_tmpdir" \
        CTRLD_POSTINSTALL_PLIST="$plist_override" \
        CTRLD_POSTINSTALL_CTRLD="$ctrld_override" \
        CTRLD_POSTINSTALL_PREFS="/does/not/matter" \
        sh "$POSTINSTALL" 2>&1)
    exit_code=$?
}

# --- Failure case: ctrld reports a listener bind failure ---------------

failure_dir="$WORKDIR/failure"
failure_tmp="$failure_dir/tmp"
mkdir -p "$failure_tmp"
failure_plist="$failure_dir/ctrld.plist"
failure_ctrld="$failure_dir/ctrld"

cat > "$failure_ctrld" <<'STUB'
#!/bin/sh
# Stands in for a ctrld that fails to bind its listener: echoes the raw
# token (as ctrld's own error output may) plus the fixed-format failure
# identifier behind a log-style prefix, then exits with the stage code.
echo "$FAKE_TOKEN"
echo "2024-01-01T00:00:00Z ERR ctrld: provisioning failed: stage=listener code=LISTENER_BIND_FAILED (exit 41)"
exit 41
STUB
chmod +x "$failure_ctrld"

run_postinstall "$failure_plist" "$failure_ctrld" "$failure_tmp"

assert_eq "$exit_code" "1" "failure case: postinstall exit code"
assert_contains "$output" "stage=listener" "failure case: output names the stage"
assert_contains "$output" "LISTENER_BIND_FAILED" "failure case: output names the code"
assert_contains "$output" "41" "failure case: output names the exit code"
assert_not_contains "$output" "$FAKE_TOKEN" "failure case: output must not contain the provision token"

leftover=$(ls -A "$failure_tmp" 2>/dev/null)
assert_eq "$leftover" "" "failure case: capture temp file removed"

# --- Success case: ctrld provisions and writes the plist ----------------

success_dir="$WORKDIR/success"
success_tmp="$success_dir/tmp"
mkdir -p "$success_tmp"
success_plist="$success_dir/ctrld.plist"
success_ctrld="$success_dir/ctrld"

cat > "$success_ctrld" <<STUB
#!/bin/sh
# Stands in for a ctrld that provisions successfully: writes the plist
# postinstall's success gate checks for, then exits clean.
: > "$success_plist"
exit 0
STUB
chmod +x "$success_ctrld"

run_postinstall "$success_plist" "$success_ctrld" "$success_tmp"

assert_eq "$exit_code" "0" "success case: postinstall exit code"
assert_contains "$output" "provisioning complete" "success case: output mentions success"

if [ "$FAILURES" -gt 0 ]; then
    echo "$FAILURES assertion(s) failed" >&2
    exit 1
fi

echo "OK: postinstall surfaces provisioning failure codes without leaking the token"
exit 0
