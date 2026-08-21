#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
postinstall_source="$repo_root/scripts/pkg/postinstall"
fixture=$(mktemp -d "${TMPDIR:-/tmp}/ctrld-pkg-intercept.XXXXXX")
trap 'rm -rf "$fixture"' EXIT HUP INT TERM

bin="$fixture/bin"
mkdir -p "$bin"

cat >"$bin/defaults" <<'EOF'
#!/bin/sh
key=${3:-}
case "$key" in
    ProvisionToken)
        [ "${FAKE_TOKEN_PRESENT:-0}" = "1" ] || exit 1
        printf '%s\n' "${FAKE_TOKEN:-test-token}"
        ;;
    InterceptMode)
        [ "${FAKE_MODE_PRESENT:-0}" = "1" ] || exit 1
        printf '%s\n' "${FAKE_MODE:-}"
        ;;
    CustomHostname|UseDevEnvironment)
        exit 1
        ;;
    *)
        exit 1
        ;;
esac
EOF

cat >"$bin/launchctl" <<'EOF'
#!/bin/sh
printf 'launchctl %s\n' "$*" >>"$CALLS"
exit 0
EOF

cat >"$bin/ctrld" <<'EOF'
#!/bin/sh
printf 'ctrld %s\n' "$*" >>"$CALLS"
if [ "${FAKE_CTRLD_EXIT:-0}" = "0" ]; then
    case " $* " in
        *" --cd-org="*) : >"$FAKE_PLIST" ;;
    esac
fi
exit "${FAKE_CTRLD_EXIT:-0}"
EOF

chmod +x "$bin/defaults" "$bin/launchctl" "$bin/ctrld"

assert_contains() {
    expected=$1
    file=$2
    if ! grep -Fq -- "$expected" "$file"; then
        printf 'FAIL: expected %s in %s\n' "$expected" "$file" >&2
        sed -n '1,120p' "$file" >&2
        exit 1
    fi
}

assert_not_contains() {
    unexpected=$1
    file=$2
    if grep -Fq -- "$unexpected" "$file"; then
        printf 'FAIL: did not expect %s in %s\n' "$unexpected" "$file" >&2
        sed -n '1,120p' "$file" >&2
        exit 1
    fi
}

run_case() {
    name=$1
    existing=$2
    mode_present=$3
    mode=$4
    ctrld_exit=${5:-0}
    expected_status=${6:-0}
    case_dir="$fixture/$name"
    mkdir -p "$case_dir"
    plist="$case_dir/ctrld.plist"
    prefs="$case_dir/preferences"
    calls="$case_dir/calls"
    output="$case_dir/output"
    postinstall="$case_dir/postinstall"
    : >"$calls"
    if [ "$existing" = "1" ]; then
        : >"$plist"
    fi

    sed \
        -e "s|^PLIST=\"/Library/LaunchDaemons/ctrld.plist\"$|PLIST=\"$plist\"|" \
        -e "s|^CTRLD=\"/usr/local/bin/ctrld\"$|CTRLD=\"$bin/ctrld\"|" \
        -e "s|^PREFS=\"/Library/Managed Preferences/com.controld.ctrld\"$|PREFS=\"$prefs\"|" \
        "$postinstall_source" >"$postinstall"
    chmod +x "$postinstall"

    status=0
    PATH="$bin:$PATH" \
    CALLS="$calls" \
    FAKE_TOKEN_PRESENT=1 \
    FAKE_TOKEN=test-token \
    FAKE_MODE_PRESENT="$mode_present" \
    FAKE_MODE="$mode" \
    FAKE_CTRLD_EXIT="$ctrld_exit" \
    FAKE_PLIST="$plist" \
    "$postinstall" >"$output" 2>&1 || status=$?

    if [ "$status" -ne "$expected_status" ]; then
        printf 'FAIL: %s exited %s, want %s\n' "$name" "$status" "$expected_status" >&2
        sed -n '1,120p' "$output" >&2
        exit 1
    fi

    printf '%s\n' "$case_dir"
}

assert_not_contains 'CTRLD_POSTINSTALL_' "$postinstall_source"

case_dir=$(run_case fresh-legacy 0 0 '')
assert_contains 'ctrld start --cd-org=test-token' "$case_dir/calls"
assert_not_contains '--intercept-mode' "$case_dir/calls"

case_dir=$(run_case fresh-standard 0 1 standard)
assert_contains 'ctrld start --cd-org=test-token' "$case_dir/calls"
assert_not_contains '--intercept-mode' "$case_dir/calls"

case_dir=$(run_case fresh-intercept 0 1 intercept-dns)
assert_contains 'ctrld start --cd-org=test-token --intercept-mode dns' "$case_dir/calls"

case_dir=$(run_case upgrade-legacy 1 0 '')
assert_contains 'launchctl load' "$case_dir/calls"
assert_not_contains 'ctrld start' "$case_dir/calls"

case_dir=$(run_case upgrade-standard 1 1 standard)
assert_contains 'ctrld start --intercept-mode off' "$case_dir/calls"
assert_not_contains 'launchctl load' "$case_dir/calls"

case_dir=$(run_case upgrade-intercept 1 1 intercept-dns)
assert_contains 'ctrld start --intercept-mode dns' "$case_dir/calls"
assert_not_contains 'launchctl load' "$case_dir/calls"

case_dir=$(run_case fresh-invalid 0 1 invalid)
assert_contains 'WARNING: unsupported InterceptMode in managed preferences; using standard mode' "$case_dir/output"
assert_not_contains '--intercept-mode' "$case_dir/calls"

case_dir=$(run_case upgrade-invalid 1 1 invalid)
assert_contains 'WARNING: unsupported InterceptMode in managed preferences; preserving existing service mode' "$case_dir/output"
assert_contains 'launchctl load' "$case_dir/calls"
assert_not_contains 'ctrld start' "$case_dir/calls"

case_dir=$(run_case upgrade-standard-failure 1 1 standard 1 1)
assert_contains 'ctrld start --intercept-mode off' "$case_dir/calls"
assert_contains 'ERROR: upgrade installed but managed InterceptMode could not be applied' "$case_dir/output"
assert_not_contains 'launchctl load' "$case_dir/calls"

printf 'PASS: pkg postinstall preserves legacy mode and applies standard/intercept-dns policy\n'
