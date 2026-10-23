#!/bin/sh
# Test: the MDM pkg postinstall script validates managed prefs before
# running ctrld, classifies every failure (pre-flight or post-invoke) with
# a stable 'stage=package code=<CODE>' identifier line, best-effort appends
# 'ctrld-client diag' output on failure, and never leaks the provision token.
#
# Self-contained and root-free: each case runs a copy of the real
# postinstall script with its PLIST/CTRLD/PREFS assignments sed-rewritten
# to fixture paths (same seam as test-pkg-intercept-mode.sh), with
# 'defaults', 'launchctl', and 'ctrld-client' stubbed on PATH. No macOS-only API is
# used, so this runs as plain POSIX sh on Linux too.
#
# With POSTINSTALL_TEST_REAL_DEFAULTS=1 on macOS, 'defaults' is not stubbed:
# each case writes its managed-prefs values into a real plist under the
# fixture dir with 'defaults write', and the postinstall copy reads them
# with the real binary. This tests the one boundary a stub cannot: what
# 'defaults read' prints and exits with for an empty string, a boolean, a
# control character, or a missing key. ctrld and launchctl stay stubbed, so
# the run never touches the services of the machine.
#
# The wait loop between profile attempts is shortened to 0 seconds in the
# copy under test. The attempt count and the log lines stay as they are.
#
# Run: sh test-postinstall-provision-failure.sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
postinstall_source="$repo_root/scripts/pkg/postinstall"

fixture=$(mktemp -d "${TMPDIR:-/tmp}/ctrld-postinstall-test.XXXXXX")
trap 'rm -rf "$fixture"' EXIT HUP INT TERM

# A well-formed fake token used for cases that must reach ctrld (success,
# ctrld-emitted-identifier passthrough). Obviously fake, but still checked
# for non-leakage like a real one would be.
GOOD_TOKEN="org-v1-FAKE93af0cDONOTLEAK"
# A present-but-malformed value (contains whitespace) for the
# PROVISION_TOKEN_MALFORMED case.
MALFORMED_TOKEN="FAKE TOKEN WITH SPACE DO NOT LEAK"
# A second, differently-shaped org-v1- token: never the value read from
# managed prefs, so it can only be caught by the pattern-based redaction,
# not the exact-match one.
OTHER_ORG_TOKEN="org-v1-DIFFERENTshape001"
export GOOD_TOKEN MALFORMED_TOKEN OTHER_ORG_TOKEN

# Real mktemp, resolved before the fixture bin/ overrides PATH, so the
# mktemp stub can fall through to it when a test case is not forcing a
# failure.
REAL_MKTEMP=$(command -v mktemp)
export REAL_MKTEMP

bin="$fixture/bin"
mkdir -p "$bin"

real_defaults=${POSTINSTALL_TEST_REAL_DEFAULTS:-0}
if [ "$real_defaults" = "1" ] && [ "$(uname -s)" != "Darwin" ]; then
    echo "POSTINSTALL_TEST_REAL_DEFAULTS=1 needs macOS: the real 'defaults' binary is the point of this mode" >&2
    exit 2
fi

# --- Stubs -----------------------------------------------------------

if [ "$real_defaults" != "1" ]; then
cat >"$bin/defaults" <<'EOF'
#!/bin/sh
# Stand-in for macOS 'defaults read <domain> <key>'. Every key answers from
# a FAKE_*_PRESENT/FAKE_* pair the test case exports beforehand; a key with
# no *_PRESENT=1 comes back unset, like a profile that never set it.
key=${3:-}
case "$key" in
    ProvisionToken)
        [ "${FAKE_TOKEN_PRESENT:-0}" = "1" ] || exit 1
        printf '%s\n' "${FAKE_TOKEN_VALUE:-}"
        ;;
    CustomHostname)
        [ "${FAKE_HOST_PRESENT:-0}" = "1" ] || exit 1
        printf '%s\n' "${FAKE_HOST:-}"
        ;;
    InterceptMode)
        [ "${FAKE_MODE_PRESENT:-0}" = "1" ] || exit 1
        printf '%s\n' "${FAKE_MODE:-}"
        ;;
    UseDevEnvironment)
        [ "${FAKE_DEVENV_PRESENT:-0}" = "1" ] || exit 1
        printf '%s\n' "${FAKE_DEVENV:-}"
        ;;
    *)
        exit 1
        ;;
esac
EOF
chmod +x "$bin/defaults"
fi

# write_real_prefs materializes the FAKE_* managed-prefs values of the
# current case into a real plist at "$1", the path the postinstall copy
# reads as its PREFS domain. A key with no *_PRESENT=1 is not written, like
# a profile that never set it.
write_real_prefs() {
    domain=$1
    [ "${FAKE_TOKEN_PRESENT:-0}" = "1" ] && defaults write "$domain" ProvisionToken -string "${FAKE_TOKEN_VALUE:-}"
    [ "${FAKE_HOST_PRESENT:-0}" = "1" ] && defaults write "$domain" CustomHostname -string "${FAKE_HOST:-}"
    [ "${FAKE_MODE_PRESENT:-0}" = "1" ] && defaults write "$domain" InterceptMode -string "${FAKE_MODE:-}"
    [ "${FAKE_DEVENV_PRESENT:-0}" = "1" ] && defaults write "$domain" UseDevEnvironment -string "${FAKE_DEVENV:-}"
    return 0
}

cat >"$bin/launchctl" <<'EOF'
#!/bin/sh
[ -n "${CALLS:-}" ] && printf 'launchctl %s\n' "$*" >>"$CALLS"
exit "${FAKE_LAUNCHCTL_EXIT:-0}"
EOF
chmod +x "$bin/launchctl"

cat >"$bin/ctrld-client" <<'EOF'
#!/bin/sh
[ -n "${CALLS:-}" ] && printf 'ctrld-client %s\n' "$*" >>"$CALLS"

if [ "$1" = "diag" ]; then
    if [ "${FAKE_DIAG_TRAPS_TERM:-0}" = "1" ]; then
        # Ignores the polite signal, so only SIGKILL can end it. Proves
        # postinstall's wait stays bounded either way.
        trap '' TERM
        sleep 30
        exit 0
    fi
    if [ "${FAKE_DIAG_WORKS:-0}" = "1" ]; then
        echo "resolver: healthy"
        echo "listener: 127.0.0.1:53 bound"
        [ -n "${FAKE_DIAG_LEAK_LINE:-}" ] && echo "$FAKE_DIAG_LEAK_LINE"
        exit 0
    fi
    echo "ctrld-client: unknown command \"diag\"" >&2
    exit 1
fi

if [ "${FAKE_CTRLD_EXIT:-0}" = "0" ]; then
    : >"$FAKE_PLIST"
    exit 0
fi
# The service manager writes the plist at install time, before the start
# step, so a start failure leaves it behind. Reproduced so the test can
# prove postinstall does not read that leftover as success.
[ "${FAKE_CTRLD_CREATE_PLIST:-0}" = "1" ] && : >"$FAKE_PLIST"
# A real ctrld may echo the raw token on error; reproduced here so the test
# can prove postinstall never lets it reach install.log.
echo "$GOOD_TOKEN"
[ -n "${FAKE_CTRLD_IDENTIFIER:-}" ] && echo "$FAKE_CTRLD_IDENTIFIER"
exit "$FAKE_CTRLD_EXIT"
EOF
chmod +x "$bin/ctrld-client"

cat >"$bin/mktemp" <<'EOF'
#!/bin/sh
# Stand-in for mktemp: forces the postinstall script's own mktemp failure
# branch on demand, otherwise falls through to the real mktemp.
if [ "${FAKE_MKTEMP_FAIL:-0}" = "1" ]; then
    exit 1
fi
exec "$REAL_MKTEMP" "$@"
EOF
chmod +x "$bin/mktemp"

# --- Assertion helpers -------------------------------------------------

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

assert_not_contains "$(cat "$postinstall_source")" "CTRLD_POSTINSTALL_" "production script must not depend on removed env-var overrides"

# --- Fixture plumbing ---------------------------------------------------

# make_postinstall_copy writes a copy of the real postinstall script with
# its PLIST/CTRLD/PREFS assignments rewritten to fixture paths, so the test
# drives the actual production logic instead of a re-implementation.
make_postinstall_copy() {
    plist_override=$1
    ctrld_override=$2
    prefs_override=$3
    dest=$4
    sed \
        -e "s|^PLIST=\"/Library/LaunchDaemons/ctrld-client.plist\"\$|PLIST=\"$plist_override\"|" \
        -e "s|^CTRLD=\"/usr/local/bin/ctrld-client\"\$|CTRLD=\"$ctrld_override\"|" \
        -e "s|^PREFS=\"/Library/Managed Preferences/com.controld.ctrld\"\$|PREFS=\"$prefs_override\"|" \
        -e "s|^        sleep 10\$|        sleep 0|" \
        "$postinstall_source" >"$dest"
    chmod +x "$dest"
    # A substitution that stops matching is silent: the copy keeps the real
    # system paths and the case runs against the installed machine. Check
    # that each redirection landed.
    for expected in "PLIST=\"$plist_override\"" "CTRLD=\"$ctrld_override\"" "PREFS=\"$prefs_override\""; do
        if ! grep -Fq -- "$expected" "$dest"; then
            printf 'FAIL: fixture substitution did not apply (%s); postinstall paths changed?\n' "$expected" >&2
            exit 1
        fi
    done
    if grep -Eq '^(PLIST|CTRLD|PREFS)="(/Library|/usr/local)' "$dest"; then
        printf 'FAIL: a real system path survived substitution\n' >&2
        grep -E '^(PLIST|CTRLD|PREFS)=' "$dest" >&2
        exit 1
    fi
}

# reset_fakes clears every FAKE_*/CALLS override so one case's env can never
# leak into the next.
reset_fakes() {
    unset FAKE_TOKEN_PRESENT FAKE_TOKEN_VALUE FAKE_HOST_PRESENT FAKE_HOST \
        FAKE_MODE_PRESENT FAKE_MODE FAKE_DEVENV_PRESENT FAKE_DEVENV \
        FAKE_CTRLD_EXIT FAKE_CTRLD_IDENTIFIER FAKE_CTRLD_CREATE_PLIST \
        FAKE_DIAG_WORKS FAKE_DIAG_LEAK_LINE FAKE_DIAG_TRAPS_TERM \
        FAKE_LAUNCHCTL_EXIT FAKE_MKTEMP_FAIL CALLS 2>/dev/null || true
}

# run_case sets up a fresh fixture dir (plist, prefs, private TMPDIR, a
# calls log) for "$name", runs a fixture-rewritten postinstall copy with
# every currently-exported FAKE_* var visible to the stubs, and leaves
# $output/$exit_code/$case_dir set for the caller's assertions.
run_case() {
    name=$1
    existing_plist=${2:-0}
    case_dir="$fixture/$name"
    case_tmp="$case_dir/tmp"
    mkdir -p "$case_tmp"
    plist="$case_dir/ctrld-client.plist"
    prefs="$case_dir/prefs"
    calls="$case_dir/calls"
    output_file="$case_dir/output"
    postinstall="$case_dir/postinstall"
    : >"$calls"
    [ "$existing_plist" = "1" ] && : >"$plist"
    [ "$real_defaults" = "1" ] && write_real_prefs "$prefs"

    make_postinstall_copy "$plist" "$bin/ctrld-client" "$prefs" "$postinstall"

    status=0
    PATH="$bin:$PATH" \
        TMPDIR="$case_tmp" \
        FAKE_PLIST="$plist" \
        CALLS="$calls" \
        "$postinstall" >"$output_file" 2>&1 || status=$?

    exit_code=$status
    output=$(cat "$output_file")
    calls_out=$(cat "$calls")
}

# --- Case: missing prefs -> PROFILE_PREFS_MISSING -----------------------
# Runs postinstall's real wait loop to exhaustion (~110s): no seam shortens
# it, since that timing is untouched by this change.

reset_fakes
run_case missing-prefs

assert_eq "$exit_code" "1" "missing-prefs: exit code"
assert_contains "$output" "stage=package code=PROFILE_PREFS_MISSING (exit 1)" "missing-prefs: identifier line"
assert_contains "$output" "Scope the com.controld.ctrld configuration profile" "missing-prefs: remediation hint kept"
assert_not_contains "$calls_out" "ctrld-client start" "missing-prefs: ctrld start never invoked"

# --- Case: malformed token -> PROVISION_TOKEN_MALFORMED -----------------

reset_fakes
export FAKE_TOKEN_PRESENT=1 FAKE_TOKEN_VALUE="$MALFORMED_TOKEN"
run_case malformed-token

assert_eq "$exit_code" "1" "malformed-token: exit code"
assert_contains "$output" "stage=package code=PROVISION_TOKEN_MALFORMED (exit 1)" "malformed-token: identifier line"
assert_not_contains "$output" "$MALFORMED_TOKEN" "malformed-token: token value must not leak"
assert_not_contains "$calls_out" "ctrld-client start" "malformed-token: ctrld start never invoked"

# --- Case: bad CustomHostname -> CUSTOM_HOSTNAME_INVALID -----------------

reset_fakes
export FAKE_TOKEN_PRESENT=1 FAKE_TOKEN_VALUE="$GOOD_TOKEN"
export FAKE_HOST_PRESENT=1 FAKE_HOST="bad host!"
run_case bad-hostname

assert_eq "$exit_code" "1" "bad-hostname: exit code"
assert_contains "$output" "stage=package code=CUSTOM_HOSTNAME_INVALID (exit 1)" "bad-hostname: identifier line"
assert_contains "$output" "bad host!" "bad-hostname: message names the hostname"
assert_not_contains "$output" "$GOOD_TOKEN" "bad-hostname: token value must not leak"
assert_not_contains "$calls_out" "ctrld-client start" "bad-hostname: ctrld start never invoked"

# --- Case: token pasted into CustomHostname -> message is redacted --------
# An admin can fill any managed-prefs key with the token by mistake. The
# CUSTOM_HOSTNAME_INVALID message echoes the value, so the log line must
# carry the redaction marker and never the token.

reset_fakes
export FAKE_TOKEN_PRESENT=1 FAKE_TOKEN_VALUE="$GOOD_TOKEN"
export FAKE_HOST_PRESENT=1 FAKE_HOST="${GOOD_TOKEN}!"
run_case token-in-hostname

assert_eq "$exit_code" "1" "token-in-hostname: exit code"
assert_contains "$output" "stage=package code=CUSTOM_HOSTNAME_INVALID (exit 1)" "token-in-hostname: identifier line"
assert_contains "$output" "[redacted-token]" "token-in-hostname: message carries the redaction marker"
assert_not_contains "$output" "$GOOD_TOKEN" "token-in-hostname: token value must not leak"

# --- Case: token pasted into UseDevEnvironment -> warning is redacted ------

reset_fakes
export FAKE_TOKEN_PRESENT=1 FAKE_TOKEN_VALUE="$GOOD_TOKEN"
export FAKE_DEVENV_PRESENT=1 FAKE_DEVENV="$GOOD_TOKEN"
export FAKE_CTRLD_EXIT=0
run_case token-in-dev-env

assert_eq "$exit_code" "0" "token-in-dev-env: exit code"
assert_contains "$output" "WARNING: UseDevEnvironment value" "token-in-dev-env: still warns on the bad value"
assert_contains "$output" "[redacted-token]" "token-in-dev-env: warning carries the redaction marker"
assert_not_contains "$output" "$GOOD_TOKEN" "token-in-dev-env: token value must not leak"

# --- Case: CustomHostname structural failures (RFC1123 mirror) -----------
# Same rule as cmd/cli/hostname.go's validHostname: 3-64 characters, then
# dot-separated labels that start and end on a letter or digit (no
# leading/trailing hyphen or dot, no empty label). None of these contain a
# disallowed character, so only the structural check can catch them.

bad_hostname_idx=0
for bad_host in '-' '.abc' 'abc-' 'a'; do
    bad_hostname_idx=$((bad_hostname_idx + 1))
    reset_fakes
    export FAKE_TOKEN_PRESENT=1 FAKE_TOKEN_VALUE="$GOOD_TOKEN"
    export FAKE_HOST_PRESENT=1 FAKE_HOST="$bad_host"
    run_case "bad-hostname-struct-$bad_hostname_idx"
    assert_eq "$exit_code" "1" "bad-hostname-struct '$bad_host': exit code"
    assert_contains "$output" "stage=package code=CUSTOM_HOSTNAME_INVALID (exit 1)" "bad-hostname-struct '$bad_host': identifier line"
    assert_not_contains "$calls_out" "ctrld-client start" "bad-hostname-struct '$bad_host': ctrld start never invoked"
done

long_host=""
i=0
while [ "$i" -lt 90 ]; do
    long_host="${long_host}a"
    i=$((i + 1))
done

reset_fakes
export FAKE_TOKEN_PRESENT=1 FAKE_TOKEN_VALUE="$GOOD_TOKEN"
export FAKE_HOST_PRESENT=1 FAKE_HOST="$long_host"
run_case bad-hostname-too-long

assert_eq "$exit_code" "1" "bad-hostname-too-long: exit code"
assert_contains "$output" "stage=package code=CUSTOM_HOSTNAME_INVALID (exit 1)" "bad-hostname-too-long: identifier line"
assert_not_contains "$calls_out" "ctrld-client start" "bad-hostname-too-long: ctrld start never invoked"

# --- Case: dotted CustomHostname is valid, passes through ----------------

reset_fakes
export FAKE_TOKEN_PRESENT=1 FAKE_TOKEN_VALUE="$GOOD_TOKEN"
export FAKE_HOST_PRESENT=1 FAKE_HOST="foo.bar"
export FAKE_CTRLD_EXIT=0
run_case good-hostname-dotted

assert_eq "$exit_code" "0" "good-hostname-dotted: exit code"
assert_contains "$calls_out" "--custom-hostname=foo.bar" "good-hostname-dotted: passed through to ctrld"

# --- Case: bad InterceptMode, fresh install -> fails, INTERCEPT_MODE_INVALID

reset_fakes
export FAKE_TOKEN_PRESENT=1 FAKE_TOKEN_VALUE="$GOOD_TOKEN"
export FAKE_MODE_PRESENT=1 FAKE_MODE="bogus"
run_case bad-mode-fresh

assert_eq "$exit_code" "1" "bad-mode-fresh: exit code"
assert_contains "$output" "stage=package code=INTERCEPT_MODE_INVALID (exit 1)" "bad-mode-fresh: identifier line"
assert_not_contains "$output" "$GOOD_TOKEN" "bad-mode-fresh: token value must not leak"
assert_not_contains "$calls_out" "ctrld-client start" "bad-mode-fresh: ctrld start never invoked"

# --- Case: bad InterceptMode, upgrade -> warns, keeps mode, exit 0 -------

reset_fakes
export FAKE_MODE_PRESENT=1 FAKE_MODE="bogus"
run_case bad-mode-upgrade 1

assert_eq "$exit_code" "0" "bad-mode-upgrade: exit code"
assert_contains "$output" "WARNING: unsupported InterceptMode in managed preferences; preserving existing service mode" "bad-mode-upgrade: warns"
assert_contains "$calls_out" "launchctl load" "bad-mode-upgrade: falls back to launchctl load"
assert_not_contains "$calls_out" "ctrld-client " "bad-mode-upgrade: ctrld start never invoked"

# --- Case: upgrade reload fails -> SERVICE_RELOAD_FAILED -----------------
# No managed InterceptMode override, so postinstall falls back to
# reloading the existing service; launchctl itself fails.

reset_fakes
export FAKE_LAUNCHCTL_EXIT=1
run_case reload-fails 1

assert_eq "$exit_code" "1" "reload-fails: exit code"
assert_contains "$output" "stage=package code=SERVICE_RELOAD_FAILED (exit 1)" "reload-fails: identifier line"
assert_contains "$output" "sudo launchctl load" "reload-fails: remediation hint kept"
assert_contains "$calls_out" "launchctl load" "reload-fails: launchctl load was attempted"
assert_contains "$calls_out" "ctrld-client diag" "reload-fails: diag block attempted"

# --- Case: unrecognized UseDevEnvironment value -> warns, still installs -

reset_fakes
export FAKE_TOKEN_PRESENT=1 FAKE_TOKEN_VALUE="$GOOD_TOKEN"
export FAKE_DEVENV_PRESENT=1 FAKE_DEVENV="banana"
export FAKE_CTRLD_EXIT=0
run_case bad-dev-env

assert_eq "$exit_code" "0" "bad-dev-env: exit code"
assert_contains "$output" 'WARNING: UseDevEnvironment value "banana" is not recognized; ignoring' "bad-dev-env: warns on the bad value"
assert_contains "$output" "provisioning complete, service installed" "bad-dev-env: install still proceeds"
assert_not_contains "$calls_out" "--dev" "bad-dev-env: unrecognized value never turns on --dev"
assert_not_contains "$output" "$GOOD_TOKEN" "bad-dev-env: token value must not leak"

# --- Case: ctrld-emitted identifier passthrough --------------------------
# The token and hostname both pass postinstall's own shape checks; ctrld
# itself rejects the token and reports its own fixed-format identifier,
# which postinstall must surface unmodified.

reset_fakes
export FAKE_TOKEN_PRESENT=1 FAKE_TOKEN_VALUE="$GOOD_TOKEN"
export FAKE_CTRLD_EXIT=22
export FAKE_CTRLD_IDENTIFIER="provisioning failed: stage=input code=PROVISION_TOKEN_MALFORMED (exit 22)"
run_case ctrld-identifier-passthrough

assert_eq "$exit_code" "1" "identifier-passthrough: exit code"
assert_contains "$output" "provisioning failed: stage=input code=PROVISION_TOKEN_MALFORMED (exit 22)" "identifier-passthrough: surfaces ctrld's own identifier"
assert_contains "$output" "ctrld exit 22" "identifier-passthrough: names ctrld's exit code"
assert_not_contains "$output" "$GOOD_TOKEN" "identifier-passthrough: token value must not leak"

# --- Case: service start fails after install wrote the plist -------------

reset_fakes
export FAKE_TOKEN_PRESENT=1 FAKE_TOKEN_VALUE="$GOOD_TOKEN"
export FAKE_CTRLD_EXIT=52 FAKE_CTRLD_CREATE_PLIST=1
export FAKE_CTRLD_IDENTIFIER="provisioning failed: stage=service code=SERVICE_START_FAILED (exit 52)"
run_case start-fails-plist-present

assert_eq "$exit_code" "1" "start-fails-plist-present: exit code"
assert_contains "$output" "stage=service code=SERVICE_START_FAILED (exit 52)" "start-fails-plist-present: identifier line"
assert_not_contains "$output" "provisioning complete" "start-fails-plist-present: leftover plist is not success"
assert_not_contains "$output" "$GOOD_TOKEN" "start-fails-plist-present: token value must not leak"

# --- Case: empty ProvisionToken -> PROFILE_PREFS_MISSING with its own hint --

reset_fakes
export FAKE_TOKEN_PRESENT=1 FAKE_TOKEN_VALUE=""
run_case empty-token

assert_eq "$exit_code" "1" "empty-token: exit code"
assert_contains "$output" "stage=package code=PROFILE_PREFS_MISSING (exit 1)" "empty-token: identifier line"
assert_contains "$output" "ProvisionToken value is empty" "empty-token: names the empty value, not a missing profile"
assert_not_contains "$calls_out" "ctrld-client start" "empty-token: ctrld start never invoked"

# --- Case: control character in token arrives escaped, passes preflight ----
# 'defaults read' prints a non-whitespace control character as escaped text
# (a byte 0x01 becomes the four characters \001), so the preflight sees a
# plain 6-64 character value and hands it to ctrld unchanged. The stub emits
# that escaped text; real-defaults mode stores the raw byte and lets the
# real binary escape it.

reset_fakes
if [ "$real_defaults" = "1" ]; then
    export FAKE_TOKEN_PRESENT=1 FAKE_TOKEN_VALUE="$(printf 'org-v1-abc\001def')"
else
    export FAKE_TOKEN_PRESENT=1 FAKE_TOKEN_VALUE='org-v1-abc\001def'
fi
export FAKE_CTRLD_EXIT=0
run_case control-char-token-escaped

assert_eq "$exit_code" "0" "control-char-token-escaped: preflight passes the escaped text"
assert_contains "$calls_out" 'ctrld-client start --cd-org=org-v1-abc\001def' "control-char-token-escaped: ctrld receives the escaped text unchanged"
assert_not_contains "$output" "PROVISION_TOKEN_MALFORMED" "control-char-token-escaped: preflight does not classify escaped text as malformed"

# --- Case: UseDevEnvironment false -> no warning, no --dev -----------------

reset_fakes
export FAKE_TOKEN_PRESENT=1 FAKE_TOKEN_VALUE="$GOOD_TOKEN"
export FAKE_DEVENV_PRESENT=1 FAKE_DEVENV="0"
export FAKE_CTRLD_EXIT=0
run_case dev-env-false

assert_eq "$exit_code" "0" "dev-env-false: exit code"
assert_not_contains "$output" "WARNING: UseDevEnvironment" "dev-env-false: a boolean false is a recognized value"
assert_not_contains "$calls_out" "--dev" "dev-env-false: false never turns on --dev"

# --- Case: success --------------------------------------------------------

reset_fakes
export FAKE_TOKEN_PRESENT=1 FAKE_TOKEN_VALUE="$GOOD_TOKEN"
export FAKE_CTRLD_EXIT=0
export FAKE_DIAG_WORKS=1
run_case success

assert_eq "$exit_code" "0" "success: exit code"
assert_contains "$output" "provisioning complete, service installed" "success: reports success"
assert_not_contains "$output" "diag:" "success: no diag block on the success path"
assert_not_contains "$output" "$GOOD_TOKEN" "success: token value must not leak"

leftover=$(find "$fixture/success/tmp" -type f 2>/dev/null)
assert_eq "$leftover" "" "success: capture temp file removed"

# --- Case: diag present on failure ----------------------------------------

reset_fakes
export FAKE_TOKEN_PRESENT=1 FAKE_TOKEN_VALUE="$GOOD_TOKEN"
export FAKE_CTRLD_EXIT=22
export FAKE_CTRLD_IDENTIFIER="provisioning failed: stage=input code=PROVISION_TOKEN_MALFORMED (exit 22)"
export FAKE_DIAG_WORKS=1
run_case diag-present

assert_eq "$exit_code" "1" "diag-present: exit code"
assert_contains "$output" "ctrld postinstall: diag: resolver: healthy" "diag-present: diag output appended"
assert_contains "$output" "ctrld postinstall: diag: listener: 127.0.0.1:53 bound" "diag-present: every diag line prefixed"
assert_not_contains "$output" "$GOOD_TOKEN" "diag-present: token value must not leak"

leftover=$(find "$fixture/diag-present/tmp" -type f 2>/dev/null)
assert_eq "$leftover" "" "diag-present: capture and diag temp files removed"

# --- Case: diag output redacts the token, fresh install ------------------
# diag leaks both the real (managed-prefs) token and an unrelated org-v1-
# shaped string; the first is caught by the exact-match swap, the second
# only by the pattern-based one. The rest of the leaked line must survive.

reset_fakes
export FAKE_TOKEN_PRESENT=1 FAKE_TOKEN_VALUE="$GOOD_TOKEN"
export FAKE_CTRLD_EXIT=22
export FAKE_CTRLD_IDENTIFIER="provisioning failed: stage=input code=PROVISION_TOKEN_MALFORMED (exit 22)"
export FAKE_DIAG_WORKS=1
export FAKE_DIAG_LEAK_LINE="leaked: $GOOD_TOKEN and $OTHER_ORG_TOKEN"
run_case diag-redacts-token

assert_eq "$exit_code" "1" "diag-redacts-token: exit code"
assert_not_contains "$output" "$GOOD_TOKEN" "diag-redacts-token: real token value must not leak"
assert_not_contains "$output" "$OTHER_ORG_TOKEN" "diag-redacts-token: unrelated org-v1- string must not leak"
assert_contains "$output" "leaked: [redacted-token] and org-v1-[redacted]" "diag-redacts-token: both redacted, rest of the line intact"
assert_contains "$output" "ctrld postinstall: diag: resolver: healthy" "diag-redacts-token: unrelated diag lines untouched"

# --- Case: diag output redacts the token, upgrade path --------------------
# Same redaction, but on the upgrade branch that applies a managed
# InterceptMode: it never reads ProvisionToken for its own purposes, so
# this proves redact_token is still populated there.

reset_fakes
export FAKE_MODE_PRESENT=1 FAKE_MODE="standard"
export FAKE_TOKEN_PRESENT=1 FAKE_TOKEN_VALUE="$GOOD_TOKEN"
export FAKE_CTRLD_EXIT=22
export FAKE_CTRLD_IDENTIFIER="provisioning failed: stage=input code=PROVISION_TOKEN_MALFORMED (exit 22)"
export FAKE_DIAG_WORKS=1
export FAKE_DIAG_LEAK_LINE="leaked: $GOOD_TOKEN and $OTHER_ORG_TOKEN"
run_case diag-redacts-token-upgrade 1

assert_eq "$exit_code" "1" "diag-redacts-token-upgrade: exit code"
assert_contains "$calls_out" "ctrld-client start --intercept-mode off" "diag-redacts-token-upgrade: applied managed InterceptMode"
assert_not_contains "$output" "$GOOD_TOKEN" "diag-redacts-token-upgrade: real token value must not leak"
assert_not_contains "$output" "$OTHER_ORG_TOKEN" "diag-redacts-token-upgrade: unrelated org-v1- string must not leak"
assert_contains "$output" "leaked: [redacted-token] and org-v1-[redacted]" "diag-redacts-token-upgrade: both redacted, rest of the line intact"

# --- Case: diag absent/failing -> identifier still logged (fallback) -----

reset_fakes
export FAKE_TOKEN_PRESENT=1 FAKE_TOKEN_VALUE="$GOOD_TOKEN"
export FAKE_CTRLD_EXIT=1
run_case diag-absent

assert_eq "$exit_code" "1" "diag-absent: exit code"
assert_contains "$output" "provisioning failed with no identifier; see /var/log/install.log and run ctrld-client diag" "diag-absent: falls back when ctrld reports no identifier"
assert_not_contains "$output" "invalid/expired token, or no network" "diag-absent: old speculative wording is gone"
assert_not_contains "$output" "ctrld postinstall: diag:" "diag-absent: no diag block when diag fails"
assert_not_contains "$output" "$GOOD_TOKEN" "diag-absent: token value must not leak"

leftover=$(find "$fixture/diag-absent/tmp" -type f 2>/dev/null)
assert_eq "$leftover" "" "diag-absent: capture temp file removed"

# --- Case: diag ignores SIGTERM -> SIGKILL escalation bounds the wait ----
# Without the escalation this would hang for the diag stub's full 30s
# sleep (or longer, on a real ignore-forever daemon); the grace loop above
# already spends up to 10s, so 20s is a generous bound that still catches
# a regression back to a plain SIGTERM-and-wait.

reset_fakes
export FAKE_TOKEN_PRESENT=1 FAKE_TOKEN_VALUE="$GOOD_TOKEN"
export FAKE_CTRLD_EXIT=22
export FAKE_CTRLD_IDENTIFIER="provisioning failed: stage=input code=PROVISION_TOKEN_MALFORMED (exit 22)"
export FAKE_DIAG_TRAPS_TERM=1
start_ts=$(date +%s)
run_case diag-ignores-term
end_ts=$(date +%s)
elapsed=$((end_ts - start_ts))

assert_eq "$exit_code" "1" "diag-ignores-term: exit code"
if [ "$elapsed" -gt 20 ]; then
    fail "diag-ignores-term: took ${elapsed}s, expected the SIGKILL escalation to keep this well under 30s"
fi
assert_not_contains "$output" "$GOOD_TOKEN" "diag-ignores-term: token value must not leak"

# --- Case: mktemp failure -> TEMP_FILE_UNAVAILABLE, no diag attempted ----

reset_fakes
export FAKE_TOKEN_PRESENT=1 FAKE_TOKEN_VALUE="$GOOD_TOKEN"
export FAKE_MKTEMP_FAIL=1
run_case tempfile-unavailable

assert_eq "$exit_code" "1" "tempfile-unavailable: exit code"
assert_contains "$output" "stage=package code=TEMP_FILE_UNAVAILABLE (exit 1)" "tempfile-unavailable: identifier line"
assert_contains "$output" "free space in /tmp or TMPDIR" "tempfile-unavailable: remediation hint"
assert_not_contains "$calls_out" "ctrld-client " "tempfile-unavailable: ctrld never invoked"
assert_not_contains "$output" "ctrld postinstall: diag:" "tempfile-unavailable: no diag block without a capture file"
assert_not_contains "$output" "$GOOD_TOKEN" "tempfile-unavailable: token value must not leak"

if [ "$FAILURES" -gt 0 ]; then
    echo "$FAILURES assertion(s) failed" >&2
    exit 1
fi

if [ "$real_defaults" = "1" ]; then
    echo "OK (real defaults): postinstall classifies failures, surfaces diagnostics, and never leaks the token"
else
    echo "OK (stubbed defaults): postinstall classifies failures, surfaces diagnostics, and never leaks the token"
fi
exit 0
