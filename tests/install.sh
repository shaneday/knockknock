#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TEST_DIR=$(mktemp -d)
trap 'rm -rf -- "$TEST_DIR"' EXIT
cd "$PROJECT_DIR"

fail()
{
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

run_case()
{
    local name=$1 bindir=$2 unitdir=$3
    shift 3
    local stage="$TEST_DIR/$name"
    local binary="$stage$bindir/knockknock"
    local service="$stage$unitdir/knockknock.service"
    local socket="$stage$unitdir/knockknock.socket"
    local path

    mkdir -p "$stage/etc/ufw"
    printf 'keep secret\n' > "$stage/etc/knockknock.secret"
    printf 'keep rules\n' > "$stage/etc/ufw/user.rules"
    make install "DESTDIR=$stage" "$@"

    [[ -x "$binary" ]] || fail "$name: executable missing at $binary"
    cmp build/knockknock "$binary" || fail "$name: wrong executable installed"
    for path in "$service" "$socket"; do
        [[ -r "$path" ]] || fail "$name: unreadable unit $path"
        [[ -n $(find "$path" -prune -perm 0644 -print) ]] || fail "$name: unit mode is not 0644"
    done
    [[ $(grep '^ExecStart=' "$service") == "ExecStart=\"$bindir/knockknock\"" ]] ||
        fail "$name: ExecStart must contain exactly the quoted, unstaged binary path"
    if grep -Fq -- "$stage" "$service"; then
        fail "$name: DESTDIR leaked into service"
    fi
    cmp systemd/knockknock.socket "$socket" || fail "$name: socket changed"

    printf 'keep neighbor\n' > "$stage$bindir/neighbor"
    printf 'keep neighbor\n' > "$stage$unitdir/neighbor"
    make uninstall "DESTDIR=$stage" "$@"
    for path in "$binary" "$service" "$socket"; do
        [[ ! -e "$path" && ! -L "$path" ]] || fail "$name: uninstall left $path"
    done
    [[ -d "$stage$bindir" && -d "$stage$unitdir" ]] || fail "$name: uninstall removed directories"
    for path in "$stage$bindir/neighbor" "$stage$unitdir/neighbor"; do
        [[ $(cat "$path") == 'keep neighbor' ]] || fail "$name: neighbor changed"
    done
    [[ $(cat "$stage/etc/knockknock.secret") == 'keep secret' ]] || fail "$name: secret changed"
    [[ $(cat "$stage/etc/ufw/user.rules") == 'keep rules' ]] || fail "$name: rules changed"
    printf 'PASS: %s install/uninstall\n' "$name"
}

run_case default /usr/local/bin /usr/local/lib/systemd/system
run_case usr /usr/bin /usr/lib/systemd/system PREFIX=/usr
run_case overrides /opt/knock/bin /opt/knock/units \
    PREFIX=/usr BINDIR=/opt/knock/bin SYSTEMD_UNIT_DIR=/opt/knock/units
run_case spaces '/opt/knock tools/bin' /opt/knock/units \
    'BINDIR=/opt/knock tools/bin' SYSTEMD_UNIT_DIR=/opt/knock/units

# Test live unit management with a mock; never call the host's systemctl.
cat > "$TEST_DIR/systemctl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$SYSTEMCTL_LOG"
EOF
chmod +x "$TEST_DIR/systemctl"
cp "$TEST_DIR/systemctl" "$TEST_DIR/ufw"
log="$TEST_DIR/systemctl.log"
live="$TEST_DIR/live"
secret="$TEST_DIR/live.secret"
PATH="$TEST_DIR:$PATH" SYSTEMCTL_LOG="$log" make install \
    "BINDIR=$live/bin" "SYSTEMD_UNIT_DIR=$live/units" "SECRET_FILE=$secret" > "$TEST_DIR/install.out"
[[ $(cat "$secret") =~ ^[0-9a-f]{64}$ ]] || fail 'generated secret is not 64 hex characters'
[[ -n $(find "$secret" -prune -perm 0600 -print) ]] || fail 'generated secret is not mode 0600'
grep -Fq "Created $secret" "$TEST_DIR/install.out" || fail 'missing secret reminder'
printf '%s\n' 'daemon-reload' 'allow from 0.0.0.0/0 to any port 9999 proto udp comment knockknock UDP listener' \
    'enable --now knockknock.socket' > "$TEST_DIR/expected"
cmp "$TEST_DIR/expected" "$log" || fail 'install did not reload and enable the socket'
cp "$secret" "$TEST_DIR/original-secret"
PATH="$TEST_DIR:$PATH" SYSTEMCTL_LOG="$log" make install \
    "BINDIR=$live/bin" "SYSTEMD_UNIT_DIR=$live/units" "SECRET_FILE=$secret" > "$TEST_DIR/install.out"
cmp "$secret" "$TEST_DIR/original-secret" || fail 'install replaced the existing secret'
! grep -Fq "Created $secret" "$TEST_DIR/install.out" || fail 'install reported replacing the secret'
printf '%s\n' 'daemon-reload' 'allow from 0.0.0.0/0 to any port 9999 proto udp comment knockknock UDP listener' \
    'enable --now knockknock.socket' >> "$TEST_DIR/expected"
cmp "$TEST_DIR/expected" "$log" || fail 'reinstall did not reload and enable the socket'
PATH="$TEST_DIR:$PATH" SYSTEMCTL_LOG="$log" make uninstall \
    "BINDIR=$live/bin" "SYSTEMD_UNIT_DIR=$live/units" "SECRET_FILE=$secret"
printf '%s\n' 'disable --now knockknock.socket' 'stop knockknock.service' \
    'daemon-reload' >> "$TEST_DIR/expected"
cmp "$TEST_DIR/expected" "$log" || fail 'uninstall did not stop units and reload'
[[ ! -e "$live/bin/knockknock" && ! -e "$live/units/knockknock.socket" &&
   ! -e "$live/units/knockknock.service" ]] || fail 'live uninstall left files'
cmp "$secret" "$TEST_DIR/original-secret" || fail 'uninstall removed or changed the secret'
printf 'PASS: live install/uninstall manages systemd units and secret\n'

# Isolate collision files so the dry run cannot touch the working tree.
mkdir "$TEST_DIR/phony"
cp Makefile "$TEST_DIR/phony/Makefile"
touch "$TEST_DIR/phony/test" "$TEST_DIR/phony/testmore"
make -C "$TEST_DIR/phony" -f Makefile -n testmore > "$TEST_DIR/plan"
grep -Fq 'bash tests/docker.sh' "$TEST_DIR/plan" || fail 'test collision suppressed its recipe'
grep -Fq 'bash tests/orbstack.sh' "$TEST_DIR/plan" || fail 'testmore collision suppressed its recipe'
printf 'PASS: test/testmore remain phony with collision files\n'
