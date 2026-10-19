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

# Isolate collision files so the dry run cannot touch the working tree.
mkdir "$TEST_DIR/phony"
cp Makefile "$TEST_DIR/phony/Makefile"
touch "$TEST_DIR/phony/test" "$TEST_DIR/phony/testmore"
make -C "$TEST_DIR/phony" -f Makefile -n testmore > "$TEST_DIR/plan"
grep -Fq 'bash tests/docker.sh' "$TEST_DIR/plan" || fail 'test collision suppressed its recipe'
grep -Fq 'bash tests/orbstack.sh' "$TEST_DIR/plan" || fail 'testmore collision suppressed its recipe'
printf 'PASS: test/testmore remain phony with collision files\n'
