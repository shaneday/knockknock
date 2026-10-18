#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [[ ! -f "$PROJECT_DIR/knockknock-prune-ufw.sh" ]]; then
    echo 'error: knockknock-prune-ufw.sh not found' >&2
    exit 1
fi

TEST_DIR=$(mktemp -d)
trap 'rm -rf -- "$TEST_DIR"' EXIT
mkdir "$TEST_DIR/bin"
export TEST_DIR
export PATH="$TEST_DIR/bin:$PATH"
export UFW_STATUS=0 JOURNAL_STATUS=0

cat > "$TEST_DIR/bin/ufw" <<'EOF'
#!/usr/bin/env bash
set -eu
if [[ $# == 2 && "$*" == 'show added' ]]; then
    cat "$TEST_DIR/rules"
    exit "$UFW_STATUS"
fi
if [[ ( $# == 9 || ( $# == 11 && ${10} == proto && ${11} == tcp ) ) &&
      $1 == --force && $2 == delete && $3 == allow &&
      $4 == from && $6 == to && $7 == any && $8 == port && $9 =~ ^[0-9]+$ ]]; then
    printf '<%s>' "$@" >> "$TEST_DIR/deletions"
    printf '\n' >> "$TEST_DIR/deletions"
    exit 0
fi
printf 'Unexpected ufw arguments: %s\n' "$*" >> "$TEST_DIR/mock-errors"
exit 1
EOF

cat > "$TEST_DIR/bin/date" <<'EOF'
#!/usr/bin/env bash
set -eu
if [[ $# == 4 && "$*" == '-u -d 30 days ago +%Y%m%d' ]]; then
    printf '20260919\n'
    exit 0
fi
printf 'Unexpected date arguments: %s\n' "$*" >> "$TEST_DIR/mock-errors"
exit 1
EOF

cat > "$TEST_DIR/bin/journalctl" <<'EOF'
#!/usr/bin/env bash
set -eu
if [[ $# != 7 || "$*" != '--since 30 days ago --no-pager -o cat _COMM=sshd _COMM=sshd-session' ]]; then
    printf 'Unexpected journalctl arguments: %s\n' "$*" >> "$TEST_DIR/mock-errors"
    exit 1
fi
printf 'queried\n' >> "$TEST_DIR/journal-queries"
cat "$TEST_DIR/journal"
exit "$JOURNAL_STATUS"
EOF
chmod +x "$TEST_DIR/bin/ufw" "$TEST_DIR/bin/date" "$TEST_DIR/bin/journalctl"

cat > "$TEST_DIR/rules" <<'EOF'
Added user rules (see 'ufw status' for running firewall):
ufw allow from 192.0.2.1 to any port 22 comment 'knockknock 20260918'
ufw allow from 2001:db8::1 to any port 22 comment 'knockknock 20250101'
ufw allow from 192.0.2.2 to any port 22 comment 'knockknock 20260901'
ufw allow from 2001:db8::2 to any port 22 comment 'knockknock 20260901'
ufw allow from 192.0.2.3 to any port 22 comment 'knockknock 20260901'
ufw allow from 192.0.2.4 to any port 22 comment 'knockknock 20260919'
ufw allow from 192.0.2.17 to any port 22 comment 'knockknock 20260920'
ufw allow from 192.0.2.5 to any port 22 comment 'knockknock 20261101'
ufw allow from 192.0.2.6 to any port 22 comment 'knockknock'
ufw allow from 192.0.2.7 to any port 22
ufw allow from 192.0.2.8 to any port 22 comment 'manual 20250101'
ufw allow from 192.0.2.9 to any port 80 proto udp comment 'knockknock 20250101'
ufw deny from 192.0.2.10 to any port 22 comment 'knockknock 20250101'
prefix ufw allow from 192.0.2.11 to any port 22 comment 'knockknock 20250101'
ufw allow from 192.0.2.12 to any port 22 comment 'knockknock 20250101' suffix
ufw allow from 192.0.2.13 to any port 22 comment 'knockknock 2025010'
ufw allow from 192.0.2.14 to any port 22 comment 'knockknock 202501010'
ufw allow from 192.0.2.15 to any port 22 comment 'knockknock 2025xx01'
ufw allow from example.com to any port 22 comment 'knockknock 20250101'
ufw allow from 192.0.2.0/24 to any port 22 comment 'knockknock 20250101'
ufw allow from 192.0.2.16;false to any port 22 comment 'knockknock 20250101'
ufw allow from 192.0.2.1 to any port 22 proto tcp comment 'knockknock 20260918'
ufw allow from 192.0.2.1 to any port 2222 proto tcp comment 'knockknock 20260918'
ufw allow from 2001:db8::1 to any port 2222 proto tcp comment 'knockknock 20250101'
ufw allow from 192.0.2.18 to any port 2222 comment 'knockknock 20250101'
ufw allow from 192.0.2.2 to any port 22 proto tcp comment 'knockknock 20260901'
ufw allow from 2001:db8::2 to any port 2222 proto tcp comment 'knockknock 20260901'
ufw allow from 192.0.2.4 to any port 2222 proto tcp comment 'knockknock 20260919'
ufw allow from 192.0.2.19 to any port 22 proto udp comment 'knockknock 20250101'
ufw allow from 192.0.2.20 to any port ssh proto tcp comment 'knockknock 20250101'
ufw allow from 192.0.2.21 to any port 22:2222 proto tcp comment 'knockknock 20250101'
ufw allow from 192.0.2.22 to any port 2222;false proto tcp comment 'knockknock 20250101'
ufw allow from 192.0.2.23 to any port 2222 proto tcp comment 'knockknock 20250101' suffix
EOF

cat > "$TEST_DIR/journal" <<'EOF'
Accepted publickey for alice from 192.0.2.2 port 50100 ssh2: ED25519 SHA256:example
Accepted password for bob from 2001:db8::2 port 50101 ssh2
Failed password for invalid user mallory from 192.0.2.3 port 50102 ssh2
Connection closed by authenticating user root 192.0.2.1 port 50103 [preauth]
EOF

run_case()
{
    local name=$1 expected_status=$2 status=0
    : > "$TEST_DIR/deletions"
    : > "$TEST_DIR/mock-errors"
    : > "$TEST_DIR/journal-queries"
    (cd "$PROJECT_DIR" && bash knockknock-prune-ufw.sh) > "$TEST_DIR/output" 2>&1 || status=$?
    if [[ -s "$TEST_DIR/mock-errors" ]] ||
       [[ $expected_status == success && $status != 0 ]] ||
       [[ $expected_status == failure && $status == 0 ]]; then
        printf 'FAIL: %s (exit %s)\n' "$name" "$status" >&2
        cat "$TEST_DIR/mock-errors" "$TEST_DIR/output" >&2
        exit 1
    fi
    if ! diff -u "$TEST_DIR/expected" <(LC_ALL=C sort "$TEST_DIR/deletions"); then
        printf 'FAIL: %s: unexpected deletions\n' "$name" >&2
        cat "$TEST_DIR/output" >&2
        exit 1
    fi
    printf 'PASS: %s\n' "$name"
}

cat > "$TEST_DIR/expected" <<'EOF'
<--force><delete><allow><from><192.0.2.18><to><any><port><2222>
<--force><delete><allow><from><192.0.2.1><to><any><port><2222><proto><tcp>
<--force><delete><allow><from><192.0.2.1><to><any><port><22>
<--force><delete><allow><from><192.0.2.1><to><any><port><22><proto><tcp>
<--force><delete><allow><from><192.0.2.3><to><any><port><22>
<--force><delete><allow><from><2001:db8::1><to><any><port><2222><proto><tcp>
<--force><delete><allow><from><2001:db8::1><to><any><port><22>
EOF
run_case 'only old, unused, exactly matching IPv4/IPv6 rules are deleted' success
if [[ ! -s "$TEST_DIR/journal-queries" ]]; then
    echo 'FAIL: successful cleanup did not query the SSH journal' >&2
    exit 1
fi

: > "$TEST_DIR/expected"
JOURNAL_STATUS=1
run_case 'journal failure with partial successful output aborts without deletion' failure
JOURNAL_STATUS=0

: > "$TEST_DIR/journal"
run_case 'empty journal aborts without deletion' failure
printf '%s\n' 'Failed password for root from 192.0.2.3 port 50102 ssh2' > "$TEST_DIR/journal"
run_case 'journal without successful authentication aborts without deletion' failure

printf '%s\n' 'Accepted publickey for alice from 192.0.2.2 port 50100 ssh2' > "$TEST_DIR/journal"
UFW_STATUS=1
run_case 'ufw read failure with partial rules aborts without deletion' failure

printf 'All cleanup mock tests passed\n'
