#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TEST_DIR=$(mktemp -d)
trap 'rm -rf -- "$TEST_DIR"' EXIT
mkdir "$TEST_DIR/bin"
export TEST_DIR PATH="$TEST_DIR/bin:$PATH" UFW_STATUS=0 JOURNAL_STATUS=0

cat > "$TEST_DIR/bin/ufw" <<'EOF'
#!/bin/bash
[[ "$*" == status ]] || exit 2
cat "$TEST_DIR/rules"
exit "$UFW_STATUS"
EOF
cat > "$TEST_DIR/bin/journalctl" <<'EOF'
#!/bin/bash
[[ "$*" == '-u ssh.service -u sshd.service --since 30 days ago --no-pager -o cat' ]] || exit 2
cat "$TEST_DIR/logins"
exit "$JOURNAL_STATUS"
EOF
chmod +x "$TEST_DIR/bin/ufw" "$TEST_DIR/bin/journalctl"

cat > "$TEST_DIR/rules" <<'EOF'
Status: active

To                         Action      From
--                         ------      ----
9999/udp                   ALLOW       Anywhere                   # knockknock UDP listener
22/tcp                     ALLOW       192.0.2.2                  # knockknock 20260101
2222/tcp                   ALLOW IN    192.0.2.2                  # knockknock 20261101
22/tcp                     ALLOW       192.0.2.1                  # knockknock 20261015
2222/tcp (v6)              ALLOW       2001:db8::2                # knockknock 20260102
22                         ALLOW       192.0.2.3                  # knockknock 20260103
22/tcp                     DENY IN     192.0.2.4                  # knockknock 20260104
22/tcp                     ALLOW OUT   192.0.2.4                  # knockknock 20260104
22/udp                     ALLOW IN    192.0.2.4                  # knockknock 20260104
22/tcp                     ALLOW IN    192.0.2.0/24               # knockknock 20260104
22/tcp                     ALLOW IN    192.0.2.4                  # other 20260104
EOF
cat > "$TEST_DIR/logins" <<'EOF'
Accepted publickey for alice from 192.0.2.2 port 50100 ssh2: ED25519 SHA256:example
Accepted password for bob from 192.0.2.2 port 50101 ssh2
Accepted publickey for alice from 192.0.2.2 port 50102 ssh2
Accepted password for carol from 2001:db8::2 port 50103 ssh2
Failed password for mallory from 192.0.2.1 port 50104 ssh2
Accepted password for root from 192.0.2.99 port 50105 ssh2
EOF
cat > "$TEST_DIR/expected" <<'EOF'
20261101 192.0.2.2 alice,bob
20261015 192.0.2.1 -
20260103 192.0.2.3 -
20260102 2001:db8::2 carol
20260101 192.0.2.2 alice,bob
EOF

run_case()
{
    local name=$1 expected_status=$2 status=0
    bash "$PROJECT_DIR/knockknock-list.sh" > "$TEST_DIR/output" 2> "$TEST_DIR/errors" || status=$?
    if [[ ( $expected_status == success && $status != 0 ) ||
          ( $expected_status == failure && $status == 0 ) ]] ||
       ! diff -u "$TEST_DIR/expected" "$TEST_DIR/output"; then
        printf 'FAIL: %s (exit %s)\n' "$name" "$status" >&2
        cat "$TEST_DIR/errors" >&2
        exit 1
    fi
    printf 'PASS: %s\n' "$name"
}

run_case 'dated TCP rules and distinct recent SSH usernames' success
: > "$TEST_DIR/logins"
cat > "$TEST_DIR/expected" <<'EOF'
20261101 192.0.2.2 -
20261015 192.0.2.1 -
20260103 192.0.2.3 -
20260102 2001:db8::2 -
20260101 192.0.2.2 -
EOF
run_case 'empty journal still lists rules without inventing users' success
: > "$TEST_DIR/expected"
JOURNAL_STATUS=1
run_case 'journal failure does not report incomplete data' failure
JOURNAL_STATUS=0
UFW_STATUS=1
run_case 'ufw failure does not report incomplete data' failure
UFW_STATUS=0
printf 'Status: inactive\n' > "$TEST_DIR/rules"
run_case 'inactive UFW is not reported as an empty ruleset' failure
