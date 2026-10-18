#!/bin/sh
set -eu

if ! command -v orb >/dev/null 2>&1; then
    echo "error: OrbStack's 'orb' command is required" >&2
    exit 1
fi

VM_NAME=${VM_NAME:-knockknock-test-$$}
KEEP_VM=${KEEP_VM:-0}
PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TOKEN="knockknock-e2e-$$"
created=0

cleanup()
{
    status=$?
    if [ "$created" -eq 1 ] && { [ "$status" -eq 0 ] || [ "$KEEP_VM" != 1 ]; }; then
        echo "Deleting OrbStack machine $VM_NAME"
        orb delete -f "$VM_NAME" >/dev/null
    elif [ "$created" -eq 1 ]; then
        echo "Keeping failed test machine: $VM_NAME" >&2
    fi
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

echo "Creating OrbStack Ubuntu machine $VM_NAME"
orb create ubuntu "$VM_NAME" #>/dev/null
created=1

# OrbStack mounts the macOS filesystem in its Linux machines. Run the build as
# root so installation and systemd management need no interactive sudo prompt.
orb -m "$VM_NAME" -u root bash -eu << EOF
    mkdir /tmp/knockknock-source
    cp -R '$PROJECT_DIR'/.[!.]* '$PROJECT_DIR'/* /tmp/knockknock-source/
    cd /tmp/knockknock-source
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -qq build-essential ufw
    make all install
    ls -l build/knockknock
    ldd build/knockknock
    systemctl daemon-reload
    printf '%s' '$TOKEN' > /etc/knockknock.secret
    diagnostics()
    {
        systemctl status knockknock.socket knockknock.service --no-pager || true
        journalctl -u knockknock.socket -u knockknock.service --no-pager -o cat
    }
    set -E
    trap diagnostics ERR

    wait_for_idle()
    {
        for attempt in {1..100}; do
            journalctl -u knockknock.service --no-pager -o cat > /tmp/knockknock-journal
            count=\$(grep -cF "\$1" /tmp/knockknock-journal || true)
            state=\$(systemctl show knockknock.service -p ActiveState --value)
            if [ "\$state" = failed ]; then
                break
            fi
            if [ "\$count" -ge "\$2" ] && [ "\$state" = inactive ] &&
                systemctl is-active --quiet knockknock.socket; then
                return 0
            fi
            sleep 0.1
        done
        echo "Timed out waiting for inactive service and \$2 occurrences of: \$1" >&2
        return 1
    }

    assert_rules()
    {
        ufw show added > /tmp/knockknock-ufw
        grep -Fx "ufw allow from 127.0.0.1 to any port \$1 proto tcp comment 'knockknock \$(date -u +%Y%m%d)'" /tmp/knockknock-ufw
        [ "\$(grep -c '^ufw ' /tmp/knockknock-ufw)" -eq 1 ]
    }

    systemctl enable --now knockknock.socket
    rejected='knockknock: rejected knock from 127.0.0.1:'
    allowed='knockknock: ufw allowed ssh from 127.0.0.1'
    discarded='knockknock: discarding queued datagrams: secret unavailable'

    for config in missing empty; do
        echo "Testing \$config secret"
        if [ "\$config" = missing ]; then
            rm /etc/knockknock.secret
        else
            : > /etc/knockknock.secret
        fi
        journalctl -u knockknock.service --no-pager -o cat > /tmp/knockknock-journal
        discards=\$(grep -cF "\$discarded" /tmp/knockknock-journal || true)
        discards=\$((discards + 1))
        for knock in {1..8}; do
            printf '%s' '$TOKEN' > /dev/udp/127.0.0.1/9999
        done
        wait_for_idle "\$discarded" "\$discards"
        idle_discards=\$(grep -cF "\$discarded" /tmp/knockknock-journal)
        invocation=\$(systemctl show knockknock.service -p InvocationID --value)
        sleep 0.3
        wait_for_idle "\$discarded" "\$discards"
        [ "\$(grep -cF "\$discarded" /tmp/knockknock-journal)" -eq "\$idle_discards" ]
        [ "\$(systemctl show knockknock.service -p InvocationID --value)" = "\$invocation" ]
        ufw show added > /tmp/knockknock-ufw
        if grep -qF 'knockknock' /tmp/knockknock-ufw ||
            grep -qF 'knockknock: ufw ' /tmp/knockknock-journal; then
            cat /tmp/knockknock-ufw
            echo "Unavailable secret changed the firewall" >&2
            false
        fi
    done

    echo "Testing secret repair and dated comment refresh without reset or restart"
    ufw allow from 127.0.0.1 to any port 22 proto tcp comment 'knockknock 20000101'
    printf '%s' '$TOKEN' > /etc/knockknock.secret
    printf '%s' '$TOKEN' > /dev/udp/127.0.0.1/9999
    wait_for_idle "\$allowed" 1
    assert_rules 22
    ufw --force delete allow from 127.0.0.1 to any port 22 proto tcp
    allowed_baseline=\$(grep -cF "\$allowed" /tmp/knockknock-journal)
    ufw_baseline=\$(grep -cF 'knockknock: ufw ' /tmp/knockknock-journal)

    for phase in 1 2; do
        if [ "\$phase" -eq 1 ]; then
            echo "Testing invalid datagram burst, including oversized input"
            printf -v oversized '%2048s' ''
            printf '%s%s' '$TOKEN' "\$oversized" > /dev/udp/127.0.0.1/9999
            for knock in {1..256}; do
                printf '%s-invalid' '$TOKEN' > /dev/udp/127.0.0.1/9999
            done
            # UDP may drop part of the burst; do not require every packet to arrive.
            wait_for_idle "\$rejected" 1
            grep -F 'knockknock: rejected oversized datagram' /tmp/knockknock-journal
        else
            echo "Testing 12 separate invalid-knock invocations"
            rejections=\$(grep -cF "\$rejected" /tmp/knockknock-journal)
            for knock in {1..12}; do
                printf '%s-invalid' '$TOKEN' > /dev/udp/127.0.0.1/9999
                rejections=\$((rejections + 1))
                wait_for_idle "\$rejected" "\$rejections"
            done
        fi

        ufw show added > /tmp/knockknock-ufw
        if grep -qF 'knockknock' /tmp/knockknock-ufw ||
            [ "\$(grep -cF 'knockknock: ufw ' /tmp/knockknock-journal || true)" -ne "\$((ufw_baseline + phase - 1))" ]; then
            cat /tmp/knockknock-ufw
            echo "Invalid knocks changed the firewall" >&2
            false
        fi
        printf '%s' '$TOKEN' > /dev/udp/127.0.0.1/9999
        wait_for_idle "\$allowed" "\$((allowed_baseline + phase))"

        cat /tmp/knockknock-journal
        grep -E 'knockknock: rejected knock from 127[.]0[.]0[.]1:[0-9]+ [(][0-9]+ bytes[)]' /tmp/knockknock-journal
        grep -E 'knockknock: accepted knock from 127[.]0[.]0[.]1:[0-9]+ [(][0-9]+ bytes[)]' /tmp/knockknock-journal
        if grep -qF '$TOKEN' /tmp/knockknock-journal; then
            echo 'Knock payload leaked into journal' >&2
            false
        fi

        echo "Checking ufw rule..."
        assert_rules 22
        echo "ufw rule check passed"
        if [ "\$phase" -eq 1 ]; then
            ufw --force delete allow from 127.0.0.1 to any port 22 proto tcp
        fi
    done

    echo "Testing custom SSH port on next socket activation"
    ufw --force delete allow from 127.0.0.1 to any port 22 proto tcp
    make clean
    make all install CPPFLAGS=-DSSH_PORT=2222
    printf '%s' '$TOKEN' > /dev/udp/127.0.0.1/9999
    wait_for_idle "\$allowed" "\$((allowed_baseline + 3))"
    assert_rules 2222
EOF

echo "OrbStack systemd socket-activation test passed"
