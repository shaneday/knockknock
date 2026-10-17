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
    systemctl enable --now knockknock.socket
    printf '%s' '$TOKEN' > /dev/udp/127.0.0.1/9999

    until journalctl -u knockknock.service --no-pager -o cat | grep -qF '$TOKEN'; do
        sleep 0.1
    done

    journalctl -u knockknock.service --no-pager -o cat

    echo "Checking ufw rule..."
    ufw show added | grep -F 'from 127.0.0.1' | grep -F 'port 22' | grep -F 'knockknock'
    echo "ufw rule check passed"
EOF

echo "OrbStack systemd socket-activation test passed"
