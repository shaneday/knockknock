#!/bin/sh
set -eu

if command -v orb >/dev/null 2>&1; then
    ORB=$(command -v orb)
elif [ -x /usr/local/bin/orb ]; then
    ORB=/usr/local/bin/orb
elif [ -x /opt/homebrew/bin/orb ]; then
    ORB=/opt/homebrew/bin/orb
elif [ -x /Applications/OrbStack.app/Contents/MacOS/bin/orb ]; then
    ORB=/Applications/OrbStack.app/Contents/MacOS/bin/orb
else
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
        "$ORB" delete "$VM_NAME" >/dev/null
    elif [ "$created" -eq 1 ]; then
        echo "Keeping failed test machine: $VM_NAME" >&2
    fi
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

echo "Creating OrbStack Ubuntu machine $VM_NAME"
"$ORB" create ubuntu "$VM_NAME" >/dev/null
created=1

# OrbStack mounts the macOS filesystem in its Linux machines. Run the build as
# root so installation and systemd management need no interactive sudo prompt.
"$ORB" -m "$VM_NAME" -u root bash -eu -c "
    rm -rf /tmp/knockknock-source
    mkdir /tmp/knockknock-source
    cp -R '$PROJECT_DIR'/.[!.]* '$PROJECT_DIR'/* /tmp/knockknock-source/
    cd /tmp/knockknock-source
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -qq build-essential
    make clean all check
    make install
    systemctl daemon-reload
    systemctl enable --now knockknock.socket
    printf '%s' '$TOKEN' > /dev/udp/127.0.0.1/9999

    attempts=0
    until journalctl -u knockknock.service --no-pager -o cat | grep -F '$TOKEN'; do
        attempts=\$((attempts + 1))
        if [ \"\$attempts\" -ge 20 ]; then
            systemctl status knockknock.socket knockknock.service --no-pager >&2 || true
            exit 1
        fi
        sleep 0.1
    done
"

echo "OrbStack systemd socket-activation test passed"
