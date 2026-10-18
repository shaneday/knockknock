#!/bin/sh
set -eu

if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker is required" >&2
    exit 1
fi

CONTAINER_NAME=${CONTAINER_NAME:-knockknock-test-$$}
IMAGE_NAME=${IMAGE_NAME:-knockknock-test-image-$$}
KEEP_CONTAINER=${KEEP_CONTAINER:-0}
KEEP_IMAGE=${KEEP_IMAGE:-0}
PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TOKEN="knockknock-e2e-$$"
created=0
built=0

cleanup()
{
    status=$?
    if [ "$created" -eq 1 ] && { [ "$status" -eq 0 ] || [ "$KEEP_CONTAINER" != 1 ]; }; then
        echo "Deleting Docker container $CONTAINER_NAME"
        docker rm -f "$CONTAINER_NAME" >/dev/null
    elif [ "$created" -eq 1 ]; then
        echo "Keeping failed test container: $CONTAINER_NAME" >&2
    fi

    if [ "$built" -eq 1 ] && { [ "$status" -eq 0 ] || [ "$KEEP_IMAGE" != 1 ]; }; then
        echo "Deleting Docker image $IMAGE_NAME"
        docker rmi -f "$IMAGE_NAME" >/dev/null
    elif [ "$built" -eq 1 ]; then
        echo "Keeping test image: $IMAGE_NAME" >&2
    fi

    exit "$status"
}
trap cleanup EXIT HUP INT TERM

echo "Building Ubuntu systemd test image $IMAGE_NAME"
cat <<'EOF' | docker build -t "$IMAGE_NAME" - >/dev/null
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && \
    apt-get install -qq build-essential systemd systemd-sysv bash ufw iptables && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    update-alternatives --set iptables /usr/sbin/iptables-legacy && \
    update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy

CMD ["/lib/systemd/systemd"]
EOF
built=1

echo "Starting systemd container $CONTAINER_NAME"
docker run -d \
    --name "$CONTAINER_NAME" \
    --privileged \
    --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    "$IMAGE_NAME" >/dev/null
created=1

echo "Waiting for systemd to finish booting in $CONTAINER_NAME"
# systemd overlays /tmp with a fresh tmpfs while booting, so wait for it to
# settle before copying files in or issuing systemctl commands.
for _ in $(seq 1 100); do
    if docker exec "$CONTAINER_NAME" systemctl is-system-running --wait >/dev/null 2>&1; then
        break
    fi
    state=$(docker exec "$CONTAINER_NAME" systemctl is-system-running 2>/dev/null || true)
    case "$state" in
        running|degraded) break ;;
    esac
    sleep 0.5
done

echo "Copying project into $CONTAINER_NAME"
docker exec "$CONTAINER_NAME" rm -rf /opt/knockknock
PARENT_DIR=$(dirname -- "$PROJECT_DIR")
PROJECT_NAME=$(basename -- "$PROJECT_DIR")
COPYFILE_DISABLE=1 tar --exclude="$PROJECT_NAME/.git" --exclude="$PROJECT_NAME/build" -C "$PARENT_DIR" -cf - "$PROJECT_NAME" |
    docker exec -i "$CONTAINER_NAME" tar --warning=no-unknown-keyword --no-same-owner --no-same-permissions -C /opt -xf -
docker exec "$CONTAINER_NAME" test -d /opt/knockknock

echo "Building and testing inside $CONTAINER_NAME"
docker exec "$CONTAINER_NAME" bash -eu -c '
    cd /opt/knockknock
    make clean
    make all install
    ls -l build/knockknock
    ldd build/knockknock
    systemctl daemon-reload
    printf "%s" '"$TOKEN"' > /etc/knockknock.secret
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
            count=$(grep -cF "$1" /tmp/knockknock-journal || true)
            state=$(systemctl show knockknock.service -p ActiveState --value)
            if [ "$state" = failed ]; then
                break
            fi
            if [ "$count" -ge "$2" ] && [ "$state" = inactive ] &&
                systemctl is-active --quiet knockknock.socket; then
                return 0
            fi
            sleep 0.1
        done
        echo "Timed out waiting for inactive service and $2 occurrences of: $1" >&2
        return 1
    }

    systemctl enable --now knockknock.socket
    rejected="knockknock: rejected knock from 127.0.0.1:"
    allowed="knockknock: ufw allowed ssh from 127.0.0.1"
    discarded="knockknock: discarding queued datagrams: secret unavailable"

    for config in missing empty; do
        echo "Testing $config secret"
        if [ "$config" = missing ]; then
            rm /etc/knockknock.secret
        else
            : > /etc/knockknock.secret
        fi
        journalctl -u knockknock.service --no-pager -o cat > /tmp/knockknock-journal
        discards=$(grep -cF "$discarded" /tmp/knockknock-journal || true)
        discards=$((discards + 1))
        for knock in {1..8}; do
            printf "%s" '"$TOKEN"' > /dev/udp/127.0.0.1/9999
        done
        wait_for_idle "$discarded" "$discards"
        idle_discards=$(grep -cF "$discarded" /tmp/knockknock-journal)
        invocation=$(systemctl show knockknock.service -p InvocationID --value)
        sleep 0.3
        wait_for_idle "$discarded" "$discards"
        [ "$(grep -cF "$discarded" /tmp/knockknock-journal)" -eq "$idle_discards" ]
        [ "$(systemctl show knockknock.service -p InvocationID --value)" = "$invocation" ]
        ufw show added > /tmp/knockknock-ufw
        if grep -qF "knockknock" /tmp/knockknock-ufw ||
            grep -qF "knockknock: ufw " /tmp/knockknock-journal; then
            cat /tmp/knockknock-ufw
            echo "Unavailable secret changed the firewall" >&2
            false
        fi
    done

    echo "Testing secret repair without reset or restart"
    printf "%s" '"$TOKEN"' > /etc/knockknock.secret
    printf "%s" '"$TOKEN"' > /dev/udp/127.0.0.1/9999
    wait_for_idle "$allowed" 1
    ufw show added | grep -F "from 127.0.0.1" | grep -F "port 22" | grep -F "knockknock"
    ufw --force delete allow from 127.0.0.1 to any port 22
    allowed_baseline=$(grep -cF "$allowed" /tmp/knockknock-journal)
    ufw_baseline=$(grep -cF "knockknock: ufw " /tmp/knockknock-journal)

    for phase in 1 2; do
        if [ "$phase" -eq 1 ]; then
            echo "Testing invalid datagram burst, including oversized input"
            printf -v oversized "%2048s" ""
            printf "%s%s" '"$TOKEN"' "$oversized" > /dev/udp/127.0.0.1/9999
            for knock in {1..256}; do
                printf "%s-invalid" '"$TOKEN"' > /dev/udp/127.0.0.1/9999
            done
            # UDP may drop part of the burst; do not require every packet to arrive.
            wait_for_idle "$rejected" 1
            grep -F "knockknock: rejected oversized datagram" /tmp/knockknock-journal
        else
            echo "Testing 12 separate invalid-knock invocations"
            rejections=$(grep -cF "$rejected" /tmp/knockknock-journal)
            for knock in {1..12}; do
                printf "%s-invalid" '"$TOKEN"' > /dev/udp/127.0.0.1/9999
                rejections=$((rejections + 1))
                wait_for_idle "$rejected" "$rejections"
            done
        fi

        ufw show added > /tmp/knockknock-ufw
        if grep -qF "knockknock" /tmp/knockknock-ufw ||
            [ "$(grep -cF "knockknock: ufw " /tmp/knockknock-journal || true)" -ne "$((ufw_baseline + phase - 1))" ]; then
            cat /tmp/knockknock-ufw
            echo "Invalid knocks changed the firewall" >&2
            false
        fi
        printf "%s" '"$TOKEN"' > /dev/udp/127.0.0.1/9999
        wait_for_idle "$allowed" "$((allowed_baseline + phase))"

        cat /tmp/knockknock-journal
        grep -E "knockknock: rejected knock from 127[.]0[.]0[.]1:[0-9]+ [(][0-9]+ bytes[)]" /tmp/knockknock-journal
        grep -E "knockknock: accepted knock from 127[.]0[.]0[.]1:[0-9]+ [(][0-9]+ bytes[)]" /tmp/knockknock-journal
        if grep -qF '"$TOKEN"' /tmp/knockknock-journal; then
            echo "Knock payload leaked into journal" >&2
            false
        fi

        echo "Checking ufw rule..."
        ufw show added | grep -F "from 127.0.0.1" | grep -F "port 22" | grep -F "knockknock"
        echo "ufw rule check passed"
        if [ "$phase" -eq 1 ]; then
            ufw --force delete allow from 127.0.0.1 to any port 22
        fi
    done
'

echo "Docker systemd socket-activation test passed"
