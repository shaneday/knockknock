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
    systemctl enable --now knockknock.socket
    printf "%s" '"$TOKEN"' > /dev/udp/127.0.0.1/9999

    until journalctl -u knockknock.service --no-pager -o cat | grep -F '"$TOKEN"'; do
        sleep 0.1
    done

    journalctl -u knockknock.service --no-pager -o cat

    echo "Checking ufw rule..."
    ufw show added | grep -F "from 127.0.0.1" | grep -F "port 22" | grep -F "knockknock"
    echo "ufw rule check passed"
'

echo "Docker systemd socket-activation test passed"
