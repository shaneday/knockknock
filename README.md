# knockknock

`knockknock` is a small UDP packet handler designed for systemd socket
activation. systemd owns the listening socket and starts one short-lived
handler when data arrives. The handler drains queued datagrams, logs each one's
source, size, and authentication outcome, and adds a TCP-only UFW allow rule for
SSH from the sender when the secret matches. Payload contents are never logged.

## Build

Requirements are a C11 compiler, GNU Make, and Linux headers.

```sh
make
make test
```

SSH rules default to TCP port 22. For another SSH port, rebuild with:

```sh
make clean
make CPPFLAGS=-DSSH_PORT=2222
```

This changes the firewall destination port, not the UDP knock listener or sshd's
configuration.

## Install

Create the secret file that every incoming knock must match exactly before
installing and starting the socket:

```sh
echo 'my-secret-passphrase' | sudo tee /etc/knockknock.secret
sudo chmod 600 /etc/knockknock.secret
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now knockknock.socket
```

The file must be readable only by root.

The secret is the first line: 1–512 bytes, excluding its LF or CRLF line ending.
A final newline is optional; later lines are ignored. An empty or oversized
first line is rejected, not truncated. Packets must match the secret byte-for-byte.

If the secret is missing, unreadable, empty, or too long, the handler logs the
error and drains queued packets without running UFW. After fixing the file, send
a fresh knock; no socket reset or restart is needed since the daemon reads the
file on each invocation.

The socket listens on UDP port 9999 by default. Test it with:

```sh
printf '%s' 'my-secret-passphrase' | nc -u -w1 127.0.0.1 9999
journalctl -u knockknock.service
```

Send the secret without a trailing newline; use `printf '%s'` or `echo -n`.

To use another port, copy `systemd/knockknock.socket` into
`/etc/systemd/system/`, change `ListenDatagram`, and reload systemd.

## Removing old SSH rules

Knocks date their UFW rules with `knockknock YYYYMMDD` (UTC), refreshing the date
on each valid knock. Remove rules older than 30 days, keeping IPs with a
successful SSH login in the last 30 days:

```sh
sudo bash knockknock-prune-ufw.sh
```

This uses SSH login events in the systemd journal, not open sessions; keep
30 days of journal history. Cleanup handles custom TCP ports and older dated
rules without a protocol; undated rules are left alone. If logs are unavailable
or contain no successful logins, cleanup simply skips deletion.

Copy the script to `/usr/local/sbin/`, then add to root's crontab
(`sudo crontab -e`) to run monthly:

```cron
0 3 1 * * PATH=/usr/sbin:/usr/bin /bin/bash /usr/local/sbin/knockknock-prune-ufw.sh
```

## End-to-end tests

With Docker installed and running, use this while working:

```sh
make test
```

On macOS with [OrbStack](https://orbstack.dev/) installed and running, run both
Docker and OrbStack VM tests before committing (requires Docker too):

```sh
make testmore
```

The tests build and install the project in disposable Ubuntu environments,
send invalid bursts (including oversized packets) and repeated separate knocks,
then verify a valid knock still creates the UFW rule without resetting or
restarting either unit. They also check journal metadata without exposing
payloads, plus missing/empty-secret recovery without repeated activation.
Test environments are deleted on exit.

For debugging failures, set `KEEP_CONTAINER=1` or `KEEP_VM=1` to retain the
Docker container or OrbStack VM. Use `CONTAINER_NAME=name` or `VM_NAME=name`
to choose its name.

## Design

There is deliberately no dependency on `libsystemd`. The socket activation
contract is small: systemd supplies file descriptors starting at 3 and sets
`LISTEN_PID` and `LISTEN_FDS`. The program validates that contract and each
datagram socket before receiving packets.

Each invocation drains the socket with nonblocking receives until the queue is
empty. Invalid and oversized packets are rejected without running UFW. The
service's `StartLimitIntervalSec=0` and socket's `TriggerLimitIntervalSec=0`
disable activation limits so unauthenticated traffic cannot leave knocking
permanently disabled. This should not be a problem, as the service is
undetectable, so unlikely to be a target for DDoS attack.
