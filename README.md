# knockknock

`knockknock` is a small UDP packet handler designed for systemd socket
activation. systemd owns the listening socket and starts one short-lived
handler when data arrives. The handler drains queued datagrams, logs accepted
knocks with source and size, summarizes rejected knocks, and adds a TCP-only UFW
allow rule for SSH from the sender when the secret matches. Payload contents are
never logged.

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

UFW must already be installed, configured, and enabled. Installation adds an
IPv4 allow rule for UDP port 9999 with the comment `knockknock UDP listener`
before starting the socket. Knockknock does not set up or enable the firewall.

Knocking and the resulting SSH access use IPv4; clients need IPv4 connectivity
to the server. If the server also has IPv6, configure UFW to protect SSH there
separately.

Install and start the socket:

```sh
sudo make install
```

If `/etc/knockknock.secret` is absent, installation creates a root-owned, mode
`600` file containing a random 64-character hex secret and reminds you to edit
it if desired. Keep the random value or replace it with another strong secret;
securely transfer the secret to your client. An existing secret is never
overwritten, even if it is empty or invalid.

Installation defaults to `/usr/local`. Use `sudo make install PREFIX=/usr` for
`/usr/bin` and `/usr/lib/systemd/system`; `BINDIR` and `SYSTEMD_UNIT_DIR` can also
be overridden. The installed service uses the selected binary path. `DESTDIR`
stages files for packaging without changing that path or managing the host's
systemd units. Without `DESTDIR`, `make install` reloads systemd and enables and
starts `knockknock.socket`; configure and enable UFW first. To supply your own
secret, create `/etc/knockknock.secret` as root with mode `600` before installing.

The daemon requires a root-owned file with no group/other permissions (`600` or `400`).

The secret is the first line: 1–512 bytes, excluding its LF or CRLF line ending.
A final newline is optional; later lines are ignored. An empty or oversized
first line is rejected, not truncated. Packets must match the secret byte-for-byte.

If the secret file has the wrong owner or permissions, or the secret is missing,
unreadable, empty, or too long, the handler logs the error and drains queued
packets without running UFW. Fix it and send a fresh knock; no socket reset or
restart is needed since the daemon reads the file on each invocation.

The socket listens on UDP port 9999 by default. Test it with:

```sh
printf '%s' '<your-secret>' | nc -u -w1 127.0.0.1 9999
journalctl -u knockknock.service
```

Replace `<your-secret>` with the actual secret, without a trailing newline; use
`printf '%s'` or `echo -n`.

To use another port, copy `systemd/knockknock.socket` into
`/etc/systemd/system/`, change `ListenDatagram`, and reload systemd. Update the
UFW listener rule separately: installation only adds the default UDP/9999 rule.

## Uninstall

Use the same path overrides you used for installation:

```sh
sudo make uninstall
```

`make uninstall` disables and stops the socket, stops the service, removes the
installed files, and reloads systemd. The secret and existing UFW rules are kept,
including the UDP/9999 listener rule; remove that rule manually if it is no
longer needed.

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

## Listing allowed IPs and recent SSH users seen on each IP

```sh
sudo bash knockknock-list.sh
```

This report prints one line per dated knock-created TCP allow rule: `YYYYMMDD IP
username1,username2` (or `-` when none). Usernames are distinct accounts
observed from that IP in the last 30 days of the `ssh.service`/`sshd.service`
journal.

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
restarting either unit. They check accepted-knock metadata and rejected-knock
summaries without exposing payloads, plus missing/empty-secret recovery without
repeated activation.
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
empty. Invalid and oversized packets are rejected without running UFW. Their
logs are summarized once per second during a busy invocation and again when it
becomes idle; accepted knocks and UFW outcomes remain individually logged. The
service's `StartLimitIntervalSec=0` and socket's `TriggerLimitIntervalSec=0`
disable activation limits so unauthenticated traffic cannot leave knocking
permanently disabled. Log aggregation reduces journal load, but does not bound
CPU use or repeated service starts under sustained or spaced-out traffic. If
UDP/9999 is publicly reachable, apply an ingress rate limit appropriate to
expected clients and test valid knocks under load; a strict limit can drop
legitimate knocks as well.

## Security

The secret is a plain text string, there is no attempt to provide cryptographic
security, and the secret is visible to intermediary routers on the client to
server network path.

The intension is only for knockknock to provide an *additional* layer of
security, in many cases allowing the firewall to make the machine completely
invisible to all IPs except those who have successfully knocked.

A future version may add symmetric encryption to the knock payload, but that
will require a substantial increase in code complexity, which is in direct
conflict with the preliminary goals.
