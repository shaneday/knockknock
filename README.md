# knockknock

`knockknock` is a small UDP packet handler designed for systemd socket
activation. systemd owns the listening socket and starts one short-lived
handler when data arrives. The handler receives one datagram, logs its source,
size, and authentication outcome, and adds a UFW allow rule for SSH from the
sender when the secret matches. Payload contents are never logged.

## Build

Requirements are a C11 compiler, GNU Make, and Linux headers.

```sh
make
make test
```

## Install

```sh
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now knockknock.socket
```

Before starting the socket, create the secret file that every incoming knock
must match exactly:

```sh
echo 'my-secret-passphrase' | sudo tee /etc/knockknock.secret
sudo chmod 600 /etc/knockknock.secret
```

The file must be readable only by root.

The daemon reads this file on each invocation and rejects any packet that does
not match it byte-for-byte (trailing newline stripped). To rotate the secret,
replace the file — no service restart needed.

The socket listens on UDP port 9999 by default. Test it with:

```sh
printf 'hello\n' | nc -u -w1 127.0.0.1 9999
journalctl -u knockknock.service
```

To use another port, copy `systemd/knockknock.socket` into
`/etc/systemd/system/`, change `ListenDatagram`, and reload systemd.

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
send valid and invalid knocks, check journal metadata without exposing payloads,
and verify the UFW rule. Test environments are deleted on exit.

For debugging failures, set `KEEP_CONTAINER=1` or `KEEP_VM=1` to retain the
Docker container or OrbStack VM. Use `CONTAINER_NAME=name` or `VM_NAME=name`
to choose its name.

## Design

There is deliberately no dependency on `libsystemd`. The socket activation
contract is small: systemd supplies file descriptors starting at 3 and sets
`LISTEN_PID` and `LISTEN_FDS`. The program validates that contract and each
datagram socket before receiving a packet.
