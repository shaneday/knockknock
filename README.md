# knockknock

`knockknock` is a small UDP packet handler designed for systemd socket
activation. systemd owns the listening socket and starts one short-lived
handler when data arrives. The handler currently receives one datagram and
writes its source, size, and escaped payload to the journal; packet-driven
actions will be added later.

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

## End-to-end test

On macOS with [OrbStack](https://orbstack.dev/) installed and running:

```sh
./tests/orbstack.sh
```

The script creates a uniquely named Ubuntu machine, builds and installs the
project inside it, sends a UDP datagram, verifies the journal entry, and
deletes the machine on exit. Set `KEEP_VM=1` to retain a failed test machine
for debugging, or `VM_NAME=name` to choose its name.

## Design

There is deliberately no dependency on `libsystemd`. The socket activation
contract is small: systemd supplies file descriptors starting at 3 and sets
`LISTEN_PID` and `LISTEN_FDS`. The program validates that contract and each
datagram socket before receiving a packet.
