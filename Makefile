CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wformat=2
LDFLAGS ?=
LDLIBS ?=

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SYSTEMD_UNIT_DIR ?= $(PREFIX)/lib/systemd/system
DESTDIR ?=
# Test override only; the handler still reads /etc/knockknock.secret.
SECRET_FILE ?= /etc/knockknock.secret

TARGET := build/knockknock
OBJECTS := build/main.o

.PHONY: all clean install uninstall test testmore

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS) $(LDLIBS)

build/main.o: src/main.c | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

build:
	mkdir -p $@

install: $(TARGET)
	install -d "$(DESTDIR)$(BINDIR)" "$(DESTDIR)$(SYSTEMD_UNIT_DIR)"
	install -m 0755 $(TARGET) "$(DESTDIR)$(BINDIR)/knockknock"
	install -m 0644 systemd/knockknock.socket "$(DESTDIR)$(SYSTEMD_UNIT_DIR)/"
	sed 's|^ExecStart=.*|ExecStart="$(BINDIR)/knockknock"|' systemd/knockknock.service > build/knockknock.service
	install -m 0644 build/knockknock.service "$(DESTDIR)$(SYSTEMD_UNIT_DIR)/"
	@[ -n "$(DESTDIR)" ] || [ -e "$(SECRET_FILE)" ] || \
		{ bash -o pipefail -c 'umask 077; set -C; od -An -N32 -tx1 /dev/urandom | tr -d " \n" > "$(SECRET_FILE)"' && \
		  echo "Created $(SECRET_FILE); keep the random secret or edit it before knocking."; }
	@[ -n "$(DESTDIR)" ] || systemctl daemon-reload
	@[ -n "$(DESTDIR)" ] || ufw allow from 0.0.0.0/0 to any port 9999 proto udp comment 'knockknock UDP listener'
	@[ -n "$(DESTDIR)" ] || systemctl enable --now knockknock.socket

uninstall:
	@[ -n "$(DESTDIR)" ] || systemctl disable --now knockknock.socket
	@[ -n "$(DESTDIR)" ] || systemctl stop knockknock.service
	rm -f "$(DESTDIR)$(BINDIR)/knockknock" \
		"$(DESTDIR)$(SYSTEMD_UNIT_DIR)/knockknock.socket" \
		"$(DESTDIR)$(SYSTEMD_UNIT_DIR)/knockknock.service"
	@[ -n "$(DESTDIR)" ] || systemctl daemon-reload

clean:
	rm -rf build

test:
	@echo "Running tests..."
	bash tests/install.sh
	bash tests/secret.sh
	bash tests/cleanup.sh
	bash tests/list.sh
	bash tests/docker.sh

# Doesn't cache well so a bit slow to run regularly
testmore: test
	type orb && bash tests/orbstack.sh
