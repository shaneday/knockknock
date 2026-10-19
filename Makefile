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

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/knockknock" \
		"$(DESTDIR)$(SYSTEMD_UNIT_DIR)/knockknock.socket" \
		"$(DESTDIR)$(SYSTEMD_UNIT_DIR)/knockknock.service"

clean:
	rm -rf build

test:
	@echo "Running tests..."
	bash tests/install.sh
	bash tests/secret.sh
	bash tests/cleanup.sh
	bash tests/docker.sh

# Doesn't cache well so a bit slow to run regularly
testmore: test
	type orb && bash tests/orbstack.sh
