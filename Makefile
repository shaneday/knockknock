CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wformat=2
LDFLAGS ?=
LDLIBS ?=

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SYSTEMD_UNIT_DIR ?= /usr/local/lib/systemd/system
DESTDIR ?=

TARGET := build/knockknock
OBJECTS := build/main.o

.PHONY: all clean install

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
	install -m 0644 systemd/knockknock.socket systemd/knockknock.service \
		"$(DESTDIR)$(SYSTEMD_UNIT_DIR)/"

clean:
	rm -rf build

test:
	@echo "Running tests..."
	bash tests/docker.sh
	type orb && bash tests/orbstack.sh
