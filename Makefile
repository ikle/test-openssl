TARGETS = evp-md5sum evp-bio-md5sum evp-sign evp-verify bn chain-hash

all: $(TARGETS)

clean:
	rm -f *.o $(TARGETS)

PREFIX ?= /usr/local

install: $(TARGETS)
	install -D -d $(DESTDIR)/$(PREFIX)/bin
	install -s -m 0755 $^ $(DESTDIR)/$(PREFIX)/bin

CFLAGS += -I$(CURDIR)/include
CFLAGS += `pkg-config openssl --cflags`
LDLIBS += `pkg-config openssl --libs`

evp-sign: crypto-sign.o
evp-verify: crypto-verify.o
