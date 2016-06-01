TARGETS = evp-md5sum evp-bio-md5sum evp-sign evp-verify bn

all: $(TARGETS)

clean:
	rm -f *.o $(TARGETS)

PREFIX ?= /usr/local

install: $(TARGETS)
	install -D -d $(DESTDIR)/$(PREFIX)/bin
	install -s -m 0755 $^ $(DESTDIR)/$(PREFIX)/bin

OPENSSL_CFLAGS = `pkg-config openssl --cflags --libs`

evp-md5sum evp-bio-md5sum: CFLAGS += $(OPENSSL_CFLAGS)
evp-sign evp-verify: CFLAGS += $(OPENSSL_CFLAGS)
evp-sign: crypto-sign.o
evp-verify: crypto-verify.o

bn: CFLAGS += $(OPENSSL_CFLAGS)
