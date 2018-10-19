#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/conf.h>

#include "crypto-sign.h"

int main(int argc, char *argv[])
{
	FILE *f;
	struct sign_ctx c;
	unsigned char buf[BUFSIZ];
	size_t count;
	struct pkey *key;

	OPENSSL_config(NULL);

	if (argc != 4 || isatty(1))
		errx(1, "usage:\n"
			"\t%s <digest> <private-key.pem> <filename> > <signature>",
			argv[0]);

	if (!sign_init(&c, argv[1]))
		errx(1, "cannot initialize digest context");

	if ((f = fopen(argv[3], "rb")) == NULL)
		err(1, "%s", argv[3]);

	/* TODO: check read errors */
	while ((count = fread(buf, 1, sizeof(buf), f)) > 0)
		sign_update(&c, buf, count);

	fclose(f);

	if ((key = pkey_read_private(argv[2], "")) == NULL)
		errx(1, "cannot open private key %s", argv[2]);

	if ((count = sign_final(&c, buf, sizeof (buf), key)) == 0)
		errx(1, "cannot finalize signing");

	pkey_free(key);

	fwrite(buf, count, 1, stdout);
	return 0;
}
