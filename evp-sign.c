#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "crypto-sign.h"

int main(int argc, char *argv[])
{
	FILE *f;
	struct sign_ctx c;
	unsigned char buf[BUFSIZ];
	size_t count;
	struct pkey *key;
	unsigned char *sign;

	if (argc != 3 || isatty(1))
		errx(1, "usage:\n\t%s <private-key.pem> <filename> > <signature>", argv[0]);

	if (!sign_init(&c, "md5"))
		errx(1, "cannot initialize digest context");

	if ((f = fopen(argv[2], "rb")) == NULL)
		err(1, "%s", argv[2]);

	/* TODO: check read errors */
	while ((count = fread(buf, 1, sizeof(buf), f)) > 0)
		sign_update(&c, buf, count);

	fclose(f);

	if ((key = pkey_read_private(argv[1], "")) == NULL)
		errx(1, "cannot open private key", argv[1]);

	if ((sign = sign_final(&c, &count, key)) == NULL)
		errx(1, "cannot finalize signing");

	pkey_free(key);

	fwrite(sign, count, 1, stdout);
	free(sign);

	return 0;
}
