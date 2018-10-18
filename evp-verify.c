#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/conf.h>

#include "crypto-verify.h"

int main(int argc, char *argv[])
{
	FILE *f;
	struct verify_ctx c;
	unsigned char buf[BUFSIZ];
	size_t count;
	struct pkey *key;
	unsigned char *sign;
	int status;

	OPENSSL_config(NULL);

	if (argc != 3 || isatty(0))
		errx(1, "usage:\n\t%s <public-key.pem> <filename> < <signature>", argv[0]);

	if (!verify_init(&c, "md5"))
		errx(1, "cannot initialize digest context");

	if ((f = fopen(argv[2], "rb")) == NULL)
		err(1, "%s", argv[2]);

	/* TODO: check read errors */
	while ((count = fread(buf, 1, sizeof(buf), f)) > 0)
		verify_update(&c, buf, count);

	fclose(f);

	if ((key = pkey_read_public(argv[1], "")) == NULL)
		errx(1, "cannot open public key %s", argv[1]);

	if ((sign = malloc(pkey_size(key))) == NULL)
		err(1, "cannot allocate key storage");

	count = fread(sign, 1, pkey_size(key), stdin);

	status = verify_final(&c, sign, count, key);

	pkey_free(key);
	free(sign);

	return status ? 0 : 1;
}
