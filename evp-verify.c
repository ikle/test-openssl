/*
 * OpenSSL Crypto Verify Test
 *
 * Copyright (c) 2015-2025 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/conf.h>

#include "crypto-verify.h"

int main (int argc, char *argv[])
{
	FILE *f;
	struct verify_ctx c;
	unsigned char buf[BUFSIZ];
	size_t count;
	struct pkey *key;
	unsigned char *sign;
	int status;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	OPENSSL_config (NULL);
#else
	OPENSSL_init_crypto (OPENSSL_INIT_LOAD_CONFIG, NULL);
#endif

	if (argc != 4 || isatty (0))
		errx (1, "usage:\n"
			 "\t%s <digest> <public-key.pem> <filename> < <signature>",
			 argv[0]);

	if (!verify_init (&c, argv[1]))
		errx (1, "cannot initialize digest context");

	if ((f = fopen (argv[3], "rb")) == NULL)
		err (1, "%s", argv[3]);

	/* TODO: check read errors */
	while ((count = fread (buf, 1, sizeof(buf), f)) > 0)
		verify_update (&c, buf, count);

	fclose (f);

	if ((key = pkey_read_public (argv[2], "")) == NULL)
		errx (1, "cannot open public key %s", argv[2]);

	if ((sign = malloc (pkey_size (key))) == NULL)
		err (1, "cannot allocate key storage");

	count = fread (sign, 1, pkey_size (key), stdin);

	status = verify_final (&c, sign, count, key);

	pkey_free (key);
	free (sign);

	return status ? 0 : 1;
}
