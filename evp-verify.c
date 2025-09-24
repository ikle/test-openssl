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

#include "crypto-verify.h"
#include "evp-verify-ng.h"

static int verify_file (const char *path, struct evp_pkey *key,
			const void *sign, size_t len)
{
	struct evp_verify *o;
	FILE *in;
	unsigned char buf[BUFSIZ];
	size_t count;
	int ok = 0;

	if ((o = evp_verify_open (NULL, key)) == NULL)
		return 0;

	if ((in = fopen (path, "rb")) == NULL)
		goto no_file;

	while ((count = fread (buf, 1, sizeof (buf), in)) > 0)
		if (!evp_verify_update (o, buf, count))
			goto no_update;

	ok = !ferror (in) && evp_verify_final (o, sign, len);
no_update:
	fclose (in);
no_file:
	evp_verify_close (o);
	return ok;
}

int main (int argc, char *argv[])
{
	FILE *f;
	struct verify_ctx c;
	unsigned char buf[BUFSIZ];
	size_t count;
	struct pkey *key;
	unsigned char *sign;
	int status;

	evp_init ();

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
	fprintf (stderr, "I: Verify %s\n", status ? "OK" : "Fail");

	status = verify_file (argv[3], (void *) key, sign, count);
	fprintf (stderr, "I: Verify NG %s\n", status ? "OK" : "Fail");

	pkey_free (key);
	free (sign);

	return status ? 0 : 1;
}
