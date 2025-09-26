/*
 * OpenSSL EVP Digest Test
 *
 * Copyright (c) 2015-2025 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>

#include <evp/digest.h>

int main (int argc, char *argv[])
{
	struct evp_digest *o;
	FILE *f;
	char buf[BUFSIZ];
	size_t count, i;

	if (argc < 3) {
		fprintf (stderr, "Usage:\n\t%s <digest> <filename> ...\n", argv[0]);
		return 1;
	}

	evp_init ();

	if ((o = evp_digest_open (argv[1])) == NULL) {
		fprintf (stderr, "E: Cannot open digest %s\n", argv[1]);
		return 1;
	}
start:
	if ((f = fopen (argv[2], "rb")) == NULL) {
		perror (argv[2]);
		goto error;
	}

	while ((count = fread (buf, 1, sizeof (buf), f)) > 0)
		evp_digest_update (o, buf, count);

	if (ferror (f)) {
		perror (argv[2]);
		goto error;
	}

	fclose (f);

	if ((count = evp_digest_final (o, buf, sizeof (buf))) == 0) {
		fprintf (stderr, "E: Cannot finalize digest\n");
		goto error;
	}

	for (i = 0; i < count; ++i)
		printf ("%02x", (unsigned char) buf[i]);

	printf ("  %s\n", argv[2]);

	if ((++argv)[2] != NULL) {
		evp_digest_reset (o);
		goto start;
	}

	evp_digest_close (o);
	return 0;
error:
	evp_digest_close (o);
	return 1;
}
