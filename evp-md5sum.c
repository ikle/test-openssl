/*
 * OpenSSL EVP Digest Test
 *
 * Copyright (c) 2015-2025 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <openssl/evp.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define EVP_MD_CTX_new   EVP_MD_CTX_create
#define EVP_MD_CTX_free  EVP_MD_CTX_destroy
#endif

int main (int argc, char *argv[])
{
	FILE *f;
	const EVP_MD *md;
	EVP_MD_CTX *c;
	unsigned char buf[BUFSIZ];
	size_t count;
	unsigned len, i;
	unsigned char hash[EVP_MAX_MD_SIZE];

	if (argc < 2) {
		fprintf (stderr, "Usage:\n\t%s <filename> ...\n", argv[0]);
		return 1;
	}

	OpenSSL_add_all_digests ();
	md = EVP_get_digestbyname ("md5");

	for (; argc > 1; --argc, ++argv) {
		if ((f = fopen (argv[1], "rb")) == NULL) {
			perror (argv[1]);
			return 1;
		}

		if ((c = EVP_MD_CTX_new ()) == NULL) {
			fprintf (stderr, "E: Cannot allocate digest context\n");
			return 1;
		}

		EVP_DigestInit_ex (c, md, NULL);

		/* TODO: check read errors */
		while ((count = fread (buf, 1, sizeof (buf), f)) > 0)
			EVP_DigestUpdate (c, buf, count);

		fclose (f);

		EVP_DigestFinal_ex (c, hash, &len);
		EVP_MD_CTX_free (c);

		for (i = 0; i < len; ++i)
			printf ("%02x", hash[i]);

		printf ("  %s\n", argv[1]);
	}

	return 0;
}
