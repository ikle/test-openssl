/*
 * Vyatta Chain Hash
 *
 * Copyright (c) 2018 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

static
int get_chain_sha1 (const char *scope, const char *name, const char *type,
		    void *md)
{
	SHA_CTX c;

	if (!SHA1_Init (&c))
		return 0;

	if (scope != NULL)
		SHA1_Update (&c, scope, strlen (scope));

	if (name != NULL) {
		SHA1_Update (&c, "-", 1);
		SHA1_Update (&c, name, strlen (name));
	}

	if (type != NULL) {
		SHA1_Update (&c, "-", 1);
		SHA1_Update (&c, type, strlen (type));
	}

	SHA1_Final (md, &c);
	return 1;
}

static int get_base64 (const void *from, size_t avail, char *to, size_t size)
{
	BIO *b64, *mem;
	char *p;
	long len;

	if ((b64 = BIO_new (BIO_f_base64 ())) == NULL)
		return 0;

	if ((mem = BIO_new (BIO_s_mem ())) == NULL)
		goto error;

	BIO_push (b64, mem);

	if (BIO_write (b64, from, avail) < 0 ||
	    BIO_flush (b64) != 1)
		goto error;

	len = BIO_get_mem_data (mem, &p);
	if (len > size)
		len = size;

	memcpy (to, p, len);
	BIO_free_all (b64);
	return len;
error:
	BIO_free_all (b64);
	return 0;
}

int get_chain_hash (const char *scope, const char *name, const char *type,
		    void *hash)
{
	char md[SHA_DIGEST_LENGTH];

	if (!get_chain_sha1 (scope, name, type, md))
		return 0;

	return get_base64 (md, sizeof (md), hash, 27) == 27;
}

#include <err.h>
#include <stdio.h>

int main (int argc, char *argv[])
{
	const char *scope = NULL, *name = NULL, *type = NULL;
	char hash[27];

	if (argc > 1 && argv[1][0] != '\0')
		scope = argv[1];

	if (argc > 2 && argv[2][0] != '\0')
		name = argv[2];

	if (argc > 3 && argv[3][0] != '\0')
		type = argv[3];

	OpenSSL_add_all_digests ();

	if (!get_chain_hash (scope, name, type, hash))
		errx (1, "could not format hash");

	printf ("hash = %.27s\n", hash);
	return 0;
}
