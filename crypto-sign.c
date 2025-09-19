/*
 * OpenSSL Crypto Sign Helpers
 *
 * Copyright (c) 2015-2025 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "crypto-sign.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define EVP_MD_CTX_new   EVP_MD_CTX_create
#define EVP_MD_CTX_free  EVP_MD_CTX_destroy
#endif

struct pkey *pkey_read_private (const char *filename, const char *password)
{
	FILE *f;
	EVP_PKEY *key;

	if ((f = fopen (filename, "rb")) == NULL)
		return NULL;

	key = PEM_read_PrivateKey (f, NULL, NULL, (void *) password);

	fclose (f);
	return (void *) key;
}

int sign_init (struct sign_ctx *c, const char *digest)
{
	const EVP_MD *md;

	if ((md = EVP_get_digestbyname (digest)) == NULL)
		return 0;

	if ((c->c = EVP_MD_CTX_new ()) == NULL)
		return 0;

	return EVP_SignInit_ex (c->c, md, NULL);
}

int sign_final (struct sign_ctx *c, void *sign, size_t size, struct pkey *key)
{
	unsigned len = size;

	if (sign == NULL)
		return EVP_PKEY_size ((void *) key);

	if (!EVP_SignFinal (c->c, sign, &len, (void *) key))
		len = 0;

	EVP_MD_CTX_free (c->c);
	return len;
}
