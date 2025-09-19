/*
 * OpenSSL Crypto Verify Helpers
 *
 * Copyright (c) 2015-2025 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "crypto-verify.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define EVP_MD_CTX_new   EVP_MD_CTX_create
#define EVP_MD_CTX_free  EVP_MD_CTX_destroy
#endif

struct pkey *pkey_read_public (const char *filename, const char *password)
{
	FILE *f;
	EVP_PKEY *key;
	X509 *cert;

	if ((f = fopen (filename, "rb")) == NULL)
		return NULL;

	key = PEM_read_PUBKEY (f, NULL, NULL, (void *) password);
	if (key != NULL)
		goto out;

	rewind (f);

	if ((cert = PEM_read_X509 (f, NULL, NULL, (void *) password)) == NULL)
		goto out;

	key = X509_get_pubkey (cert);
	X509_free (cert);
out:
	fclose (f);
	return (void *) key;
}

int verify_init (struct verify_ctx *c, const char *digest)
{
	const EVP_MD *md;

	if ((md = EVP_get_digestbyname (digest)) == NULL)
		return 0;

	if ((c->c = EVP_MD_CTX_new ()) == NULL)
		return 0;

	return EVP_VerifyInit_ex (c->c, md, NULL);
}

int verify_final (struct verify_ctx *c, const void *sign, size_t size,
		  struct pkey *key)
{
	int status = EVP_VerifyFinal (c->c, sign, size, (void *) key);

	EVP_MD_CTX_free (c->c);
	return status == 1;
}
