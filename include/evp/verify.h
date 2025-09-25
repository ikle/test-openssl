/*
 * EVP Signature Verify Helpers
 *
 * Copyright (c) 2011-2025 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef EVP_VERIFY_H
#define EVP_VERIFY_H  1

#include <evp/pkey.h>

#define evp_key(o)  (EVP_PKEY *) (o)
#define evp_mdc(o)  (EVP_MD_CTX *) (o)

static inline struct evp_verify *
evp_verify_open (const char *digest, const struct evp_pkey *key)
{
	EVP_MD_CTX *c;

	if ((c = EVP_MD_CTX_new ()) == NULL)
		return NULL;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if (EVP_DigestVerifyInit (c, NULL, EVP_get_digestbyname (digest),
				  NULL, evp_key (key)) == 1)
#else
	if (EVP_DigestVerifyInit_ex (c, NULL, digest, NULL, NULL,
				     evp_key (key), NULL) == 1)
#endif
		return (void *) c;

	EVP_MD_CTX_free (c);
	return NULL;
}

static inline
int evp_verify_update (struct evp_verify *o, const void *data, size_t size)
{
	return EVP_DigestVerifyUpdate (evp_mdc (o), data, size) == 1;
}

static inline
int evp_verify_final (struct evp_verify *o, const void *sign, size_t size)
{
	return EVP_DigestVerifyFinal (evp_mdc (o), sign, size) == 1;
}

static inline void evp_verify_close (struct evp_verify *o)
{
	EVP_MD_CTX_free (evp_mdc (o));
}

#undef evp_mdc
#undef evp_key

#endif  /* EVP_VERIFY_H */
