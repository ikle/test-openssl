/*
 * EVP Message Digest Helpers
 *
 * Copyright (c) 2011-2025 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef EVP_DIGEST_H
#define EVP_DIGEST_H  1

#include <string.h>

#include <evp/core.h>

#define evp_mdc(o)  (EVP_MD_CTX *) (o)

static inline struct evp_digest *evp_digest_open (const char *digest)
{
	EVP_MD_CTX *c;

	if ((c = EVP_MD_CTX_new ()) == NULL)
		return NULL;

	if (EVP_DigestInit_ex (c, EVP_get_digestbyname (digest), NULL) == 1)
		return (void *) c;

	EVP_MD_CTX_free (c);
	return NULL;
}

static inline
int evp_digest_update (struct evp_digest *o, const void *data, size_t size)
{
	return EVP_DigestUpdate (evp_mdc (o), data, size) == 1;
}

static inline
size_t evp_digest_final (struct evp_digest *o, void *md, size_t size)
{
	unsigned char buf[EVP_MAX_MD_SIZE];
	unsigned len;

	if (md == NULL)
		return EVP_MD_CTX_size (evp_mdc (o));

	if (size >= sizeof (buf))
		return EVP_DigestFinal_ex (evp_mdc (o), md, &len) == 1 ? len : 0;

	if (EVP_DigestFinal_ex (evp_mdc (o), buf, &len) != 1)
		return 0;

	memcpy (md, buf, len = len < size ? len : size);
	OPENSSL_cleanse (buf, sizeof (buf));
	return len;
}

static inline int evp_digest_reset (struct evp_digest *o)
{
	return EVP_DigestInit_ex (evp_mdc (o), NULL, NULL) == 1;
}

static inline void evp_digest_close (struct evp_digest *o)
{
	EVP_MD_CTX_free (evp_mdc (o));
}

#undef evp_mdc

#endif  /* EVP_DIGEST_H */
