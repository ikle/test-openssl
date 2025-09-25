/*
 * EVP Asymmetric Key Helpers
 *
 * Copyright (c) 2011-2025 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef EVP_PKEY_H
#define EVP_PKEY_H  1

#include <stdio.h>

#include <openssl/pem.h>

#include "evp-core.h"

struct evp_pkey *evp_pkey_read_private (FILE *from, const char *pass)
{
	return (void *) PEM_read_PrivateKey (from, NULL, NULL, (void *) pass);
}

struct evp_pkey *evp_pkey_read_public (FILE *from, const char *pass)
{
	return (void *) PEM_read_PUBKEY (from, NULL, NULL, (void *) pass);
}

#define EVP_DEFINE_OPEN(type)						\
struct evp_pkey *evp_pkey_open_##type (const char *path, const char *pass) \
{									\
	FILE *in;							\
	struct evp_pkey *o;						\
									\
	if ((in = fopen (path, "rb")) == NULL)				\
		return NULL;						\
									\
	o = evp_pkey_read_##type (in, pass);				\
	fclose (in);							\
	return o;							\
}

EVP_DEFINE_OPEN (private)
EVP_DEFINE_OPEN (public)

#define evp_key(o)  (EVP_PKEY *) (o)

static inline void evp_pkey_close (struct evp_pkey *o)
{
	EVP_PKEY_free (evp_key (o));
}

static inline size_t evp_pkey_size (struct evp_pkey *o)
{
	return EVP_PKEY_size (evp_key (o));
}

#undef evp_key
#undef EVP_DEFINE_OPEN

#endif  /* EVP_PKEY_H */
