/*
 * EVP Core Helpers
 *
 * Copyright (c) 2011-2025 Alexei A. Smekalkine <ikle@ikle.ru>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef EVP_CORE_H
#define EVP_CORE_H  1

#include <openssl/conf.h>
#include <openssl/evp.h>

static inline void evp_init (void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	OPENSSL_config (NULL);
#else
	OPENSSL_init_crypto (OPENSSL_INIT_LOAD_CONFIG, NULL);
#endif
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define EVP_MD_CTX_new   EVP_MD_CTX_create
#define EVP_MD_CTX_free  EVP_MD_CTX_destroy
#endif

#endif  /* EVP_CORE_H */
