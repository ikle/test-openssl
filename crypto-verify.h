#ifndef _CRYPTO_VERIFY_H
#define _CRYPTO_VERIFY_H  1

#include <stddef.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

struct pkey *pkey_read_public(const char *filename, const char *password);

static inline void pkey_free(struct pkey *key)
{
	EVP_PKEY_free((void *) key);
}

static inline size_t pkey_size(struct pkey *key)
{
	return EVP_PKEY_size((void *) key);
}

struct verify_ctx {
	EVP_MD_CTX c;
};

int verify_init(struct verify_ctx *c, const char *digest);

static inline
int verify_update(struct verify_ctx *c, const void *data, size_t size)
{
	return EVP_VerifyUpdate(&c->c, data, size);
}

int verify_final(struct verify_ctx *c, const void *sign, size_t size,
		 struct pkey *key);

#endif  /* _CRYPTO_VERIFY_H */
