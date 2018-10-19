#ifndef _CRYPTO_SIGN_H
#define _CRYPTO_SIGN_H  1

#include <openssl/evp.h>

struct pkey *pkey_read_private(const char *filename, const char *password);

static inline void pkey_free(struct pkey *key)
{
	EVP_PKEY_free((void *) key);
}

struct sign_ctx {
	EVP_MD_CTX c;
};

int sign_init(struct sign_ctx *c, const char *digest);

static inline
int sign_update(struct sign_ctx *c, const void *data, size_t size)
{
	return EVP_SignUpdate(&c->c, data, size);
}

int sign_final(struct sign_ctx *c, void *sign, size_t size, struct pkey *key);

#endif  /* _CRYPTO_SIGN_H */
