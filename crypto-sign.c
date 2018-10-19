#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "crypto-sign.h"

struct pkey *pkey_read_private(const char *filename, const char *password)
{
	FILE *f;
	EVP_PKEY *key;

	if ((f = fopen(filename, "rb")) == NULL)
		return NULL;

	key = PEM_read_PrivateKey(f, NULL, NULL, (void *) password);

	fclose(f);
	return (void *) key;
}

int sign_init(struct sign_ctx *c, const char *digest)
{
	const EVP_MD *md;

	if ((md = EVP_get_digestbyname(digest)) == NULL)
		return 0;

	EVP_MD_CTX_init(&c->c);

	return EVP_SignInit_ex(&c->c, md, NULL);
}

void *sign_final(struct sign_ctx *c, size_t *size, struct pkey *key)
{
	void *sign;
	unsigned len = EVP_PKEY_size((void *) key);

	if ((sign = malloc(len)) == NULL)
		goto no_mem;

	if (!EVP_SignFinal(&c->c, sign, &len, (void *) key))
		goto no_sign;

	EVP_MD_CTX_cleanup(&c->c);
	*size = len;
	return sign;
no_sign:
	free(sign);
no_mem:
	EVP_MD_CTX_cleanup(&c->c);
	return NULL;
}
