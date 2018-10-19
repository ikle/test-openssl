#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "crypto-verify.h"

struct pkey *pkey_read_public(const char *filename, const char *password)
{
	FILE *f;
	EVP_PKEY *key;
	X509 *cert;

	if ((f = fopen(filename, "rb")) == NULL)
		return NULL;

	key = PEM_read_PUBKEY(f, NULL, NULL, (void *) password);
	if (key != NULL)
		goto out;

	rewind(f);

	if ((cert = PEM_read_X509(f, NULL, NULL, (void *) password)) == NULL)
		goto out;

	key = X509_get_pubkey(cert);
	X509_free(cert);
out:
	fclose(f);
	return (void *) key;
}

int verify_init(struct verify_ctx *c, const char *digest)
{
	const EVP_MD *md;

	if ((md = EVP_get_digestbyname(digest)) == NULL)
		return 0;

	EVP_MD_CTX_init(&c->c);

	return EVP_VerifyInit_ex(&c->c, md, NULL);
}

int verify_final(struct verify_ctx *c, const void *sign, size_t size,
		 struct pkey *key)
{
	int status = EVP_VerifyFinal(&c->c, sign, size, (void *) key);

	EVP_MD_CTX_cleanup(&c->c);
	return status == 1;
}
