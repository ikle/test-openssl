#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

int main(int argc, char *argv[])
{
	BIO *b;
	const EVP_MD *md;
	EVP_MD_CTX c;
	unsigned char buf[BUFSIZ];
	int len, i;
	unsigned char hash[EVP_MAX_MD_SIZE];

	if (argc < 2) {
		fprintf(stderr, "Usage:\n\t%s <filename> ...\n", argv[0]);
		return 1;
	}

	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname("md5");

	for (; argc > 1; --argc, ++argv) {
		if ((b = BIO_new_file(argv[1], "r")) == NULL) {
			fprintf(stderr, "ERROR: Unable to open file '%s'\n", argv[1]);
			return 1;
		}

		EVP_MD_CTX_init(&c);
		EVP_DigestInit_ex(&c, md, NULL);

		/* TODO: check read errors */
		while ((len = BIO_read(b, buf, sizeof(buf))) > 0)
			EVP_DigestUpdate(&c, buf, len);

		BIO_free(b);

		EVP_DigestFinal_ex(&c, hash, &len);
		EVP_MD_CTX_cleanup(&c);

		for (i = 0; i < len; ++i)
			printf("%02x", hash[i]);

		printf("  %s\n", argv[1]);
	}

	return 0;
}
