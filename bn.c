#include <stdio.h>

#include <openssl/bn.h>

static void bn_load_save(const char *in)
{
	BN_CTX *c;
	BIGNUM *a;
	char *out;

	c = BN_CTX_new();
	BN_CTX_start(c);

	a = BN_CTX_get(c);

	BN_hex2bn(&a, in);
	out = BN_bn2hex(a);

	printf("in:  %s\nout: %s\n", in, out);

	OPENSSL_free(out);

	BN_CTX_end(c);
	BN_CTX_free(c);
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "usage:\n\tbn <hex-number>\n");
		return 1;
	}

	bn_load_save(argv[1]);
	return 0;
}
