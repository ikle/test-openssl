#include <stdio.h>
#include <openssl/bio.h>

int sign_print(FILE *f, const void *data, size_t size)
{
	BIO *file, *b64;
	const char *p;
	int count;

	if ((b64 = BIO_new(BIO_f_base64())) == NULL)
		goto no_base64;

	if ((file = BIO_new_fp(f, BIO_NOCLOSE)) == NULL)
		goto no_file;

	BIO_push(b64, file);

	for (p = data; size > 0; p += count, size -= count)
		if ((count = BIO_write(b64, p, size)) <= 0)
			goto no_write;

	BIO_flush(b64);

	BIO_free_all(b64);
	return 1;
no_write:
	BIO_vfree(file);
no_file:
	BIO_vfree(b64);
no_base64:
	return 0;
}
