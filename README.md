# Generate RSA key pair

```
$ openssl genpkey -algorithm rsa -out privkey.pem
....................++++++
..........................++++++
$ openssl rsa -in privkey.pem -pubout -out pubkey.pem
writing RSA key
$
```

# Sign and verify

```
$ ./evp-sign privkey.pem evp-sign.c > sign
$ hd sign
00000000  36 4e 79 d8 df 8e df a1  ec 33 86 a2 7c fb 6c 14  |6Ny......3..|.l.|
00000010  8d 56 a4 fa 5d 0b 85 fc  09 f2 97 5f d2 2a 84 4b  |.V..]......_.*.K|
00000020  98 fa d1 7e e5 8e 56 d8  69 20 d6 7d 1a f1 d9 20  |...~..V.i .}... |
00000030  1d f4 3c 77 99 cb 28 dd  26 b6 dc b5 07 ab b7 29  |..<w..(.&......)|
00000040  52 e7 fd a9 e4 c8 2a 3b  9e 4c eb c3 4a 5e 1a 21  |R.....*;.L..J^.!|
00000050  5a 3e eb 96 9b 40 ca 56  c3 3e 83 d6 ec 63 d5 e2  |Z>...@.V.>...c..|
00000060  34 69 24 f3 66 ff e2 f4  c4 d3 38 85 40 47 da c1  |4i$.f.....8.@G..|
00000070  44 ab 3d af 24 6c 9e ec  2b 5e 25 01 ee 7d 77 a0  |D.=.$l..+^%..}w.|
00000080
$ ./evp-verify pubkey.pem evp-sign.c < sign
$ echo $?
0
$
```

# Verify protocol

1. request 'file': filename and file descriptor to verify;
2. request 'data': file offset and data chunk size to verify;
3. request 'signature': file offset and signature size to verify with;
4. each request must be answered;
5. possible answers: continue, accept or reject;
6. file closed on accept or reject;
7. any error condition equal to reject.

## Use cases

### File required to verify

1. in: file, out: continue;
2. in: data, out: continue — zero or more times;
3. in signature, out: accept or reject.

### File matched by path should be accepted or rejected

1. in: file, out: accept or reject.

## Kernel

Until public verification key is not loaded verification disabled (always
accepted). Once key loaded it cannot be changed.

## Userspace API

New open flag O_VERIFY — verification requested.

1. int open (const char *filename, O_VERIFY | ...): regular open + file request
  1. ret >= 0 — accept, verification does not required;
  2. ret = -1, errno = EINVAL  — writable mode requested alongside with
     verification;
  3. ret = -1, errno = EBUSY   — file opened for writing already;
  4. ret = -1, errno = EACCESS — reject;
  5. ret = -1, errno = EVERIFY — continue (verification required), file
     locked for any modifications;
  6. ret = -1, errno = any other open error.
2. int verify_update (int fd, loff_t offset, size_t size): data request
  1. ret = 0 — continue;
  2. ret = -1 + errno = EACCESS — reject (should never happen);
  3. ret = -1, errno = EBADF, EIO or another system level error.
3. int verify (int fd, loff_t offset, size_t size): signature request
  1. ret = 0 — accept;
  2. ret = -1 + errno = EACCESS — reject;
  3. ret = -1, errno = EBADF, EIO or another system level error.