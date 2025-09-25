# Generate RSA key pair

```
$ openssl genpkey -algorithm rsa -out privkey.pem
....................++++++
..........................++++++
$ openssl rsa -in privkey.pem -pubout -out pubkey.pem
writing RSA key
$
```

# Generating GOST keys

Generate key pair:
```
$ openssl genpkey -algorithm gost2001 -pkeyopt paramset:A -out gost-privkey.pem
$ openssl pkey -in gost-privkey.pem -pubout -out gost-pubkey.pem
```

Show result:
```
$ openssl pkey -in gost-privkey.pem -text -noout
$ openssl pkey -pubin -in gost-pubkey.pem -text -noout
```

Generate certificate and extract public key from it:
```
$ openssl req -new -x509 -days 365 -key gost-privkey.pem -out gost-ca.pem \
  -subj "/C=RU/ST=Russia/L=Spb/O=Ikle Org/OU=Ikle CA/CN=Ikle CA Root"
$ openssl x509 -in gost-ca.pem -text -noout
$ openssl x509 -inform pem -in gost-ca.pem -pubkey -noout > gost-pubkey.pem
```

Where `-inform pem` for pkey and x509 subcommands are optional.

# Sign and verify

```
$ ./evp-sign md5 privkey.pem evp-sign.c > sign
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
$ ./evp-verify md5 pubkey.pem evp-sign.c < sign
$ echo $?
0
$
```

# Sign and verify with GOST

```
$ ./evp-sign md_gost94 gost-privkey.pem evp-sign.c > sign
$ hd sign
00000000  3f 6a b0 2e e4 41 a4 ae  e1 f4 87 43 20 b0 4f b2  |?j...A.....C .O.|
00000010  cd ee 09 b1 4c ad 58 fc  72 9a d5 89 19 d3 39 89  |....L.X.r.....9.|
00000020  a2 50 73 c7 5d 63 7c c3  1e 6c d6 53 d5 64 81 cb  |.Ps.]c|..l.S.d..|
00000030  a0 1e 0c 69 60 04 32 2e  30 e8 53 0e 2a 24 97 ad  |...i`.2.0.S.*$..|
00000040
$ ./evp-verify md_gost94 gost-pubkey.pem evp-sign.c < sign
$ echo $?
0
```

