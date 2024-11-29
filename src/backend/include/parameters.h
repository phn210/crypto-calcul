#ifndef PARAMETERS_H
#define PARAMETERS_H

#define SECURITY_LEVEL unsigned int
#define L0 112
#define L1 128
#define L2 192
#define L3 256

#define PRIMALITY_TEST unsigned char
#define GMP_TEST 0
#define FERMAT_TEST 1
#define MILLER_RABIN_TEST 2

#define HASH_FUNCTION unsigned char
#define MD5 0
#define SHA1 1
#define SHA2 2
#define SHA3 3

#define ECC unsigned char
#define WEIERSTRASS 0
#define MONTGOMERY 1
#define EDWARDS 2

#define WEIERSTRASS_CURVE unsigned char
#define P224 0
#define P256 1
#define P384 2
#define P521 3
#define P256K1 4

#define MONTGOMERY_CURVE unsigned char
#define C25519 0

#define EDWARDS_CURVE unsigned char
#define E25519 0
#define E448 1

#endif