#ifndef PARAMETERS_H
#define PARAMETERS_H

#define SECURITY_LEVEL unsigned int
#define L0 112
#define L1 128
#define L2 192
#define L3 256

#ifdef BYTE_ORDER

#undef BYTE_ORDER
#undef NATIVE
#undef BIG_ENDIAN
#undef LITTLE_ENDIAN

#define BYTE_ORDER char
#define NATIVE 0
#define BIG_ENDIAN 1
#define LITTLE_ENDIAN -1

#endif

#define PRIMALITY_TEST unsigned char
#define GMP_TEST 0
#define FERMAT_TEST 1
#define MILLER_RABIN_TEST 2

#define HASH_FUNCTION unsigned char
#define MD5 0
#define SHA1 1
#define SHA2 2
#define SHA3 3
#define POSEIDON 4

#define RSA_ALGORITHM unsigned char
#define STANDARD 0
#define CRT 1

#define EC unsigned char
#define WEIERSTRASS 0
#define MONTGOMERY 1
#define EDWARDS 2

#define WEIERSTRASS_CURVE unsigned char
#define P224 0
#define P256 1
#define P384 2
#define P521 3
#define P256K1 4
#define W25519 5
#define W448 6

#define MONTGOMERY_CURVE unsigned char
#define C25519 0
#define C448 1

#define EDWARDS_CURVE unsigned char
#define ED25519 0
#define ED448 1
#define E448 2

#define SECRET_SHARING unsigned char
#define ADDITIVE 0
#define MULTIPLICATIVE 1
#define SHAMIR 2

#endif