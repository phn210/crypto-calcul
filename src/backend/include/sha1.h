#ifndef SHA1_H
#define SHA1_H

#include "common.h"

#define SHA1_BLOCK_SIZE 20              // SHA1 outputs a 20 byte digest

typedef struct {
	BYTE data[64];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[5];
	WORD k[4];
} SHA1_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void sha1_init(SHA1_CTX *ctx);
void sha1_update(SHA1_CTX *ctx, const BYTE data[], size_t len);
void sha1_final(SHA1_CTX *ctx, BYTE hash[]);

#endif
