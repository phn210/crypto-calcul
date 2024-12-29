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
} sha1_ctx;

/*********************** FUNCTION DECLARATIONS **********************/
void sha1_init(sha1_ctx *ctx);
void sha1_update(sha1_ctx *ctx, const BYTE data[], size_t len);
void sha1_final(sha1_ctx *ctx, BYTE hash[]);
void *sha1(const void *m, size_t len, void *md, size_t md_len);

#endif
