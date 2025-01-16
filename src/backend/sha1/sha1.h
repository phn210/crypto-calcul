#ifndef SHA1_H
#define SHA1_H

#include "common.h"

#define SHA1_BLOCK_SIZE 20 // SHA1 outputs a 20 byte digest
#define SHA1_DIGEST_SIZE 20

typedef struct
{
	BYTE data[64];
	uint32_t datalen;
	uint64_t bitlen;
	uint32_t state[5];
	uint32_t k[4];
} sha1_ctx;

/*********************** FUNCTION DECLARATIONS **********************/
void sha1_init(sha1_ctx *ctx);
void sha1_update(sha1_ctx *ctx, const BYTE data[], size_t len);
void sha1_final(sha1_ctx *ctx, BYTE hash[SHA1_DIGEST_SIZE]);
void *sha1(const void *m, size_t len, void *md, size_t md_len);

#endif
