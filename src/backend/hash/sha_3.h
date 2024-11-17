#ifndef SHA3_H
#define SHA3_H

#include <stddef.h>
#include "parameters.h"

typedef struct sha_3_ctx
{

} sha3_ctx_t;

int sha3_init(sha3_ctx_t *ctx, int digest_size);
int sha3_update(sha3_ctx_t *ctx, const void *data, size_t len);
int sha3_final(void *digest, sha3_ctx_t *ctx);

#endif