#ifndef SS_H
#define SS_H

#include "common.h"

typedef struct ss_share
{
    uint8_t *s; // shares
    unsigned int i; // index
} ss_share_t;

typedef struct ss_ctx
{
    SECRET_SHARING scheme; // secret sharing scheme
    size_t n; // number of shares
    size_t t; // maximum number of shares without reconstruction
    size_t share_len; // share length in bytes
    size_t secret_len; // secret length in bytes
    size_t p; // modulus
    uint8_t *secret; // secret
    ss_share_t *shares; // shares
    char is_ready; // ready flag
} ss_ctx_t;

void init_ss(ss_ctx_t *ctx, size_t n, size_t t, size_t p, SECRET_SHARING scheme);
void free_ss(ss_ctx_t *ctx);

void create_shares(ss_ctx_t *ctx, const uint8_t *secret);
void contribute_share(ss_ctx_t *ctx, ss_share_t *share, unsigned int index);
void reconstruct_secret(ss_ctx_t *ctx, uint8_t *secret, ss_share_t *shares, size_t num_shares);

void share_to_bytes(ss_ctx_t ctx, ss_share_t share, uint8_t *bytes);
void share_from_bytes(ss_ctx_t ctx, ss_share_t *share, const uint8_t *bytes);

#endif