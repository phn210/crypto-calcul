// #include "ss.h"
// #include "conversion.h"
// #include "rng.h"

// void init_ss(ss_ctx_t *ctx, size_t n, size_t t, size_t p, ss_algo_t scheme)
// {
//     ctx->scheme = scheme;
//     ctx->n = n;
//     ctx->p = p;

//     if (scheme == SHAMIR)
//     {
//         if (t > n)
//         {
//             fprintf(stderr, "t must be less than or equal n\n");
//             exit(EXIT_FAILURE);
//         }
//         ctx->t = t;
//     }
//     else if (scheme == ADDITIVE || scheme == MULTIPLICATIVE)
//         ctx->t = n;
//     else
//     {
//         fprintf(stderr, "Invalid scheme\n");
//         exit(EXIT_FAILURE);
//     }
//     ctx->secret_len = p;
//     ctx->share_len = p * n;
//     ctx->secret = (uint8_t *)malloc(ctx->secret_len);
//     ctx->shares = (ss_share_t *)malloc(n * sizeof(ss_share_t));
//     for (size_t i = 0; i < n; i++)
//     {
//         ctx->shares[i].s = (uint8_t *)malloc(ctx->share_len);
//     }
//     ctx->is_ready = 0;
// }

// void free_ss(ss_ctx_t *ctx)
// {
//     free(ctx->secret);
//     for (size_t i = 0; i < ctx->n; i++)
//     {
//         free(ctx->shares[i].s);
//     }
//     free(ctx->shares);
// }

// void create_shares(ss_ctx_t *ctx, const uint8_t *secret) {
//     if (!ctx->is_ready)
//     {
//         fprintf(stderr, "Secret sharing context is not ready\n");
//         exit(EXIT_FAILURE);
//     }

//     mpz_t s;
//     mpz_init(s);
//     bytes_to_bigint(s, secret, ctx->secret_len);

//     gmp_randstate_t state;
//     rng_init(state);

//     switch (ctx->scheme)
//     {
//     case SHAMIR:
//         break;
//     case ADDITIVE:
//         mpz_t r, sum;
//         mpz_inits(r, sum, NULL);
//         for (int i=0; i<ctx->n-1; i++) {
//             rand_int_m(r, state, ctx->p);
//             bigint_to_bytes(ctx->shares[i].s, r, ctx->share_len);
//             ctx->shares[i].i = i+1;
//             mpz_add(sum, sum, r);
//         }
//         mpz_sub(r, s, sum);
//         mpz_mod(r, r, ctx->p);
//         bigint_to_bytes(ctx->shares[ctx->n-1].s, r, ctx->share_len);
//         ctx->shares[ctx->n-1].i = ctx->n;
//         mpz_clears(r, sum, NULL);
//         break;
//     case MULTIPLICATIVE:
//         mpz_t r, prod;
//         mpz_inits(r, prod, NULL);
//         for (int i=0; i<ctx->n-1; i++) {
//             rand_int_m(r, state, ctx->p);
//             bigint_to_bytes(ctx->shares[i].s, r, ctx->share_len);
//             ctx->shares[i].i = i+1;
//             mpz_mul(prod, prod, r);
//         }
//         mpz_invert(r, prod, ctx->p);
//         mpz_mod(r, r, ctx->p);
//         mpz_mul(r, s, r);
//         bigint_to_bytes(ctx->shares[ctx->n-1].s, r, ctx->share_len);
//         ctx->shares[ctx->n-1].i = ctx->n;
//         mpz_clears(r, prod, NULL);
//         break;
//     }

//     ctx->is_ready = 1;
//     mpz_clear(s);
//     gmp_randclear(state);
// }

// void create_shares_with_seed(ss_ctx_t *ctx, const uint8_t *secret, unsigned int seed) {
//     if (!ctx->is_ready)
//     {
//         fprintf(stderr, "Secret sharing context is not ready\n");
//         exit(EXIT_FAILURE);
//     }

//     mpz_t s;
//     mpz_init(s);
//     bytes_to_bigint(s, secret, ctx->secret_len);

//     for (int i=0; i<ctx->n; i++) {

//     }
// }

// void contribute_share(ss_ctx_t *ctx, ss_share_t *share, unsigned int index)
// {
//     if (!ctx->is_ready)
//     {
//         fprintf(stderr, "Secret sharing context is not ready\n");
//         exit(EXIT_FAILURE);
//     }
//     if (index < 1 || index > ctx->n)
//     {
//         fprintf(stderr, "Invalid index\n");
//         exit(EXIT_FAILURE);
//     }
//     if (ctx->scheme == SHAMIR)
//     {
//         fprintf(stderr, "Contribute share is not supported for Shamir's scheme\n");
//         exit(EXIT_FAILURE);
//     }
//     memcpy(ctx->shares[index - 1].s, share->s, ctx->share_len);
//     ctx->shares[index - 1].i = share->i;
// }

// void reconstruct_secret(ss_ctx_t *ctx, uint8_t *secret, ss_share_t *shares, size_t num_shares);

// void share_to_bytes(ss_ctx_t ctx, ss_share_t share, uint8_t *bytes)
// {
//     memcpy(bytes, share.s, ctx.share_len);
//     memcpy(bytes + ctx.share_len, &share.i, sizeof(unsigned int));
// }

// void share_from_bytes(ss_ctx_t ctx, ss_share_t *share, const uint8_t *bytes)
// {
//     memcpy(share->s, bytes, ctx.share_len);
//     memcpy(&share->i, bytes + ctx.share_len, sizeof(unsigned int));
// }