#include "ec.h"
#include "conversion.h"

void init_curve(curve_t *curve, WEIERSTRASS_CURVE curve_id)
{
    init_affine(&curve->G);
    mpz_inits(curve->p, curve->r, curve->a, curve->b, NULL);

    switch (curve_id)
    {
    case P224:
    {
        curve->name = (char *)malloc(strlen(P224_NAME) + 1);
        memcpy(curve->name, P224_NAME, strlen(P224_NAME));
        // curve->hash = sha2;
        curve->md_len = P224_MD_LEN;
        curve->efs = P224_EFS;
        curve->cof = P224_COF;
        hex_to_bigint(curve->p, P224_p);
        hex_to_bigint(curve->r, P224_r);
        mpz_set_si(curve->a, P224_A);
        hex_to_bigint(curve->b, P224_B);
        hex_to_bigint(curve->G.x, P224_Gx);
        hex_to_bigint(curve->G.y, P224_Gy);
        break;
    }
    case P384:
    {
        curve->name = (char *)malloc(strlen(P384_NAME) + 1);
        memcpy(curve->name, P384_NAME, strlen(P384_NAME));
        // curve->hash = sha2;
        curve->md_len = P384_MD_LEN;
        curve->efs = P384_EFS;
        curve->cof = P384_COF;
        hex_to_bigint(curve->p, P384_p);
        hex_to_bigint(curve->r, P384_r);
        mpz_set_si(curve->a, P384_A);
        hex_to_bigint(curve->b, P384_B);
        hex_to_bigint(curve->G.x, P384_Gx);
        hex_to_bigint(curve->G.y, P384_Gy);
        break;
    }
    case P521:
    {
        curve->name = (char *)malloc(strlen(P521_NAME) + 1);
        memcpy(curve->name, P521_NAME, strlen(P521_NAME));
        // curve->hash = sha2;
        curve->md_len = P521_MD_LEN;
        curve->efs = P521_EFS;
        curve->cof = P521_COF;
        hex_to_bigint(curve->p, P521_p);
        hex_to_bigint(curve->r, P521_r);
        mpz_set_si(curve->a, P521_A);
        hex_to_bigint(curve->b, P521_B);
        hex_to_bigint(curve->G.x, P521_Gx);
        hex_to_bigint(curve->G.y, P521_Gy);
        break;
    }
    case P256K1:
    {
        curve->name = (char *)malloc(strlen(P256K1_NAME) + 1);
        memcpy(curve->name, P256K1_NAME, strlen(P256K1_NAME));
        // curve->hash = sha2;
        curve->md_len = P256K1_MD_LEN;
        curve->efs = P256K1_EFS;
        curve->cof = P256K1_COF;
        hex_to_bigint(curve->p, P256K1_p);
        hex_to_bigint(curve->r, P256K1_r);
        mpz_set_si(curve->a, P256K1_A);
        hex_to_bigint(curve->b, P256K1_B);
        hex_to_bigint(curve->G.x, P256K1_Gx);
        hex_to_bigint(curve->G.y, P256K1_Gy);
        break;
    }
    case W25519:
    {
        curve->name = (char *)malloc(strlen(W25519_NAME) + 1);
        memcpy(curve->name, W25519_NAME, strlen(W25519_NAME));
        // curve->hash = sha2;
        curve->md_len = W25519_MD_LEN;
        curve->efs = W25519_EFS;
        curve->cof = W25519_COF;
        hex_to_bigint(curve->p, W25519_p);
        hex_to_bigint(curve->r, W25519_r);
        hex_to_bigint(curve->a, W25519_A);
        hex_to_bigint(curve->b, W25519_B);
        hex_to_bigint(curve->G.x, W25519_Gx);
        hex_to_bigint(curve->G.y, W25519_Gy);
        break;
    }
    case W448:
    {
        curve->name = (char *)malloc(strlen(W448_NAME) + 1);
        memcpy(curve->name, W448_NAME, strlen(W448_NAME));
        // curve->hash = sha2;
        curve->md_len = W448_MD_LEN;
        curve->efs = W448_EFS;
        curve->cof = W448_COF;
        hex_to_bigint(curve->p, W448_p);
        hex_to_bigint(curve->r, W448_r);
        hex_to_bigint(curve->a, W448_A);
        hex_to_bigint(curve->b, W448_B);
        hex_to_bigint(curve->G.x, W448_Gx);
        hex_to_bigint(curve->G.y, W448_Gy);
        break;
    }
    default: // P256
    {
        curve->name = (char *)malloc(strlen(P256_NAME) + 1);
        memcpy(curve->name, P256_NAME, strlen(P256_NAME));
        // curve->hash = sha2;
        curve->md_len = P256_MD_LEN;
        curve->efs = P256_EFS;
        curve->cof = P256_COF;
        hex_to_bigint(curve->p, P256_p);
        hex_to_bigint(curve->r, P256_r);
        mpz_set_si(curve->a, P256_A);
        hex_to_bigint(curve->b, P256_B);
        hex_to_bigint(curve->G.x, P256_Gx);
        hex_to_bigint(curve->G.y, P256_Gy);
        break;
    }
    }
}

char is_infinity(const point_t p)
{
    return mpz_sgn(p.x) == 0 && mpz_sgn(p.z) == 0;
}

char equals(const point_t p, const point_t q, const curve_t curve)
{
    mpz_t tmp1, tmp2;
    mpz_init_set_ui(tmp1, 0);
    mpz_init_set_ui(tmp2, 0);

    mpz_addmul(tmp1, p.x, q.z);
    mpz_submul(tmp1, q.x, p.z);
    mpz_mod(tmp1, tmp1, curve.p);

    mpz_addmul(tmp2, p.y, q.z);
    mpz_submul(tmp2, q.y, p.z);
    mpz_mod(tmp2, tmp2, curve.p);

    char res = mpz_cmp_ui(tmp1, 0) == 0 && mpz_cmp_ui(tmp2, 0) == 0;
    mpz_clears(tmp1, tmp2, NULL);
    return res;
}

void neg(point_t *r, const point_t p, const curve_t curve)
{
    copy_point(r, p);
    mpz_neg(r->y, r->y);
    mpz_mod(r->y, r->y, curve.p);
}

void add(point_t *r, const point_t p, const point_t q, const curve_t curve)
{
    if (is_infinity(p))
    {
        copy_point(r, q);
        return;
    }

    if (is_infinity(q))
    {
        copy_point(r, p);
        return;
    }

    // Projective coordinates for short Weierstrass curves
    // https://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective-3.html#addition-add-2015-rcb
    // https://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-madd-2015-rcb

    mpz_t b3, t0, t1, t2, t3, t4, t5, X3, Y3, Z3;
    mpz_inits(b3, t0, t1, t2, t3, t4, t5, X3, Y3, Z3, NULL);
    mpz_mul_ui(b3, curve.b, 3);

    if (mpz_cmp_si(curve.a, -3) == 0)
    {
        mpz_mul(t0, p.x, q.x);
        mpz_mul(t1, p.y, q.y);
        mpz_mul(t2, p.z, q.z);
        mpz_add(t3, p.x, p.y);
        mpz_add(t4, q.x, q.y);
        mpz_mul(t3, t3, t4);
        mpz_add(t4, t0, t1);
        mpz_sub(t3, t3, t4);
        mpz_add(t4, p.y, p.z);
        mpz_add(X3, q.y, q.z);
        mpz_mul(t4, t4, X3);
        mpz_add(X3, t1, t2);
        mpz_sub(t4, t4, X3);
        mpz_add(X3, p.x, p.z);
        mpz_add(Y3, q.x, q.z);
        mpz_mul(X3, X3, Y3);
        mpz_add(Y3, t0, t2);
        mpz_sub(Y3, X3, Y3);
        mpz_mul(Z3, curve.b, t2);
        mpz_sub(X3, Y3, Z3);
        mpz_add(Z3, X3, X3);
        mpz_add(X3, X3, Z3);
        mpz_sub(Z3, t1, X3);
        mpz_add(X3, t1, X3);
        mpz_mul(Y3, curve.b, Y3);
        mpz_add(t1, t2, t2);
        mpz_add(t2, t1, t2);
        mpz_sub(Y3, Y3, t2);
        mpz_sub(Y3, Y3, t0);
        mpz_add(t1, Y3, Y3);
        mpz_add(Y3, t1, Y3);
        mpz_add(t1, t0, t0);
        mpz_add(t0, t1, t0);
        mpz_sub(t0, t0, t2);
        mpz_mul(t1, t4, Y3);
        mpz_mul(t2, t0, Y3);
        mpz_mul(Y3, X3, Z3);
        mpz_add(Y3, Y3, t2);
        mpz_mul(X3, t3, X3);
        mpz_sub(X3, X3, t1);
        mpz_mul(Z3, t4, Z3);
        mpz_mul(t1, t3, t0);
        mpz_add(Z3, Z3, t1);
    }
    else
    {
        mpz_mul(t0, p.x, q.x);
        mpz_mul(t1, p.y, q.y);
        mpz_mul(t2, p.z, q.z);
        mpz_add(t3, p.x, p.y);
        mpz_add(t4, q.x, q.y);
        mpz_mul(t3, t3, t4);
        mpz_add(t4, t0, t1);
        mpz_sub(t3, t3, t4);
        mpz_add(t4, p.x, p.z);
        mpz_add(t5, q.x, q.z);
        mpz_mul(t4, t4, t5);
        mpz_add(t5, t0, t2);
        mpz_sub(t4, t4, t5);
        mpz_add(t5, p.y, p.z);
        mpz_add(X3, q.y, q.z);
        mpz_mul(t5, t5, X3);
        mpz_add(X3, t1, t2);
        mpz_sub(t5, t5, X3);
        mpz_mul(Z3, curve.a, t4);
        mpz_mul(X3, b3, t2);
        mpz_add(Z3, X3, Z3);
        mpz_sub(X3, t1, Z3);
        mpz_add(Z3, t1, Z3);
        mpz_mul(Y3, X3, Z3);
        mpz_add(t1, t0, t0);
        mpz_add(t1, t1, t0);
        mpz_mul(t2, curve.a, t2);
        mpz_mul(t4, b3, t4);
        mpz_add(t1, t1, t2);
        mpz_sub(t2, t0, t2);
        mpz_mul(t2, curve.a, t2);
        mpz_add(t4, t4, t2);
        mpz_mul(t0, t1, t4);
        mpz_add(Y3, Y3, t0);
        mpz_mul(t0, t5, t4);
        mpz_mul(X3, t3, X3);
        mpz_sub(X3, X3, t0);
        mpz_mul(t0, t3, t1);
        mpz_mul(Z3, t5, Z3);
        mpz_add(Z3, Z3, t0);
    }

    mpz_mod(X3, X3, curve.p);
    mpz_mod(Y3, Y3, curve.p);
    mpz_mod(Z3, Z3, curve.p);

    mpz_set(r->x, X3);
    mpz_set(r->y, Y3);
    mpz_set(r->z, Z3);

    mpz_clears(t0, t1, t2, t3, t4, t5, X3, Y3, Z3, NULL);
}

void dbl(point_t *r, const point_t p, const curve_t curve)
{
    if (is_infinity(p))
    {
        infinity(r);
        return;
    }

    // Projective coordinates for short Weierstrass curves
    // https://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#doubling-dbl-2015-rcb

    mpz_t b3, t0, t1, t2, t3, X3, Y3, Z3;
    mpz_inits(b3, t0, t1, t2, t3, X3, Y3, Z3, NULL);
    mpz_mul_ui(b3, curve.b, 3);

    if (mpz_cmp_si(curve.a, -3) == 0)
    {
        mpz_powm_ui(t0, p.x, 2, curve.p);
        mpz_powm_ui(t1, p.y, 2, curve.p);
        mpz_powm_ui(t2, p.z, 2, curve.p);
        mpz_mul(t3, p.x, p.y);
        mpz_add(t3, t3, t3);
        mpz_mul(Z3, p.x, p.z);
        mpz_add(Z3, Z3, Z3);
        mpz_mul(Y3, curve.b, t2);
        mpz_sub(Y3, Y3, Z3);
        mpz_add(X3, Y3, Y3);
        mpz_add(Y3, X3, Y3);
        mpz_sub(X3, t1, Y3);
        mpz_add(Y3, t1, Y3);
        mpz_mul(Y3, X3, Y3);
        mpz_mul(X3, X3, t3);
        mpz_add(t3, t2, t2);
        mpz_add(t2, t2, t3);
        mpz_mul(Z3, curve.b, Z3);
        mpz_sub(Z3, Z3, t2);
        mpz_sub(Z3, Z3, t0);
        mpz_add(t3, Z3, Z3);
        mpz_add(Z3, Z3, t3);
        mpz_add(t3, t0, t0);
        mpz_add(t0, t3, t0);
        mpz_sub(t0, t0, t2);
        mpz_mul(t0, t0, Z3);
        mpz_add(Y3, Y3, t0);
        mpz_mul(t0, p.y, p.z);
        mpz_add(t0, t0, t0);
        mpz_mul(Z3, t0, Z3);
        mpz_sub(X3, X3, Z3);
        mpz_mul(Z3, t0, t1);
        mpz_add(Z3, Z3, Z3);
        mpz_add(Z3, Z3, Z3);
    }
    else
    {
        mpz_powm_ui(t0, p.x, 2, curve.p);
        mpz_powm_ui(t1, p.y, 2, curve.p);
        mpz_powm_ui(t2, p.z, 2, curve.p);
        mpz_mul(t3, p.x, p.y);
        mpz_add(t3, t3, t3);
        mpz_mul(Z3, p.x, p.z);
        mpz_add(Z3, Z3, Z3);
        mpz_mul(X3, curve.a, Z3);
        mpz_mul(Y3, b3, t2);
        mpz_add(Y3, X3, Y3);
        mpz_sub(X3, t1, Y3);
        mpz_add(Y3, t1, Y3);
        mpz_mul(Y3, X3, Y3);
        mpz_mul(X3, t3, X3);
        mpz_mul(Z3, b3, Z3);
        mpz_mul(t2, curve.a, t2);
        mpz_sub(t3, t0, t2);
        mpz_mul(t3, curve.a, t3);
        mpz_add(t3, t3, Z3);
        mpz_add(Z3, t0, t0);
        mpz_add(t0, Z3, t0);
        mpz_add(t0, t0, t2);
        mpz_mul(t0, t0, t3);
        mpz_add(Y3, Y3, t0);
        mpz_mul(t2, p.y, p.z);
        mpz_add(t2, t2, t2);
        mpz_mul(t0, t2, t3);
        mpz_sub(X3, X3, t0);
        mpz_mul(Z3, t2, t1);
        mpz_add(Z3, Z3, Z3);
        mpz_add(Z3, Z3, Z3);
    }

    mpz_mod(X3, X3, curve.p);
    mpz_mod(Y3, Y3, curve.p);
    mpz_mod(Z3, Z3, curve.p);

    mpz_set(r->x, X3);
    mpz_set(r->y, Y3);
    mpz_set(r->z, Z3);

    mpz_clears(b3, t0, t1, t2, t3, X3, Y3, Z3, NULL);
}

void mul(point_t *r, const point_t p, const mpz_t k, const curve_t curve)
{
    point_t q;
    init_point(&q);
    infinity(&q);

    size_t i = mpz_sizeinbase(k, 2);
    for (int j = i - 1; j >= 0; j--)
    {
        dbl(&q, q, curve);
        if (mpz_tstbit(k, j))
            add(&q, q, p, curve);
    }

    copy_point(r, q);
    free_point(&q);
}

void rhs(mpz_t r, const mpz_t x, const curve_t curve)
{
    mpz_powm_ui(r, x, 3, curve.p);
    mpz_addmul(r, x, curve.a);
    mpz_add(r, r, curve.b);
    mpz_mod(r, r, curve.p);
}

char is_on_curve(const point_t p, const curve_t curve)
{
    if (is_infinity(p))
        return 1;

    point_affine_t p_affine;
    init_affine(&p_affine);
    affine(&p_affine, p, curve);

    mpz_t tmp;
    mpz_init(tmp);
    rhs(tmp, p_affine.x, curve);
    mpz_neg(tmp, tmp);
    mpz_addmul(tmp, p_affine.y, p_affine.y);
    mpz_mod(tmp, tmp, curve.p);
    char res = mpz_cmp_ui(tmp, 0) == 0;

    mpz_clear(tmp);
    free_affine(&p_affine);
    return res;
}

void infinity(point_t *p)
{
    mpz_set_ui(p->x, 0);
    mpz_set_ui(p->y, 1);
    mpz_set_ui(p->z, 0);
}

void affine(point_affine_t *r, const point_t p, const curve_t curve)
{
    if (is_infinity(p))
    {
        mpz_set_ui(r->x, 0);
        return;
    }

    mpz_set(r->x, p.x);
    mpz_set(r->y, p.y);

    if (mpz_cmp_ui(p.z, 1) == 0)
        return;

    mpz_t z_inv;
    mpz_init(z_inv);
    mpz_invert(z_inv, p.z, curve.p);
    mpz_mul(r->x, r->x, z_inv);
    mpz_mod(r->x, r->x, curve.p);
    mpz_mul(r->y, r->y, z_inv);
    mpz_mod(r->y, r->y, curve.p);
    mpz_clear(z_inv);
}