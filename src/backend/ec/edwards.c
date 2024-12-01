#include "ec.h"
#include "conversion.h"

void init_curve(curve_t *curve, EDWARDS_CURVE curve_id)
{
    init_affine(&curve->G);
    mpz_inits(curve->p, curve->r, curve->a, curve->b, NULL);

    switch (curve_id)
    {
    case ED448:
    {
        curve->name = (char *)malloc(strlen(ED448_NAME) + 1);
        memcpy(curve->name, ED448_NAME, strlen(ED448_NAME));
        // curve->hash = sha2;
        curve->md_len = ED448_MD_LEN;
        curve->efs = ED448_EFS;
        curve->cof = ED448_COF;
        hex_to_bigint(curve->p, ED448_p);
        hex_to_bigint(curve->r, ED448_r);
        mpz_set_si(curve->a, ED448_A);
        hex_to_bigint(curve->b, ED448_B);
        hex_to_bigint(curve->G.x, ED448_Gx);
        hex_to_bigint(curve->G.y, ED448_Gy);
        break;
    }
    case E448:
    {
        curve->name = (char *)malloc(strlen(E448_NAME) + 1);
        memcpy(curve->name, E448_NAME, strlen(E448_NAME));
        // curve->hash = sha2;
        curve->md_len = E448_MD_LEN;
        curve->efs = E448_EFS;
        curve->cof = E448_COF;
        hex_to_bigint(curve->p, E448_p);
        hex_to_bigint(curve->r, E448_r);
        mpz_set_si(curve->a, E448_A);
        hex_to_bigint(curve->b, E448_B);
        hex_to_bigint(curve->G.x, E448_Gx);
        hex_to_bigint(curve->G.y, E448_Gy);
        break;
    }
    default: // ED25519
    {
        curve->name = (char *)malloc(strlen(ED25519_NAME) + 1);
        memcpy(curve->name, ED25519_NAME, strlen(ED25519_NAME));
        // curve->hash = sha2;
        curve->md_len = ED25519_MD_LEN;
        curve->efs = ED25519_EFS;
        curve->cof = ED25519_COF;
        hex_to_bigint(curve->p, ED25519_p);
        hex_to_bigint(curve->r, ED25519_r);
        mpz_set_si(curve->a, ED25519_A);
        hex_to_bigint(curve->b, ED25519_B);
        hex_to_bigint(curve->G.x, ED25519_Gx);
        hex_to_bigint(curve->G.y, ED25519_Gy);
        break;
    }
    }
}

char is_infinity(const point_t p)
{
    return mpz_sgn(p.x) == 0 && mpz_cmp(p.y, p.z) == 0;
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
    mpz_neg(r->x, r->x);
    mpz_mod(r->x, r->x, curve.p);
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

    // Projective coordinates for twisted Edwards curves
    // https://www.hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#addition-add-2008-bbjlp

    mpz_t A, B, C, D, E, F, G, X3, Y3, Z3;
    mpz_inits(A, B, C, D, E, F, G, X3, Y3, Z3, NULL);

    mpz_mul(A, p.z, q.z);
    mpz_powm_ui(B, A, 2, curve.p);
    mpz_mul(C, p.x, q.x);
    mpz_mul(D, p.y, q.y);
    mpz_mul(E, curve.b, C);
    mpz_mul(E, E, D);
    mpz_sub(F, B, E);
    mpz_add(G, B, E);
    mpz_add(B, p.x, p.y);
    mpz_add(E, q.x, q.y);
    mpz_mul(B, B, E);
    mpz_sub(B, B, C);
    mpz_sub(B, B, D);
    mpz_mul(B, A, B);
    mpz_mul(X3, F, B);
    mpz_mul(B, curve.a, C);
    mpz_sub(B, D, B);
    mpz_mul(B, G, B);
    mpz_mul(Y3, A, B);
    mpz_mul(Z3, F, G);

    mpz_mod(X3, X3, curve.p);
    mpz_mod(Y3, Y3, curve.p);
    mpz_mod(Z3, Z3, curve.p);

    mpz_set(r->x, X3);
    mpz_set(r->y, Y3);
    mpz_set(r->z, Z3);

    mpz_clears(A, B, C, D, E, F, G, X3, Y3, Z3, NULL);
}

void dbl(point_t *r, const point_t p, const curve_t curve)
{
    if (is_infinity(p))
    {
        infinity(r);
        return;
    }

    // Projective coordinates for twisted Edwards curves
    // https://www.hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#doubling-dbl-2008-bbjlp

    mpz_t B, C, D, E, F, H, J, X3, Y3, Z3;
    mpz_inits(B, C, D, E, F, H, J, X3, Y3, Z3, NULL);

    mpz_add(B, p.x, p.y);
    mpz_powm_ui(B, B, 2, curve.p);
    mpz_powm_ui(C, p.x, 2, curve.p);
    mpz_powm_ui(D, p.y, 2, curve.p);
    mpz_mul(E, curve.a, C);
    mpz_add(F, E, D);
    mpz_powm_ui(H, p.z, 2, curve.p);
    mpz_mul_ui(J, H, 2);
    mpz_sub(J, F, J);
    mpz_sub(B, B, C);
    mpz_sub(B, B, D);
    mpz_mul(X3, B, J);
    mpz_sub(E, E, D);
    mpz_mul(Y3, F, E);
    mpz_mul(Z3, F, J);

    mpz_mod(X3, X3, curve.p);
    mpz_mod(Y3, Y3, curve.p);
    mpz_mod(Z3, Z3, curve.p);

    mpz_set(r->x, X3);
    mpz_set(r->y, Y3);
    mpz_set(r->z, Z3);

    mpz_clears(B, C, D, E, F, H, J, X3, Y3, Z3, NULL);
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
    // (A*X^2 - 1)/(B*X^2 - 1)
    mpz_t t0, t1;
    mpz_inits(t0, t1, NULL);
    mpz_powm_ui(t0, x, 2, curve.p);
    mpz_mul(t1, curve.b, t0);
    mpz_sub_ui(t1, t1, 1);
    mpz_invert(t1, t1, curve.p);
    mpz_mul(t0, curve.a, t0);
    mpz_sub_ui(t0, t0, 1);
    mpz_mul(r, t0, t1);
    mpz_mod(r, r, curve.p);
    mpz_clears(t0, t1, NULL);
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