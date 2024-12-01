#include "ec.h"
#include "conversion.h"

void init_curve(curve_t *curve, MONTGOMERY_CURVE curve_id)
{
    init_affine(&curve->G);
    mpz_inits(curve->p, curve->r, curve->a, curve->b, NULL);

    switch (curve_id)
    {
    case C448:
    {
        // curve->hash = sha2;
        curve->md_len = C448_MD_LEN;
        curve->efs = C448_EFS;
        curve->cof = C448_COF;
        hex_to_bigint(curve->p, C448_p);
        hex_to_bigint(curve->r, C448_r);
        mpz_set_si(curve->a, C448_A);
        hex_to_bigint(curve->b, C448_B);
        hex_to_bigint(curve->G.x, C448_Gx);
        hex_to_bigint(curve->G.y, C448_Gy);
        break;
    }
    default: // C25519
    {
        // curve->hash = sha2;
        curve->md_len = C25519_MD_LEN;
        curve->efs = C25519_EFS;
        curve->cof = C25519_COF;
        hex_to_bigint(curve->p, C25519_p);
        hex_to_bigint(curve->r, C25519_r);
        mpz_set_si(curve->a, C25519_A);
        hex_to_bigint(curve->b, C25519_B);
        hex_to_bigint(curve->G.x, C25519_Gx);
        hex_to_bigint(curve->G.y, C25519_Gy);
        break;
    }
    }
}

char is_infinity(const point_t p)
{
    return mpz_sgn(p.z) == 0;
}

char equals(const point_t p, const point_t q, const curve_t curve)
{
    mpz_t tmp;
    mpz_init_set_ui(tmp, 0);

    mpz_addmul(tmp, p.x, q.z);
    mpz_submul(tmp, q.x, p.z);
    mpz_mod(tmp, tmp, curve.p);

    char res = mpz_cmp_ui(tmp, 0) == 0;
    mpz_clear(tmp);
    return res;
}

void dadd(point_t *r, const point_t p, const point_t q, const point_t w, const curve_t curve)
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
    // https://www.hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#diffadd-dadd-1987-m-3

    mpz_t A, B, C, D, E, F, X5, Z5;
    mpz_inits(A, B, C, D, E, F, X5, Z5, NULL);

    mpz_add(A, q.x, q.z);
    mpz_sub(B, q.x, q.z);
    mpz_add(C, w.x, w.z);
    mpz_sub(D, w.x, w.z);
    mpz_mul(E, A, D);
    mpz_mul(F, B, C);
    mpz_add(A, E, F);
    mpz_sub(B, E, F);
    mpz_powm_ui(A, A, 2, curve.p);
    mpz_powm_ui(B, B, 2, curve.p);
    mpz_mul(X5, p.z, A);
    mpz_mul(Z5, p.x, B);

    mpz_mod(X5, X5, curve.p);
    mpz_mod(Z5, Z5, curve.p);

    mpz_set(r->x, X5);
    mpz_set(r->z, Z5);

    mpz_clears(A, B, C, D, E, F, X5, Z5, NULL);
}

void dbl(point_t *r, const point_t p, const curve_t curve)
{
    if (is_infinity(p))
    {
        infinity(r);
        return;
    }

    // Projective coordinates for short Weierstrass curves
    // https://www.hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#doubling-dbl-2008-bbjlp
    mpz_t a24, A, B, C, X3, Z3;
    mpz_inits(a24, A, B, C, X3, Z3, NULL);
    mpz_add_ui(a24, curve.a, 2);
    mpz_fdiv_q_2exp(a24, a24, 2);

    mpz_add(A, p.x, p.z);
    mpz_powm_ui(A, A, 2, curve.p);
    mpz_sub(B, p.x, p.z);
    mpz_powm_ui(B, B, 2, curve.p);
    mpz_sub(C, A, B);
    mpz_mul(X3, A, B);
    mpz_mul(Z3, C, a24);
    mpz_add(Z3, Z3, B);
    mpz_mul(Z3, Z3, C);

    mpz_mod(X3, X3, curve.p);
    mpz_mod(Z3, Z3, curve.p);

    mpz_set(r->x, X3);
    mpz_set(r->z, Z3);

    mpz_clears(a24, A, B, C, X3, Z3, NULL);
}

void mul(point_t *r, const point_t p, const mpz_t k, const curve_t curve)
{
    if (is_infinity(p) || mpz_sgn(k) == 0)
    {
        infinity(r);
        return;
    }

    int nb, i, b;
    point_t R0, R1, D;
    point_affine_t D_affine;

    init_point(&R0);
    init_point(&R1);
    init_point(&D);
    init_affine(&D_affine);

    copy_point(&R0, p);
    dbl(&R1, p, curve);

    affine(&D_affine, p, curve);
    mpz_set(D.x, D_affine.x);
    mpz_set_ui(D.z, 1);

    nb = mpz_sizeinbase(k, 2);
    printf("nb: %d\n", nb);
    for (i = nb - 2; i >= 0; i--)
    {
        b = mpz_tstbit(k, i);
        printf("%d ", b);
        dadd(r, R1, R0, D, curve);
        if (b)
            swap_points(&R0, &R1);
        copy_point(&R1, *r);
        dbl(&R0, R0, curve);
        if (b)
            swap_points(&R0, &R1);
    }
    printf("\n");
    copy_point(r, R0);

    free_point(&R0);
    free_point(&R1);
    free_point(&D);
    free_affine(&D_affine);
}

void rhs(mpz_t r, const mpz_t x, const curve_t curve)
{
    // X^3 + A*X^2 + X
    mpz_pow_ui(r, x, 2);
    mpz_addmul(r, curve.a, x);
    mpz_add_ui(r, r, 1);
    mpz_mul(r, r, x);
    mpz_mod(r, r, curve.p);
}

char is_on_curve(const point_t p, const curve_t curve)
{
    if (is_infinity(p))
        return 1;

    point_affine_t p_affine;
    init_affine(&p_affine);
    affine(&p_affine, p, curve);

    mpz_t tmp1, tmp2;
    mpz_inits(tmp1, tmp2, NULL);
    rhs(tmp1, p_affine.x, curve);
    mpz_sub_ui(tmp2, curve.p, 1);
    mpz_fdiv_q_2exp(tmp2, tmp2, 1);
    mpz_powm(tmp1, tmp1, tmp2, curve.p);
    char res = mpz_cmp_ui(tmp1, 1) == 0; // Euler's Criterion

    mpz_clears(tmp1, tmp2, NULL);
    free_affine(&p_affine);
    return res;
}

void infinity(point_t *p)
{
    mpz_set_ui(p->x, 0);
    mpz_set_ui(p->z, 1);
}

void affine(point_affine_t *r, const point_t p, const curve_t curve)
{
    if (is_infinity(p))
    {
        mpz_set_ui(r->x, 0);
        return;
    }

    mpz_set(r->x, p.x);

    if (mpz_cmp_ui(p.z, 1) == 0)
        return;

    mpz_t z_inv;
    mpz_init(z_inv);
    mpz_invert(z_inv, p.z, curve.p);
    mpz_mul(r->x, r->x, z_inv);
    mpz_mod(r->x, r->x, curve.p);
    mpz_clear(z_inv);
}