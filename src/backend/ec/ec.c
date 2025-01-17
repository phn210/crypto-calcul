#include "ec.h"
#include "conversion.h"

void init_point(point_t *p)
{
    mpz_inits(p->x, p->y, p->z, NULL);
}

void free_point(point_t *p)
{
    mpz_clears(p->x, p->y, p->z, NULL);
}

void copy_point(point_t *r, const point_t p)
{
    mpz_set(r->x, p.x);
    mpz_set(r->y, p.y);
    mpz_set(r->z, p.z);
}

void swap_points(point_t *p, point_t *q)
{
    point_t tmp;
    init_point(&tmp);
    copy_point(&tmp, *p);
    copy_point(p, *q);
    copy_point(q, tmp);
    free_point(&tmp);
}

void init_affine(point_affine_t *p)
{
    mpz_inits(p->x, p->y, NULL);
}

void free_affine(point_affine_t *p)
{
    mpz_clears(p->x, p->y, NULL);
}

void copy_affine(point_affine_t *r, const point_affine_t p)
{
    mpz_set(r->x, p.x);
    mpz_set(r->y, p.y);
}

void init_curve(curve_t *curve, ec_t curve_type, unsigned char curve_id)
{
    init_affine(&curve->G);
    mpz_inits(curve->p, curve->r, curve->a, curve->b, NULL);
    curve->type = curve_type;
    curve->id = curve_id;

    switch (curve_type)
    {
    case WEIERSTRASS:
    {
        switch (curve_id)
        {
        case P224:
        {
            size_t name_len = strlen(P224_NAME);
            curve->name = (char *)malloc(name_len + 1);
            memcpy(curve->name, P224_NAME, name_len);
            curve->name[name_len] = '\0';
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
            size_t name_len = strlen(P384_NAME);
            curve->name = (char *)malloc(name_len + 1);
            memcpy(curve->name, P384_NAME, name_len);
            curve->name[name_len] = '\0';
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
        case P256:
        {
            size_t name_len = strlen(P256_NAME);
            curve->name = (char *)malloc(name_len + 1);
            memcpy(curve->name, P256_NAME, name_len);
            curve->name[name_len] = '\0';
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
        case P521:
        {
            size_t name_len = strlen(P521_NAME);
            curve->name = (char *)malloc(name_len + 1);
            memcpy(curve->name, P521_NAME, name_len);
            curve->name[name_len] = '\0';
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
            size_t name_len = strlen(P256K1_NAME);
            curve->name = (char *)malloc(name_len + 1);
            memcpy(curve->name, P256K1_NAME, name_len);
            curve->name[name_len] = '\0';
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
            size_t name_len = strlen(W25519_NAME);
            curve->name = (char *)malloc(name_len + 1);
            memcpy(curve->name, W25519_NAME, name_len);
            curve->name[name_len] = '\0';
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
            size_t name_len = strlen(W448_NAME);
            curve->name = (char *)malloc(name_len + 1);
            memcpy(curve->name, W448_NAME, name_len);
            curve->name[name_len] = '\0';
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
        default:
        {
            fprintf(stderr, "Invalid curve ID\n");
            exit(EXIT_FAILURE);
        }
        }
        break;
    }
    case MONTGOMERY:
    {
        switch (curve_id)
        {
        case C25519:
        {
            size_t name_len = strlen(C25519_NAME);
            curve->name = (char *)malloc(name_len + 1);
            memcpy(curve->name, C25519_NAME, name_len);
            curve->name[name_len] = '\0';
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
        case C448:
        {
            size_t name_len = strlen(C448_NAME);
            curve->name = (char *)malloc(name_len + 1);
            memcpy(curve->name, C448_NAME, name_len);
            curve->name[name_len] = '\0';
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
        default:
        {
            fprintf(stderr, "Invalid curve ID\n");
            exit(EXIT_FAILURE);
        }
        }
        break;
    }
    case EDWARDS:
    {
        switch (curve_id)
        {
        case ED25519:
        {
            size_t name_len = strlen(ED25519_NAME);
            curve->name = (char *)malloc(name_len + 1);
            memcpy(curve->name, ED25519_NAME, name_len);
            curve->name[name_len] = '\0';
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
        case ED448:
        {
            size_t name_len = strlen(ED448_NAME);
            curve->name = (char *)malloc(name_len + 1);
            memcpy(curve->name, ED448_NAME, name_len);
            curve->name[name_len] = '\0';
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
            size_t name_len = strlen(E448_NAME);
            curve->name = (char *)malloc(name_len + 1);
            memcpy(curve->name, E448_NAME, name_len);
            curve->name[name_len] = '\0';
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
        default:
        {
            fprintf(stderr, "Invalid curve ID\n");
            exit(EXIT_FAILURE);
        }
        }
        break;
    }
    default:
    {
        fprintf(stderr, "Invalid curve type\n");
        exit(EXIT_FAILURE);
    }
    }
    if (curve->name == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
}

void free_curve(curve_t *curve)
{
    free(curve->name);
    free_affine(&curve->G);
    mpz_clears(curve->p, curve->r, curve->a, curve->b, NULL);
}

void rhs(mpz_t r, const mpz_t x, const curve_t curve)
{
    if (curve.type == WEIERSTRASS)
    {
        // X^3 + A*X + B
        mpz_powm_ui(r, x, 3, curve.p);
        mpz_addmul(r, x, curve.a);
        mpz_add(r, r, curve.b);
    }
    else if (curve.type == MONTGOMERY)
    {
        // X^3 + A*X^2 + X
        mpz_pow_ui(r, x, 2);
        mpz_addmul(r, x, curve.a);
        mpz_add_ui(r, r, 1);
        mpz_mul(r, r, x);
    }
    else if (curve.type == EDWARDS)
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
        mpz_clears(t0, t1, NULL);
    }
    mpz_mod(r, r, curve.p);
}

void generator(point_t *p, const curve_t curve)
{
    mpz_set(p->x, curve.G.x);
    mpz_set(p->y, curve.G.y);
    mpz_set_ui(p->z, 1);
}

void infinity(point_t *p, const curve_t curve)
{
    mpz_set_ui(p->x, 0);
    if (curve.type != MONTGOMERY)
        mpz_set_ui(p->y, 1);
    if (curve.type != EDWARDS)
        mpz_set_ui(p->z, 0);
    else
        mpz_set_ui(p->z, 1);
}

char is_infinity(const point_t p, const curve_t curve)
{
    if (curve.type == WEIERSTRASS)
        return mpz_sgn(p.x) == 0 && mpz_sgn(p.z) == 0;
    if (curve.type == MONTGOMERY)
        return mpz_sgn(p.z) == 0;
    if (curve.type == EDWARDS)
        return mpz_sgn(p.x) == 0 && mpz_cmp(p.y, p.z) == 0;
    return 0;
}

char is_on_curve(const point_t p, const curve_t curve)
{
    if (is_infinity(p, curve))
        return 1;

    char res;

    point_affine_t p_affine;
    init_affine(&p_affine);
    to_affine(&p_affine, p, curve);

    mpz_t tmp;
    mpz_init(tmp);
    rhs(tmp, p_affine.x, curve);
    if (curve.type != MONTGOMERY)
    {
        mpz_neg(tmp, tmp);
        mpz_addmul(tmp, p_affine.y, p_affine.y);
        mpz_mod(tmp, tmp, curve.p);
        res = mpz_cmp_ui(tmp, 0) == 0;
    }
    else
        res = mpz_legendre(tmp, curve.p) == 1; // Euler's Criterion
    mpz_clear(tmp);
    free_affine(&p_affine);
    return res;
}

char equals(const point_t p, const point_t q, const curve_t curve)
{
    char res = 1;

    mpz_t tmp;
    mpz_init_set_ui(tmp, 0);

    mpz_addmul(tmp, p.x, q.z);
    mpz_submul(tmp, q.x, p.z);
    mpz_mod(tmp, tmp, curve.p);
    res &= mpz_cmp_ui(tmp, 0) == 0;
    if (curve.type == MONTGOMERY)
    {
        mpz_clear(tmp);
        return res;
    }

    mpz_addmul(tmp, p.y, q.z);
    mpz_submul(tmp, q.y, p.z);
    mpz_mod(tmp, tmp, curve.p);

    res &= mpz_cmp_ui(tmp, 0) == 0;
    mpz_clear(tmp);
    return res;
}

void neg(point_t *r, const point_t p, const curve_t curve)
{
    copy_point(r, p);
    if (curve.type == WEIERSTRASS)
    {
        mpz_neg(r->y, r->y);
        mpz_mod(r->y, r->y, curve.p);
    }
    else if (curve.type == EDWARDS)
    {
        mpz_neg(r->x, r->x);
        mpz_mod(r->x, r->x, curve.p);
    }
    else
    {
        fprintf(stderr, "Negation not supported for Montgomery curves\n");
        exit(EXIT_FAILURE);
    }
}

void add(point_t *r, const point_t p, const point_t q, const curve_t curve)
{
    if (is_infinity(p, curve))
    {
        copy_point(r, q);
        return;
    }

    if (is_infinity(q, curve))
    {
        copy_point(r, p);
        return;
    }

    switch (curve.type)
    {
    case WEIERSTRASS:
    {
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

        mpz_clears(b3, t0, t1, t2, t3, t4, t5, X3, Y3, Z3, NULL);
        break;
    }
    case EDWARDS:
    {
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
        break;
    }
    case MONTGOMERY:
    {
        fprintf(stderr, "Addition not supported for Montgomery curves\n");
        exit(EXIT_FAILURE);
        break;
    }
    }
}

void dadd(point_t *r, const point_t p, const point_t q, const point_t w, const curve_t curve)
{
    if (is_infinity(p, curve))
    {
        copy_point(r, q);
        return;
    }

    if (is_infinity(q, curve))
    {
        copy_point(r, p);
        return;
    }

    if (curve.type != MONTGOMERY)
    {
        fprintf(stderr, "Double addition not supported only for Montgomery curves\n");
        exit(EXIT_FAILURE);
    }

    // XZ coordinates for Montgomery curves
    // https://www.hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#diffadd-dadd-1987-m-3

    mpz_t A, B, C, D, E, F, X5, Z5;
    mpz_inits(A, B, C, D, E, F, X5, Z5, NULL);

    mpz_add(A, p.x, p.z);
    mpz_sub(B, p.x, p.z);
    mpz_add(C, q.x, q.z);
    mpz_sub(D, q.x, q.z);
    mpz_mul(E, A, D);
    mpz_mul(F, B, C);
    mpz_add(A, E, F);
    mpz_sub(B, E, F);
    mpz_powm_ui(A, A, 2, curve.p);
    mpz_powm_ui(B, B, 2, curve.p);
    mpz_mul(X5, w.z, A);
    mpz_mul(Z5, w.x, B);

    mpz_mod(X5, X5, curve.p);
    mpz_mod(Z5, Z5, curve.p);

    mpz_set(r->x, X5);
    mpz_set(r->z, Z5);

    mpz_clears(A, B, C, D, E, F, X5, Z5, NULL);
}

void dbl(point_t *r, const point_t p, const curve_t curve)
{
    if (is_infinity(p, curve))
    {
        copy_point(r, p);
        return;
    }

    switch (curve.type)
    {
    case WEIERSTRASS:
    {
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
        break;
    }
    case EDWARDS:
    {
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
        break;
    }
    case MONTGOMERY:
    {
        // XZ coordinates for Montgomery curves
        // https://www.hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#doubling-dbl-1987-m-3
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
        break;
    }
    }
}

void mul(point_t *r, const point_t p, const mpz_t k, const curve_t curve)
{
    if (is_infinity(p, curve) || mpz_sgn(k) == 0)
    {
        infinity(r, curve);
        return;
    }

    if (mpz_cmp_ui(k, 1) == 0)
    {
        copy_point(r, p);
        return;
    }

    if (mpz_cmp_ui(k, 2) == 0)
    {
        dbl(r, p, curve);
        return;
    }

    if (curve.type != MONTGOMERY)
    {
        point_t q;
        init_point(&q);
        infinity(&q, curve);

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
    else
    {
        int nb, i, b;
        point_t R0, R1, D;
        point_affine_t D_affine;

        init_point(&R0);
        init_point(&R1);
        init_point(&D);
        init_affine(&D_affine);

        copy_point(&R0, p);
        dbl(&R1, p, curve);

        to_affine(&D_affine, p, curve);
        mpz_set(D.x, D_affine.x);
        mpz_set_ui(D.z, 1);

        nb = mpz_sizeinbase(k, 2);
        for (i = nb - 2; i >= 0; i--)
        {
            b = mpz_tstbit(k, i);
            dadd(r, R1, R0, D, curve);
            if (b)
                swap_points(&R0, &R1);
            copy_point(&R1, *r);
            dbl(&R0, R0, curve);
            if (b)
                swap_points(&R0, &R1);
        }
        copy_point(r, R0);

        free_point(&R0);
        free_point(&R1);
        free_point(&D);
        free_affine(&D_affine);
    }
}

void to_affine(point_affine_t *r, const point_t p, const curve_t curve)
{
    if (is_infinity(p, curve))
    {
        mpz_set_ui(r->x, 0);
        return;
    }

    mpz_set(r->x, p.x);
    if (curve.type != MONTGOMERY)
        mpz_set(r->y, p.y);
    if (mpz_cmp_ui(p.z, 1) == 0)
        return;
    mpz_t z_inv;
    mpz_init(z_inv);
    mpz_invert(z_inv, p.z, curve.p);
    mpz_mul(r->x, r->x, z_inv);
    mpz_mod(r->x, r->x, curve.p);
    if (curve.type != MONTGOMERY)
    {
        mpz_mul(r->y, r->y, z_inv);
        mpz_mod(r->y, r->y, curve.p);
    }
    mpz_clear(z_inv);
}

void from_affine(point_t *r, const point_affine_t p, const curve_t curve)
{
    mpz_set(r->x, p.x);
    if (curve.type != MONTGOMERY)
        mpz_set(r->y, p.y);
    mpz_set_ui(r->z, 1);
}

void point_to_bytes(unsigned char *buf, const point_t p, const curve_t curve)
{
    unsigned char temp[curve.efs];
    size_t count = 0;

    point_affine_t p_affine;
    init_affine(&p_affine);
    to_affine(&p_affine, p, curve);

    // Export x-coordinate
    memset(buf, 0, curve.efs);
    memset(temp, 0, curve.efs);
    mpz_export(temp, &count, 1, 1, 0, 0, p_affine.x);
    memcpy(buf + (curve.efs - count), temp, count);
    if (count > curve.efs)
    {
        fprintf(stderr, "Error: x-coordinate too large for curve.efs\n");
        free_affine(&p_affine);
        exit(EXIT_FAILURE);
    }

    if (curve.type != MONTGOMERY)
    {
        // Export y-coordinate
        memset(buf + curve.efs, 0, curve.efs);
        memset(temp, 0, curve.efs);
        mpz_export(temp, &count, 1, 1, 0, 0, p_affine.y);
        memcpy(buf + curve.efs + (curve.efs - count), temp, count);
        if (count > curve.efs)
        {
            fprintf(stderr, "Error: y-coordinate too large for curve.efs\n");
            free_affine(&p_affine);
            exit(EXIT_FAILURE);
        }
    }

    free_affine(&p_affine);
}

void point_from_bytes(point_t *r, const unsigned char *buf, const curve_t curve)
{
    unsigned char tmp_buf[curve.efs];

    // Import x-coordinate
    memset(tmp_buf, 0, curve.efs);
    memcpy(tmp_buf, buf, curve.efs);
    mpz_import(r->x, curve.efs, 1, 1, 0, 0, tmp_buf);

    if (curve.type != MONTGOMERY)
    {
        // Import y-coordinate
        memset(tmp_buf, 0, curve.efs);
        memcpy(tmp_buf, buf + curve.efs, curve.efs);
        mpz_import(r->y, curve.efs, 1, 1, 0, 0, tmp_buf);
    }

    // Set z-coordinate to 1 (affine form)
    mpz_set_ui(r->z, 1);
}
