#include "ec.h"

void test_curve(MONTGOMERY_CURVE curve_id)
{
    int check = 1, eq = 0, on_curve = 0, inf = 0;

    curve_t curve;
    init_curve(&curve, curve_id);

    // gmp_printf("Curve's p: %Zd\n", curve.p);
    // gmp_printf("Curve's r: %Zd\n", curve.r);
    // gmp_printf("Curve's a: %Zd\n", curve.a);
    // gmp_printf("Curve's b: %Zd\n", curve.b);
    // gmp_printf("Curve's G.x: %Zd\n", curve.G.x);
    // gmp_printf("Curve's G.y: %Zd\n", curve.G.y);

    // Initialize points
    point_t p, q, r;
    init_point(&p);
    init_point(&q);
    init_point(&r);

    point_affine_t q_affine, r_affine;
    init_affine(&q_affine);
    init_affine(&r_affine);

    // Set point p to the generator point G
    mpz_set(p.x, curve.G.x);
    mpz_set_ui(p.z, 1);

    // Test point doubling (2p)
    dbl(&q, p, curve);

    // Test point multiplication (3p)
    mpz_t k;
    mpz_init_set_ui(k, 3);
    mul(&r, p, k, curve);

    // Test point differential addition (2p + p)
    dadd(&q, q, p, p, curve);
    eq = equals(q, r, curve);
    check &= eq;
    on_curve = is_on_curve(p, curve);
    check &= on_curve;
    on_curve = is_on_curve(q, curve);
    check &= on_curve;
    on_curve = is_on_curve(r, curve);
    check &= on_curve;

    // Test point multiplication (3p)
    mpz_set_ui(k, 6);
    mul(&r, p, k, curve);
    dadd(&q, r, q, q, curve);
    mpz_set_ui(k, 9);
    mul(&r, p, k, curve);
    eq = equals(q, r, curve);
    check &= eq;
    on_curve = is_on_curve(p, curve);
    check &= on_curve;
    on_curve = is_on_curve(q, curve);
    check &= on_curve;
    on_curve = is_on_curve(r, curve);
    check &= on_curve;

    // Test point multiplication (np)
    mul(&r, p, curve.r, curve);
    inf = is_infinity(r);
    check &= inf;

    if (check && eq && on_curve && inf)
    {
        printf("[%d] Curve: %s\t test passed.\n", curve_id, curve.name);
    }
    else
    {
        fprintf(stderr, "[%d] Curve: ..., test FAILED.\n", curve_id);
    }

    // Free points and curve
    mpz_clear(k);
    free_point(&p);
    free_point(&q);
    free_point(&r);
    free_curve(&curve);
}

int main()
{
    printf("\n===================== MONTGOMERY CURVES TEST =====================\n\n");

    test_curve(C25519);
    test_curve(C448);

    return 0;
}