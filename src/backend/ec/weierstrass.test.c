#include "weierstrass.h"

void test_curve(WEIERSTRASS_CURVE curve_id)
{
    printf("Testing curve with ID: %d\n", curve_id);

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
    mpz_set(p.y, curve.G.y);
    mpz_set_ui(p.z, 1);

    // Test point addition (p + p)
    add(&q, p, p, curve);
    printf("Addition (q = p + p)\n");
    gmp_printf("x: %Zd\ny: %Zd\nz: %Zd\n", q.x, q.y, q.z);

    neg(&r, p, curve);
    add(&r, q, r, curve);
    printf("Addition (r = -p + q)\n");
    printf("Equals (p == r): %s\n", equals(p, r, curve) == 0 ? "False" : "True");

    // Test point doubling (2p)
    dbl(&r, p, curve);
    printf("Doubling (r = 2p)\n");
    gmp_printf("x: %Zd\ny: %Zd\nz: %Zd\n", r.x, r.y, r.z);
    printf("Equals (q == r): %s\n", equals(q, r, curve) == 0 ? "False" : "True");

    printf("Is on curve (p): %s\n", is_on_curve(p, curve) == 0 ? "False" : "True");
    printf("Is on curve (q): %s\n", is_on_curve(q, curve) == 0 ? "False" : "True");
    printf("Is on curve (r): %s\n", is_on_curve(r, curve) == 0 ? "False" : "True");

    // infinity(&r);
    // int infinity = is_infinity(r);
    // printf("Is infinity (r): %s\n", infinity == 0 ? "False" : "True");

    // Test point multiplication (3p)
    mpz_t k;
    mpz_init_set_ui(k, 3);
    mul(&r, p, k, curve);
    printf("Multiplication (r = 3p)\n");
    // gmp_printf("x: %Zd\ny: %Zd\nz: %Zd\n", r.x, r.y, r.z);
    add(&q, p, q, curve);
    printf("Addition (q = p + q)\n");
    // gmp_printf("x: %Zd\ny: %Zd\nz: %Zd\n", q.x, q.y, q.z);
    printf("Equals (q == r): %s\n", equals(q, r, curve) == 0 ? "False" : "True");

    // Test point multiplication (np)
    mul(&r, p, curve.r, curve);
    printf("Multiplication (r = n*p)\n");
    printf("Is infinity (r): %s\n", is_infinity(r) == 0 ? "False" : "True");

    // Free points and curve
    mpz_clear(k);
    free_point(&p);
    free_point(&q);
    free_point(&r);
    free_curve(&curve);
}

int main()
{
    printf("\n===================== WEIERSTRASS CURVES TEST =====================\n\n");

    test_curve(P224);
    printf("\n\n");
    test_curve(P256);
    printf("\n\n");
    test_curve(P384);
    printf("\n\n");
    test_curve(P521);
    printf("\n\n");
    test_curve(P256K1);

    return 0;
}