#include "ec.h"

void test_weierstrass_curve(weierstrass_curve_t curve_id)
{
    int check = 1, eq = 0, on_curve = 0, inf = 0;

    curve_t curve;
    init_curve(&curve, WEIERSTRASS, curve_id);

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
    generator(&p, curve);

    // Test point addition (p + p)
    add(&q, p, p, curve);
    neg(&r, p, curve);
    add(&r, q, r, curve);
    eq = equals(p, r, curve);
    check &= eq;

    // Test point doubling (2p)
    dbl(&r, p, curve);
    eq = equals(q, r, curve);
    check &= eq;
    on_curve = is_on_curve(p, curve);
    check &= on_curve;
    on_curve = is_on_curve(q, curve);
    check &= on_curve;
    on_curve = is_on_curve(r, curve);
    check &= on_curve;

    // Test point multiplication (3p)
    mpz_t k;
    mpz_init_set_ui(k, 3);
    mul(&r, p, k, curve);
    add(&q, p, q, curve);
    eq = equals(q, r, curve);
    check &= eq;

    // Test point multiplication (np)
    mul(&r, p, curve.r, curve);
    inf = is_infinity(r, curve);
    check &= inf;

    // Test point serialization
    unsigned char buf[2 * curve.efs];
    point_to_bytes(buf, p, curve);
    point_from_bytes(&r, buf, curve);
    eq = equals(p, r, curve);
    check &= eq;

    if (check && eq && on_curve && inf)
    {
        printf("[%d] Curve: %s\t test passed.\n", curve_id, curve.name);
    }
    else
    {
        fprintf(stderr, "[%d] Curve: %s\t test FAILED.\n", curve_id, curve.name);
        gmp_printf("p.x: %Zd \np.y: %Zd \np.z: %Zd\n", p.x, p.y, p.z);
        gmp_printf("r.x: %Zd \nr.y: %Zd \nr.z: %Zd\n", r.x, r.y, r.z);
    }

    // Free points and curve
    mpz_clear(k);
    free_point(&p);
    free_point(&q);
    free_point(&r);
    free_curve(&curve);
}

void test_edwards_curve(edwards_curve_t curve_id)
{
    int check = 1, eq = 0, on_curve = 0, inf = 0;

    curve_t curve;
    init_curve(&curve, EDWARDS, curve_id);

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
    generator(&p, curve);

    // Test point addition (p + p)
    add(&q, p, p, curve);
    neg(&r, p, curve);
    add(&r, q, r, curve);
    eq = equals(p, r, curve);
    check &= eq;

    // Test point doubling (2p)
    dbl(&r, p, curve);
    eq = equals(q, r, curve);
    check &= eq;
    on_curve = is_on_curve(p, curve);
    check &= on_curve;
    on_curve = is_on_curve(q, curve);
    check &= on_curve;
    on_curve = is_on_curve(r, curve);
    check &= on_curve;

    // Test point multiplication (3p)
    mpz_t k;
    mpz_init_set_ui(k, 3);
    mul(&r, p, k, curve);
    add(&q, p, q, curve);
    eq = equals(q, r, curve);
    check &= eq;

    // Test point multiplication (np)
    mul(&r, p, curve.r, curve);
    inf = is_infinity(r, curve);
    check &= inf;

    // Test point serialization
    unsigned char buf[2 * curve.efs];
    point_to_bytes(buf, p, curve);
    point_from_bytes(&r, buf, curve);
    eq = equals(p, r, curve);
    check &= eq;

    if (check && eq && on_curve && inf)
    {
        printf("[%d] Curve: %s\t test passed.\n", curve_id, curve.name);
    }
    else
    {
        fprintf(stderr, "[%d] Curve: %s\t test FAILED.\n", curve_id, curve.name);
        gmp_printf("p.x: %Zd \np.y: %Zd \np.z: %Zd\n", p.x, p.y, p.z);
        gmp_printf("r.x: %Zd \nr.y: %Zd \nr.z: %Zd\n", r.x, r.y, r.z);
    }

    // Free points and curve
    mpz_clear(k);
    free_point(&p);
    free_point(&q);
    free_point(&r);
    free_curve(&curve);
}

void test_montgomery_curve(montgomery_curve_t curve_id)
{
    int check = 1, eq = 0, on_curve = 0, inf = 0;

    curve_t curve;
    init_curve(&curve, MONTGOMERY, curve_id);

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
    generator(&p, curve);

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
    inf = is_infinity(r, curve);
    check &= inf;

    // Test point serialization
    unsigned char buf[curve.efs];
    point_to_bytes(buf, p, curve);
    point_from_bytes(&r, buf, curve);
    eq = equals(p, r, curve);
    check &= eq;

    if (check && eq && on_curve && inf)
    {
        printf("[%d] Curve: %s\t test passed.\n", curve_id, curve.name);
    }
    else
    {
        fprintf(stderr, "[%d] Curve: %s\t test FAILED.\n", curve_id, curve.name);
        gmp_printf("p.x: %Zd \np.y: %Zd \np.z: %Zd\n", p.x, p.y, p.z);
        gmp_printf("r.x: %Zd \nr.y: %Zd \nr.z: %Zd\n", r.x, r.y, r.z);
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
    printf("\n===================== WEIERSTRASS CURVES TEST =====================\n\n");

    test_weierstrass_curve(P224);
    test_weierstrass_curve(P256);
    test_weierstrass_curve(P384);
    test_weierstrass_curve(P521);
    test_weierstrass_curve(P256K1);
    test_weierstrass_curve(W25519);
    test_weierstrass_curve(W448);

    printf("\n===================== MONTGOMERY CURVES TEST =====================\n\n");
    test_montgomery_curve(C25519);
    test_montgomery_curve(C448);

    printf("\n===================== EDWARDS CURVES TEST =====================\n\n");
    test_edwards_curve(ED25519);
    test_edwards_curve(ED448);
    test_edwards_curve(E448);

    return 0;
}