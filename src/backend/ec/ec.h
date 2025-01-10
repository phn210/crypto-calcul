#ifndef WEIERSTRASS_H
#define WEIERSTRASS_H

#include "common.h"
#include "ec_param.h"

typedef enum ec
{
    WEIERSTRASS,
    MONTGOMERY,
    EDWARDS
} ec_t;

typedef enum weierstrass_curve
{
    P224,
    P256,
    P384,
    P521,
    P256K1,
    W25519,
    W448
} weierstrass_curve_t;

typedef enum montgomery_curve
{
    C25519,
    C448
} montgomery_curve_t;

typedef enum edwards_curve
{
    ED25519,
    ED448,
    E448
} edwards_curve_t;

typedef struct point
{
    mpz_t x;
    mpz_t y;
    mpz_t z;
} point_t;

typedef struct point_affine
{
    mpz_t x;
    mpz_t y;
} point_affine_t;

typedef struct curve
{
    unsigned char type;
    unsigned char id;
    int cof; // or h: cofactor
    size_t efs;
    mpz_t p; // or q: field size
    mpz_t r; // or n: group order
    mpz_t a;
    mpz_t b;
    point_affine_t G;
    size_t md_len;
    void *(*hash)(const void *, size_t, void *, int);
    char *name;
} curve_t;

void init_point(point_t *p);
void free_point(point_t *p);
void copy_point(point_t *r, const point_t p);
void swap_points(point_t *p, point_t *q);

void init_affine(point_affine_t *p);
void free_affine(point_affine_t *p);
void copy_affine(point_affine_t *r, const point_affine_t p);

void init_curve(curve_t *curve, ec_t curve_type, unsigned char curve_id);
void free_curve(curve_t *curve);

void rhs(mpz_t r, const mpz_t x, const curve_t curve);
void generator(point_t *p, const curve_t curve);
void infinity(point_t *p, const curve_t curve);
char is_infinity(const point_t p, const curve_t curve);
char is_on_curve(const point_t p, const curve_t curve);
char equals(const point_t p, const point_t q, const curve_t curve);
void neg(point_t *r, const point_t p, const curve_t curve);
void add(point_t *r, const point_t p, const point_t q, const curve_t curve);
void dadd(point_t *r, const point_t p, const point_t q, const point_t w, const curve_t curve);
void dbl(point_t *r, const point_t p, const curve_t curve);
void mul(point_t *r, const point_t p, const mpz_t k, const curve_t curve);
void to_affine(point_affine_t *r, const point_t p, const curve_t curve);
void from_affine(point_t *r, const point_affine_t p, const curve_t curve);
void point_to_bytes(unsigned char *buf, const point_t p, const curve_t curve);
void point_from_bytes(point_t *r, const unsigned char *buf, const curve_t curve);

#endif