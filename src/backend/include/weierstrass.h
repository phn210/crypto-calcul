#ifndef WEIERSTRASS_H
#define WEIERSTRASS_H

#include <common.h>
#include <ec.h>

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
    int cof;
    size_t efs;
    mpz_t p;
    mpz_t r;
    mpz_t a;
    mpz_t b;
    point_affine_t G;
    int md_len;
    void *(*hash)(const void *, size_t, void *, int);
} curve_t;

void init_point(point_t *p);
void free_point(point_t *p);
void copy_point(point_t *r, const point_t p);
void to_bytes(unsigned char *buf, const point_t p);
void from_bytes(point_t *r, const unsigned char *buf);

void init_affine(point_affine_t *p);
void free_affine(point_affine_t *p);
void copy_affine(point_affine_t *r, const point_affine_t p);

void init_curve(curve_t *curve, WEIERSTRASS_CURVE curve_id);
void free_curve(curve_t *curve);

char is_infinity(const point_t p);
char equals(const point_t p, const point_t q, const curve_t curve);
void neg(point_t *r, const point_t p, const curve_t curve);
void add(point_t *r, const point_t p, const point_t q, const curve_t curve);
void dbl(point_t *r, const point_t p, const curve_t curve);
void mul(point_t *r, const point_t p, const mpz_t k, const curve_t curve);
void rhs(mpz_t r, const mpz_t x, const curve_t curve);
char is_on_curve(const point_t p, const curve_t curve);
void infinity(point_t *p);
void affine(point_affine_t *r, const point_t p, const curve_t curve);

#endif