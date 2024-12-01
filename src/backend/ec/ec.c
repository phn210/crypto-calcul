#include "ec.h"

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

void free_curve(curve_t *curve)
{
    free_affine(&curve->G);
    mpz_clears(curve->p, curve->r, curve->a, curve->b, NULL);
}

void to_bytes(unsigned char *buf, const point_t p);
void from_bytes(point_t *r, const unsigned char *buf);