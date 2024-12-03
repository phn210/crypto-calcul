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
    free(curve->name);
    free_affine(&curve->G);
    mpz_clears(curve->p, curve->r, curve->a, curve->b, NULL);
}

void point_to_bytes(unsigned char *buf, const point_t p, const curve_t curve)
{
    mpz_export(buf, NULL, 1, 1, 0, 0, p.x);
    mpz_export(buf + curve.efs, NULL, 1, 1, 0, 0, p.y);
    mpz_export(buf + 2 * curve.efs, NULL, 1, 1, 0, 0, p.z);
}

void point_from_bytes(point_t *r, const unsigned char *buf, const curve_t curve)
{
    mpz_import(r->x, 1, 1, 1, 0, 0, buf);
    mpz_import(r->y, 1, 1, 1, 0, 0, buf + curve.efs);
    mpz_import(r->z, 1, 1, 1, 0, 0, buf + 2 * curve.efs);
}

void generator(point_t *p, const curve_t curve)
{
    mpz_set(p->x, curve.G.x);
    mpz_set(p->y, curve.G.y);
    mpz_set_ui(p->z, 1);
}