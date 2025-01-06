#ifndef ENUM_H
#define ENUM_H

typedef enum sec_level
{
    L0 = 112,
    L1 = 128,
    L2 = 192,
    L3 = 256
} sec_level_t;

typedef enum hash_func
{
    MD5,
    SHA1,
    SHA2,
    SHA3,
    POSEIDON
} hash_func_t;

#endif