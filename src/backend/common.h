#ifndef COMMON_H
#define COMMON_H

#include <gmp.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifdef WINDOWS_H
#include <ntsecapi.h>
#endif

typedef unsigned char BYTE; // 8-bit byte
typedef unsigned int WORD;  // 32-bit word, change to "long" for 16-bit machines

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