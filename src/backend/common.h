#ifndef COMMON_H
#define COMMON_H

#include <gmp.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define UNUSED(x) (void)(x)

#ifdef WINDOWS_H

#include <windows.h>
#define RtlGenRandom SystemFunction036
BOOLEAN NTAPI RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);

#endif

typedef unsigned char BYTE; // 8-bit byte

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