#include "mgf.h"
#include "md5.h"
#include "sha1.h"
#include "sha2.h"
#include "sha3.h"

void mgf1(unsigned char *mask, size_t mask_len, const unsigned char *seed, size_t seed_len, hash_func_t hash_function, sec_level_t sec_level)
{
    unsigned char *buf = malloc(seed_len + 4);
    if (buf == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    memcpy(buf, seed, seed_len);
    size_t hash_len;
    void *(*hash)(const void *, size_t, void *, size_t);

    switch (hash_function)
    {
    case MD5:
        hash_len = MD5_DIGEST_SIZE;
        hash = &md5;
        break;
    case SHA1:
        hash_len = SHA1_DIGEST_SIZE;
        hash = &sha1;
        break;
    case SHA2:
        switch (sec_level)
        {
        case L0:
            hash_len = SHA224_DIGEST_SIZE;
            break;
        case L1:
            hash_len = SHA256_DIGEST_SIZE;
            break;
        case L2:
            hash_len = SHA384_DIGEST_SIZE;
            break;
        case L3:
            hash_len = SHA512_DIGEST_SIZE;
            break;
        default:
            fprintf(stderr, "Invalid security level\n");
            free(buf);
            exit(EXIT_FAILURE);
        }
        hash = &sha2;
        break;
    case SHA3:
        switch (sec_level)
        {
        case L0:
            hash_len = SHA3_224_DIGEST_SIZE;
            break;
        case L1:
            hash_len = SHA3_256_DIGEST_SIZE;
            break;
        case L2:
            hash_len = SHA3_384_DIGEST_SIZE;
            break;
        case L3:
            hash_len = SHA3_512_DIGEST_SIZE;
            break;
        default:
            fprintf(stderr, "Invalid security level\n");
            free(buf);
            exit(EXIT_FAILURE);
        }
        hash = &sha3;
        break;
    default:
        fprintf(stderr, "Invalid hash function\n");
        free(buf);
        exit(EXIT_FAILURE);
    }

    if (mask_len > (hash_len << 32))
    {
        fprintf(stderr, "Mask too long\n");
        free(buf);
        exit(EXIT_FAILURE);
    }

    int num_blocks = (mask_len + hash_len - 1) / hash_len;

    unsigned char *md = malloc(hash_len);
    if (md == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        free(buf);
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < num_blocks; i++)
    {
        buf[seed_len] = (i >> 24) & 0xFF;
        buf[seed_len + 1] = (i >> 16) & 0xFF;
        buf[seed_len + 2] = (i >> 8) & 0xFF;
        buf[seed_len + 3] = i & 0xFF;
        hash(buf, seed_len + 4, md, hash_len);
        size_t len = (i + 1) * hash_len > mask_len ? mask_len - i * hash_len : hash_len;
        memcpy(mask + i * hash_len, md, len);
    }

    free(buf);
    free(md);
}