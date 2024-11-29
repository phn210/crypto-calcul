#include <stdio.h>
#include <string.h>
#include "sha_1.h"

void hash_to_string(const unsigned char *hash, char *output)
{
    for (int i = 0; i < HASH_SIZE; i++)
    {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[HASH_SIZE * 2] = '\0';
}

void testvec1()
{
    char const string[] = "abc";
    char const expect[] = "a9993e364706816aba3e25717850c26c9cd0d89d";
    unsigned char result[HASH_SIZE];
    char hexresult[HASH_SIZE * 2 + 1];

    sha1(string, strlen(string), result, HASH_SIZE);
    hash_to_string(result, hexresult);

    if (strncmp(hexresult, expect, HASH_SIZE * 2) == 0)
    {
        printf("Test Vector 1: SUCCESS\n");
    }
    else
    {
        printf("Test Vector 1: FAILURE\n");
        printf("Expected: %s\n", expect);
        printf("Got:      %s\n", hexresult);
    }
}

void testvec2()
{
    char const string[] = "";
    char const expect[] = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    unsigned char result[HASH_SIZE];
    char hexresult[HASH_SIZE * 2 + 1];

    sha1(string, strlen(string), result, HASH_SIZE);
    hash_to_string(result, hexresult);

    if (strncmp(hexresult, expect, HASH_SIZE * 2) == 0)
    {
        printf("Test Vector 2: SUCCESS\n");
    }
    else
    {
        printf("Test Vector 2: FAILURE\n");
        printf("Expected: %s\n", expect);
        printf("Got:      %s\n", hexresult);
    }
}

void testvec3()
{
    char const string[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    char const expect[] = "84983e441c3bd26ebaae4aa1f95129e5e54670f1";
    unsigned char result[HASH_SIZE];
    char hexresult[HASH_SIZE * 2 + 1];

    sha1(string, strlen(string), result, HASH_SIZE);
    hash_to_string(result, hexresult);

    if (strncmp(hexresult, expect, HASH_SIZE * 2) == 0)
    {
        printf("Test Vector 3: SUCCESS\n");
    }
    else
    {
        printf("Test Vector 3: FAILURE\n");
        printf("Expected: %s\n", expect);
        printf("Got:      %s\n", hexresult);
    }
}

void testvec4()
{
    char const string1[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghij";
    char const string2[] = "klmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    char const expect[] = "a49b2446a02c645bf419f995b67091253a04a259";
    unsigned char result[HASH_SIZE];
    char hexresult[HASH_SIZE * 2 + 1];
    sha1_ctx_t ctx;

    sha1_init(&ctx);
    sha1_update(&ctx, string1, strlen(string1));
    sha1_update(&ctx, string2, strlen(string2));
    sha1_final(&ctx, result);
    hash_to_string(result, hexresult);

    if (strncmp(hexresult, expect, HASH_SIZE * 2) == 0)
    {
        printf("Test Vector 4: SUCCESS\n");
    }
    else
    {
        printf("Test Vector 4: FAILURE\n");
        printf("Expected: %s\n", expect);
        printf("Got:      %s\n", hexresult);
    }
}

void testvec5()
{
    char string[1000001];
    char const expect[] = "34aa973cd4c4daa4f61eeb2bdbad27316534016f";
    unsigned char result[HASH_SIZE];
    char hexresult[HASH_SIZE * 2 + 1];

    for (int i = 0; i < 1000000; i++)
    {
        string[i] = 'a';
    }
    string[1000000] = '\0';

    sha1(string, strlen(string), result, HASH_SIZE);
    hash_to_string(result, hexresult);

    if (strncmp(hexresult, expect, HASH_SIZE * 2) == 0)
    {
        printf("Test Vector 5: SUCCESS\n");
    }
    else
    {
        printf("Test Vector 5: FAILURE\n");
        printf("Expected: %s\n", expect);
        printf("Got:      %s\n", hexresult);
    }
}

void testvec6()
{
    char const string[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno";
    char const expect[] = "7789f0c9ef7bfc40d93311143dfbe69e2017f592";
    unsigned char result[HASH_SIZE];
    char hexresult[HASH_SIZE * 2 + 1];
    sha1_ctx_t ctx;

    sha1_init(&ctx);
    for (int i = 0; i < 16777216; i++)
    {
        sha1_update(&ctx, string, strlen(string));
    }
    sha1_final(&ctx, result);
    hash_to_string(result, hexresult);

    if (strncmp(hexresult, expect, HASH_SIZE * 2) == 0)
    {
        printf("Test Vector 6: SUCCESS\n");
    }
    else
    {
        printf("Test Vector 6: FAILURE\n");
        printf("Expected: %s\n", expect);
        printf("Got:      %s\n", hexresult);
    }
}

int main()
{
    printf("\n===================== SHA-1 TEST =====================\n\n");

    testvec1();
    testvec2();
    testvec3();
    testvec4();
    testvec5();
    testvec6();

    return 0;
}