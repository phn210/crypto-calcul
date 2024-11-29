#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#define ROTLEFT(a, b) ((a << b) | (a >> (32 - b)))
#define HASH_SIZE 20

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[5];
} SHA1_CTX;

typedef struct HashNode {
    unsigned char hash[HASH_SIZE];
    struct HashNode *next;
} HashNode;

void sha1_transform(SHA1_CTX *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, i, j, t, m[80];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for (; i < 80; ++i)
        m[i] = ROTLEFT(m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16], 1);
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];

    for (i = 0; i < 80; ++i) {
        if (i < 20) {
            t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + m[i] + 0x6ED9EBA1;
        } else if (i < 60) {
            t = ROTLEFT(a, 5) + ((b & c) | (b & d) | (c & d)) + e + m[i] + 0x8F1BBCDC;
        } else {
            t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + m[i] + 0xCA62C1D6;
        }
        e = d;
        d = c;
        c = ROTLEFT(b, 30);
        b = a;
        a = t;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

void sha1_init(SHA1_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
}

void sha1_update(SHA1_CTX *ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha1_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void sha1_final(SHA1_CTX *ctx, uint8_t hash[]) {
    uint32_t i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0x00;
        sha1_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha1_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
    }
}

void write_sha1_hash_to_file(unsigned char hash[HASH_SIZE], FILE *output_file) {
    for (int i = 0; i < HASH_SIZE; i++) {
        fprintf(output_file, "%02x", hash[i]);
    }
    fprintf(output_file, "\n");
}

int compare_hashes(unsigned char hash1[HASH_SIZE], unsigned char hash2[HASH_SIZE]) {
    return memcmp(hash1, hash2, HASH_SIZE) == 0;
}

int check_collision(HashNode *head, unsigned char new_hash[HASH_SIZE]) {
    HashNode *current = head;
    while (current != NULL) {
        if (compare_hashes(current->hash, new_hash)) {
            return 1; // Collision found
        }
        current = current->next;
    }
    return 0; // No collision
}

void add_hash(HashNode **head, unsigned char new_hash[HASH_SIZE]) {
    HashNode *new_node = (HashNode *)malloc(sizeof(HashNode));
    memcpy(new_node->hash, new_hash, HASH_SIZE);
    new_node->next = *head;
    *head = new_node;
}

void free_hash_list(HashNode *head) {
    HashNode *current = head;
    while (current != NULL) {
        HashNode *next = current->next;
        free(current);
        current = next;
    }
}

int main() {
    const char *input_filename = "dico.txt";
    const char *output_filename = "HacheSHA1File.txt";

    FILE *input_file = fopen(input_filename, "r");
    if (!input_file) {
        perror("Unable to open input file");
        return EXIT_FAILURE;
    }

    FILE *output_file = fopen(output_filename, "w");
    if (!output_file) {
        perror("Unable to open output file");
        fclose(input_file);
        return EXIT_FAILURE;
    }

    char *line = NULL;
    size_t len = 0;
    size_t read;
    unsigned char hash[HASH_SIZE];
    HashNode *hash_list = NULL;
    int collision_found = 0;

    while ((read = getline(&line, &len, input_file)) != -1) {
        // Remove newline character if present
        if (line[read - 1] == '\n') {
            line[read - 1] = '\0';
        }
        SHA1_CTX ctx;
        sha1_init(&ctx);
        sha1_update(&ctx, (uint8_t*)line, strlen(line));
        sha1_final(&ctx, hash);
        if (check_collision(hash_list, hash)) {
            collision_found = 1;
            printf("Collision found for the word: %s\n", line);
        } else {
            add_hash(&hash_list, hash);
            write_sha1_hash_to_file(hash, output_file);
        }
    }

    free(line);
    fclose(input_file);
    fclose(output_file);
    free_hash_list(hash_list);

    if (!collision_found) {
        printf("No collisions found.\n");
    }

    printf("SHA1 hashes of lines in file %s have been written to %s\n", input_filename, output_filename);

    return EXIT_SUCCESS;
}