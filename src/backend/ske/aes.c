#include "aes.h"

unsigned char xtime(unsigned char x) 
{
    return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

void aes_rot_word(unsigned char *word) 
{
    unsigned char temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

void aes_sub_word(unsigned char *word) 
{
    for (int i = 0; i < 4; i++) {
        word[i] = SBOX[word[i] / 16][word[i] % 16];
    }
}

void aes_rcon(unsigned char *word, unsigned char round) 
{
    unsigned char rcon = 1;
    for(int i = 0; i < round - 1; i++) {
        rcon = xtime(rcon);
    }

    word[0] = rcon;
    word[1] = word[2] = word[3] = 0;
}

void aes_xor_words(unsigned char *word1, unsigned char *word2) 
{
    for (int i = 0; i < 4; i++) {
        word1[i] ^= word2[i];
    }
}

void aes_key_expansion(unsigned char *key, unsigned char *w, AES_KEY_SIZE key_size, AES_ROUNDS rounds)
{
    unsigned char temp[4];
    unsigned char rcon[4];

    for (int i = 0; i < key_size; i++) {
        w[i] = key[i];
    }

    for (int i = key_size; i < 4 * 4 * (rounds + 1); i += 4) {
        for (int j = 0; j < 4; j++) {
            temp[j] = w[i - 4 + j];
        }

        if (i % key_size == 0) {
            aes_rot_word(temp);
            aes_sub_word(temp);
            aes_rcon(rcon, i / key_size);
            aes_xor_words(temp, rcon);
        } else if (key_size > 24 && i % key_size == 16) {
            aes_sub_word(temp);
        }

        for (int j = 0; j < 4; j++) {
            w[i + j] = w[i - key_size + j] ^ temp[j];
        }
    }
}

void aes_sub_bytes(unsigned char state[4][4]) 
{
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            unsigned char tmp = state[i][j];
            state[i][j] = SBOX[tmp / 16][tmp % 16];
        }
    }
}

void aes_shift_rows(unsigned char state[4][4]) 
{
    unsigned char temp;

    // Shift row 1
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // Shift row 2
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Shift row 3
    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

void aes_mix_columns(unsigned char state[4][4]) 
{
    unsigned char temp_state[4][4];

    for (int i = 0; i < 4; ++i) {
        memset(temp_state[i], 0, 4);
    }

    for (int i = 0; i < 4; ++i) {
        for (int k = 0; k < 4; ++k) {
            for (int j = 0; j < 4; ++j) {
                if (MIX_COLUMN_MATRIX[i][k] == 1)
                    temp_state[i][j] ^= state[k][j];
                else
                    temp_state[i][j] ^= GF_MUL_TABLE[MIX_COLUMN_MATRIX[i][k]][state[k][j]];
            }
        }
    }

    for (int i = 0; i < 4; ++i) {
        memcpy(state[i], temp_state[i], 4);
    }
}

void aes_add_round_key(unsigned char state[4][4], unsigned char *w) 
{
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[j][i] ^= w[i * 4 + j];
        }
    }
}

void aes_inv_sub_bytes(unsigned char state[4][4]) 
{
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            unsigned char tmp = state[i][j];
            state[i][j] = INVERSE_SBOX[tmp / 16][tmp % 16];
        }
    }
}

void aes_inv_shift_rows(unsigned char state[4][4]) 
{
    unsigned char temp;

    // Shift row 1
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    // Shift row 2
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Shift row 3
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

void aes_inv_mix_columns(unsigned char state[4][4]) 
{
    unsigned char temp_state[4][4];

    for (int i = 0; i < 4; ++i) {
        memset(temp_state[i], 0, 4);
    }

    for (int i = 0; i < 4; ++i) {
        for (int k = 0; k < 4; ++k) {
            for (int j = 0; j < 4; ++j) {
                if (INVERSE_MIX_COLUMN_MATRIX[i][k] == 1)
                    temp_state[i][j] ^= state[k][j];
                else
                    temp_state[i][j] ^= GF_MUL_TABLE[INVERSE_MIX_COLUMN_MATRIX[i][k]][state[k][j]];
            }
        }
    }

    for (int i = 0; i < 4; ++i) {
        memcpy(state[i], temp_state[i], 4);
    }
}

void aes_block_encrypt(unsigned char *block, unsigned char *w, AES_ROUNDS rounds)
{
    unsigned char state[4][4];

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[j][i] = block[i * 4 + j];
        }
    }

    aes_add_round_key(state, w);

    for (int round = 1; round < rounds; round++) {
        aes_sub_bytes(state);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, w + round * 16);

        // printf("\nRound %d:\n", round);
        // for (int i = 0; i < 4; i++) {
        //     for (int j = 0; j < 4; j++) {
        //         printf("%02x ", state[j][i]);
        //     }
        //     printf("\n");
        // }
    }

    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_add_round_key(state, w + rounds * 16);

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            block[i * 4 + j] = state[j][i];
        }
    }
}

void aes_block_decrypt(unsigned char *block, unsigned char *w, AES_ROUNDS rounds)
{
    unsigned char state[4][4];

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[j][i] = block[i * 4 + j];
        }
    }

    aes_add_round_key(state, w + rounds * 16);

    for (int round = rounds - 1; round > 0; round--) {
        aes_inv_shift_rows(state);
        aes_inv_sub_bytes(state);
        aes_add_round_key(state, w + round * 16);
        aes_inv_mix_columns(state);
    }

    aes_inv_shift_rows(state);
    aes_inv_sub_bytes(state);
    aes_add_round_key(state, w);

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            block[i * 4 + j] = state[j][i];
        }
    }
}

AES_ROUNDS get_rounds(AES_KEY_SIZE key_size) 
{
    switch (key_size) {
        case AES_KEY_SIZE_128:
            return AES_ROUNDS_128;
        case AES_KEY_SIZE_192:
            return AES_ROUNDS_192;
        case AES_KEY_SIZE_256:
            return AES_ROUNDS_256;
    }
}

void aes_encrypt_ecb(unsigned char *input, unsigned char *output, unsigned char *key, size_t len, AES_KEY_SIZE key_size) 
{
    AES_ROUNDS rounds = get_rounds(key_size);

    unsigned char *w = malloc(AES_BLOCK_SIZE * (rounds + 1));
    aes_key_expansion(key, w, key_size, rounds);

    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        aes_block_encrypt(input + i, w, rounds);
        memcpy(output + i, input + i, AES_BLOCK_SIZE);
    }
}

void aes_decrypt_ecb(unsigned char *input, unsigned char *output, unsigned char *key, size_t len, AES_KEY_SIZE key_size) 
{
    AES_ROUNDS rounds = get_rounds(key_size);

    unsigned char *w = malloc(AES_BLOCK_SIZE * (rounds + 1));
    aes_key_expansion(key, w, key_size, rounds);

    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        aes_block_decrypt(input + i, w, rounds);
        memcpy(output + i, input + i, AES_BLOCK_SIZE);
    }
}

void aes_encrypt_cbc(unsigned char *input, unsigned char *output, unsigned char *iv, unsigned char *key, size_t len, AES_KEY_SIZE key_size) 
{
    AES_ROUNDS rounds = get_rounds(key_size);

    unsigned char *w = malloc(AES_BLOCK_SIZE * (rounds + 1));
    aes_key_expansion(key, w, key_size, rounds);

    unsigned char last_block[AES_BLOCK_SIZE];
    memcpy(last_block, iv, AES_BLOCK_SIZE);

    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            input[i + j] ^= last_block[j];
        }

        aes_block_encrypt(input + i, w, rounds);

        memcpy(output + i, input + i, AES_BLOCK_SIZE);
        memcpy(last_block, output + i, AES_BLOCK_SIZE);
    }
}

void aes_decrypt_cbc(unsigned char *input, unsigned char *output, unsigned char *iv, unsigned char *key, size_t len, AES_KEY_SIZE key_size) 
{
    AES_ROUNDS rounds = get_rounds(key_size);

    unsigned char *w = malloc(AES_BLOCK_SIZE * (rounds + 1));
    aes_key_expansion(key, w, key_size, rounds);

    unsigned char last_block[AES_BLOCK_SIZE];
    memcpy(last_block, iv, AES_BLOCK_SIZE);

    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        aes_block_decrypt(input + i, w, rounds);

        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            output[i + j] = input[i + j] ^ last_block[j];
        }

        memcpy(last_block, input + i, AES_BLOCK_SIZE);
    }
}