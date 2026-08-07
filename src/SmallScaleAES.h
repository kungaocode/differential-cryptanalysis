#pragma once
#include <cstdint>
#include <vector>

typedef uint8_t word8;

const word8 NUM_ROUNDS = 5;
const word8 IRREDUCIBLE_POLY = 0x13;

const word8 SBOX[16] = {
    0x6, 0xB, 0x5, 0x4, 0x2, 0xE, 0x7, 0xA,
    0x9, 0xD, 0xF, 0xC, 0x3, 0x1, 0x0, 0x8
};

extern word8 INV_SBOX[16];

inline word8 gf_mul(word8 a, word8 b) {
    word8 result = 0;
    while (b) {
        if (b & 1) result ^= a;
        a <<= 1;
        if (a & 0x10) a ^= IRREDUCIBLE_POLY;
        a &= 0xF;
        b >>= 1;
    }
    return result;
}

void init_inv_sbox();

// State: 16 nibbles, column-major: index = col*4 + row

void sub_bytes(const word8 in[16], word8 out[16]);
void inv_sub_bytes(const word8 in[16], word8 out[16]);
void shift_rows(const word8 in[16], word8 out[16]);
void inv_shift_rows(const word8 in[16], word8 out[16]);
void mix_column(const word8 in[16], word8 out[16]);
void inv_mix_column(const word8 in[16], word8 out[16]);
void add_round_key(const word8 in[16], const word8 rk[16], word8 out[16]);

void key_expansion(const word8* key, word8 round_keys[][16]);

void encrypt(const word8* pt, const word8* key, word8* ct);
void decrypt(const word8* ct, const word8* key, word8* pt);
void encrypt_noMC_rounds(const word8* pt, const word8* key, int rounds, word8* ct);
