#include <iostream>
#include <cstring>
#include <vector>
#include "SmallScaleAES.h"

word8 INV_SBOX[16];
word8 RCON[] = {0x1, 0x2, 0x4, 0x8, 0x3, 0x6, 0xC, 0xB, 0x5};

// s(state, row, col) accessor
#define S(st, r, c) (st)[(c)*4+(r)]

void init_inv_sbox() {
    for (int i = 0; i < 16; i++) INV_SBOX[SBOX[i]] = i;
}

void sub_bytes(const word8 in[16], word8 out[16]) {
    for (int i = 0; i < 16; i++) out[i] = SBOX[in[i] & 0xF];
}

void inv_sub_bytes(const word8 in[16], word8 out[16]) {
    for (int i = 0; i < 16; i++) out[i] = INV_SBOX[in[i] & 0xF];
}

void shift_rows(const word8 in[16], word8 out[16]) {
    memcpy(out, in, 16);
    word8 tmp;
    // row 1: left shift 1
    tmp=S(out,1,0); S(out,1,0)=S(out,1,1); S(out,1,1)=S(out,1,2); S(out,1,2)=S(out,1,3); S(out,1,3)=tmp;
    // row 2: left shift 2
    tmp=S(out,2,0); S(out,2,0)=S(out,2,2); S(out,2,2)=tmp;
    tmp=S(out,2,1); S(out,2,1)=S(out,2,3); S(out,2,3)=tmp;
    // row 3: left shift 3 = right shift 1
    tmp=S(out,3,3); S(out,3,3)=S(out,3,2); S(out,3,2)=S(out,3,1); S(out,3,1)=S(out,3,0); S(out,3,0)=tmp;
}

void inv_shift_rows(const word8 in[16], word8 out[16]) {
    memcpy(out, in, 16);
    word8 tmp;
    // row 1: right shift 1
    tmp=S(out,1,3); S(out,1,3)=S(out,1,2); S(out,1,2)=S(out,1,1); S(out,1,1)=S(out,1,0); S(out,1,0)=tmp;
    // row 2: right shift 2 = same as left shift 2
    tmp=S(out,2,0); S(out,2,0)=S(out,2,2); S(out,2,2)=tmp;
    tmp=S(out,2,1); S(out,2,1)=S(out,2,3); S(out,2,3)=tmp;
    // row 3: right shift 3 = left shift 1
    tmp=S(out,3,0); S(out,3,0)=S(out,3,1); S(out,3,1)=S(out,3,2); S(out,3,2)=S(out,3,3); S(out,3,3)=tmp;
}

void mix_column(const word8 in[16], word8 out[16]) {
    for (int c = 0; c < 4; c++) {
        word8 s0=S(in,0,c), s1=S(in,1,c), s2=S(in,2,c), s3=S(in,3,c);
        S(out,0,c) = gf_mul(s0,0x2)^gf_mul(s1,0x3)^s2^s3;
        S(out,1,c) = s0^gf_mul(s1,0x2)^gf_mul(s2,0x3)^s3;
        S(out,2,c) = s0^s1^gf_mul(s2,0x2)^gf_mul(s3,0x3);
        S(out,3,c) = gf_mul(s0,0x3)^s1^s2^gf_mul(s3,0x2);
    }
}

void inv_mix_column(const word8 in[16], word8 out[16]) {
    for (int c = 0; c < 4; c++) {
        word8 s0=S(in,0,c), s1=S(in,1,c), s2=S(in,2,c), s3=S(in,3,c);
        S(out,0,c) = gf_mul(s0,0xE)^gf_mul(s1,0xB)^gf_mul(s2,0xD)^gf_mul(s3,0x9);
        S(out,1,c) = gf_mul(s0,0x9)^gf_mul(s1,0xE)^gf_mul(s2,0xB)^gf_mul(s3,0xD);
        S(out,2,c) = gf_mul(s0,0xD)^gf_mul(s1,0x9)^gf_mul(s2,0xE)^gf_mul(s3,0xB);
        S(out,3,c) = gf_mul(s0,0xB)^gf_mul(s1,0xD)^gf_mul(s2,0x9)^gf_mul(s3,0xE);
    }
}

void add_round_key(const word8 in[16], const word8 rk[16], word8 out[16]) {
    for (int i = 0; i < 16; i++) out[i] = in[i] ^ rk[i];
}

// round_keys[r][16]: r from 0 to NUM_ROUNDS
void key_expansion(const word8 key[16], word8 round_keys[][16]) {
    // w[i][4]: word i, w[i][j] = row j
    word8 w[4*(NUM_ROUNDS+1)][4];
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            w[i][j] = key[i*4+j];

    for (int r = 1; r <= NUM_ROUNDS; r++) {
        int base = (r-1)*4 + 3;
        word8 tmp[4] = {SBOX[w[base][1]], SBOX[w[base][2]], SBOX[w[base][3]], SBOX[w[base][0]]};
        tmp[0] ^= RCON[r-1];
        int nb = r*4;
        for (int j = 0; j < 4; j++) w[nb][j]   = tmp[j]       ^ w[nb-4][j];
        for (int j = 0; j < 4; j++) w[nb+1][j] = w[nb][j]     ^ w[nb-3][j];
        for (int j = 0; j < 4; j++) w[nb+2][j] = w[nb+1][j]   ^ w[nb-2][j];
        for (int j = 0; j < 4; j++) w[nb+3][j] = w[nb+2][j]   ^ w[nb-1][j];
    }

    for (int r = 0; r <= NUM_ROUNDS; r++)
        for (int c = 0; c < 4; c++)
            for (int row = 0; row < 4; row++)
                S(round_keys[r], row, c) = w[r*4+c][row];
}

void encrypt(const word8 pt[16], const word8 key[16], word8 ct[16]) {
    word8 rk[NUM_ROUNDS+1][16];
    key_expansion(key, rk);
    word8 state[16], tmp[16];
    add_round_key(pt, rk[0], state);
    for (int r = 1; r < NUM_ROUNDS; r++) {
        sub_bytes(state, tmp); shift_rows(tmp, state);
        mix_column(state, tmp); add_round_key(tmp, rk[r], state);
    }
    sub_bytes(state, tmp); shift_rows(tmp, state);
    add_round_key(state, rk[NUM_ROUNDS], ct);
}

void decrypt(const word8 ct[16], const word8 key[16], word8 pt[16]) {
    word8 rk[NUM_ROUNDS+1][16];
    key_expansion(key, rk);
    word8 state[16], tmp[16];
    add_round_key(ct, rk[NUM_ROUNDS], state);
    inv_shift_rows(state, tmp); inv_sub_bytes(tmp, state);
    for (int r = NUM_ROUNDS-1; r > 0; r--) {
        add_round_key(state, rk[r], tmp);
        inv_mix_column(tmp, state); inv_shift_rows(state, tmp); inv_sub_bytes(tmp, state);
    }
    add_round_key(state, rk[0], pt);
}

void encrypt_noMC_rounds(const word8 pt[16], const word8 key[16], int rounds, word8 ct[16]) {
    word8 rk[NUM_ROUNDS+1][16];
    key_expansion(key, rk);
    word8 state[16], tmp[16];
    add_round_key(pt, rk[0], state);
    for (int r = 1; r < rounds; r++) {
        sub_bytes(state, tmp); shift_rows(tmp, state);
        mix_column(state, tmp); add_round_key(tmp, rk[r], state);
    }
    sub_bytes(state, tmp); shift_rows(tmp, state);
    add_round_key(state, rk[rounds], ct);
}