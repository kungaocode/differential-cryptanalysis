/*
 * key_recovery_lib.cpp — Library version of key recovery
 *
 * Extracted from KeyRecovery_Modified_Simple.cpp: core functions without main().
 * Implements modified 2.5+1 round differential key recovery.
 */
#include "key_recovery.h"
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>
#include <algorithm>

const word8 DELTA_P_KR[16] = {0x6,0x3,0x2,0xA,0xC,0x5,0xD,0x9,0x7,0x8,0x4,0xA,0x4,0x6,0x6,0xF};
const word8 DELTA_X3[4] = {0x2, 0x1, 0x1, 0x3};
const int ACTIVE_POS[4] = {0, 13, 10, 7};
static const word8 FIXED_KEY[16] = {0x2,0xB,0x7,0xE,0x1,0x5,0x1,0x6,0x2,0x8,0xA,0xE,0xD,0x2,0xA,0x6};

void encrypt_modified_4rounds(const word8 pt[16], const word8 key[16], word8 ct[16]) {
    word8 rk[NUM_ROUNDS+1][16];
    key_expansion(key, rk);
    word8 state[16], tmp[16];
    add_round_key(pt, rk[0], state);
    /* Round 1: first 8 S-boxes = identity */
    for (int i = 0; i < 16; i++) {
        if (i < 8) tmp[i] = state[i];
        else tmp[i] = SBOX[state[i]];
    }
    shift_rows(tmp, state); mix_column(state, tmp);
    add_round_key(tmp, rk[1], state);
    /* Round 2: normal */
    sub_bytes(state, tmp); shift_rows(tmp, state);
    mix_column(state, tmp); add_round_key(tmp, rk[2], state);
    /* Round 3: normal */
    sub_bytes(state, tmp); shift_rows(tmp, state);
    mix_column(state, tmp); add_round_key(tmp, rk[3], state);
    /* Round 4: final (no MC) */
    sub_bytes(state, tmp); shift_rows(tmp, state);
    add_round_key(state, rk[4], ct);
}

bool partial_decrypt_check(const word8 C[16], const word8 C_prime[16],
                           const word8 k_guess[4]) {
    for (int i = 0; i < 4; i++) {
        int pos = ACTIVE_POS[i];
        word8 x3 = INV_SBOX[(C[pos] ^ k_guess[i]) & 0xF];
        word8 x3_prime = INV_SBOX[(C_prime[pos] ^ k_guess[i]) & 0xF];
        if ((x3 ^ x3_prime) != DELTA_X3[i]) return false;
    }
    return true;
}

uint32_t run_key_recovery(uint64_t N, uint64_t counter[65536],
                          uint32_t *correct_k) {
    for (int i = 0; i < 65536; i++) counter[i] = 0;
    std::mt19937_64 rng(20260514ULL);

    for (uint64_t i = 0; i < N; i++) {
        word8 P[16], P_prime[16], C[16], C_prime[16];
        uint64_t x = rng();
        for (int j = 0; j < 16; j++) { P[j] = x & 0xF; x >>= 4; }
        for (int j = 0; j < 16; j++) P_prime[j] = P[j] ^ DELTA_P_KR[j];
        encrypt_modified_4rounds(P, FIXED_KEY, C);
        encrypt_modified_4rounds(P_prime, FIXED_KEY, C_prime);

        for (uint32_t k = 0; k < 65536; k++) {
            word8 k_guess[4] = {(word8)(k&0xF),(word8)((k>>4)&0xF),
                                (word8)((k>>8)&0xF),(word8)((k>>12)&0xF)};
            if (partial_decrypt_check(C, C_prime, k_guess)) counter[k]++;
        }
    }

    /* Determine correct subkey */
    word8 rk[NUM_ROUNDS+1][16];
    key_expansion(FIXED_KEY, rk);
    word8 sk[4] = {rk[4][0], rk[4][13], rk[4][10], rk[4][7]};
    *correct_k = sk[0] | (sk[1]<<4) | (sk[2]<<8) | (sk[3]<<12);

    /* Find rank of correct key */
    uint64_t correct_count = counter[*correct_k];
    uint32_t rank = 1;
    for (uint32_t k = 0; k < 65536; k++)
        if (counter[k] > correct_count) rank++;
    return rank;
}
