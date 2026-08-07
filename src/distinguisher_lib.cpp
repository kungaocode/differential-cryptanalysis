/*
 * distinguisher_lib.cpp — Library version of differential distinguisher
 *
 * Extracted from DifferentialDistinguisher.cpp: core functions without main().
 * Implements 3-round SmallScaleAES differential distinguisher verification.
 */
#include "distinguisher.h"
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <random>

const word8 DELTA_P[16] = {0xF,0x0,0x0,0x0, 0x0,0xA,0x0,0x0, 0x0,0x0,0x1,0x0, 0x0,0x0,0x0,0x9};
const word8 DELTA_C_STAR[16] = {0xB,0x0,0x0,0x0, 0x0,0x0,0x0,0x4, 0x0,0x0,0x7,0x0, 0x0,0x7,0x0,0x0};
const int CIPHER_ROUNDS = 3;
const uint64_t N = 1ULL << 20;
const double LAMBDA0 = 4.0;
const word8 KEY[16] = {0x2,0xB,0x7,0xE,0x1,0x5,0x1,0x6,0x2,0x8,0xA,0xE,0xD,0x2,0xA,0x6};

static void random_state(std::mt19937_64& rng, word8 state[16]) {
    uint64_t x = rng();
    for (int i = 0; i < 16; i++) { state[i] = x & 0xF; x >>= 4; }
}
static inline bool eq16(const word8 a[16], const word8 b[16]) {
    return std::memcmp(a, b, 16) == 0;
}

uint64_t distinguisher_trial(uint64_t seed) {
    std::mt19937_64 rng(seed);
    word8 P[16], P_xor[16], C[16], C_xor[16], D[16];
    uint64_t hits = 0;
    for (uint64_t i = 0; i < N; i++) {
        random_state(rng, P);
        for (int j = 0; j < 16; j++) P_xor[j] = P[j] ^ DELTA_P[j];
        encrypt_noMC_rounds(P, KEY, CIPHER_ROUNDS, C);
        encrypt_noMC_rounds(P_xor, KEY, CIPHER_ROUNDS, C_xor);
        for (int j = 0; j < 16; j++) D[j] = C[j] ^ C_xor[j];
        if (eq16(D, DELTA_C_STAR)) hits++;
    }
    return hits;
}

uint64_t random_trial(uint64_t seed) {
    std::mt19937_64 rng(seed);
    word8 C[16], C_xor[16], D[16];
    uint64_t hits = 0;
    for (uint64_t i = 0; i < N; i++) {
        random_state(rng, C);
        random_state(rng, C_xor);
        for (int j = 0; j < 16; j++) D[j] = C[j] ^ C_xor[j];
        if (eq16(D, DELTA_C_STAR)) hits++;
    }
    return hits;
}

double poisson_pmf(int k, double lambda) {
    double logp = -lambda + k * std::log(lambda) - std::lgamma(k + 1.0);
    return std::exp(logp);
}
