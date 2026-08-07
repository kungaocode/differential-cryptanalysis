// Verify the 3-round SmallScaleAES differential distinguisher of Figure 1.
//
// Trail (4-1-4):
//   Delta P  : (F,0,0,0, 0,A,0,0, 0,0,1,0, 0,0,0,9)   active at 0,5,10,15
//   Delta C* : (B,0,0,0, 0,0,0,4, 0,0,7,0, 0,7,0,0)   active at 0,7,10,13
// Single-trail probability p = (1/4)^9 = 2^{-18}.
// With N = 2^20 pairs, expect M ~ Poisson(lambda_0 = 4).
//
// We run T trials; in each trial we sample N random plaintexts P and check
//     E_3(P) XOR E_3(P XOR Delta P) == Delta C*
// where E_3 is 3-round SmallScaleAES (last round has no MixColumns).
//
// As a sanity check we also run T trials of a random permutation oracle
// (just sample C, C' independently). Here lambda_1 = N / (2^{64}-1) ~ 2^{-44},
// so we should essentially never see a hit.

#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <random>

#include "SmallScaleAES.h"

static const int CIPHER_ROUNDS = 3;
static const uint64_t N = 1ULL << 20;   // 2^20 plaintext pairs per trial
static const double LAMBDA0 = 4.0;      // N * 2^{-18}

static const word8 DELTA_P[16] = {
    0xF, 0x0, 0x0, 0x0,
    0x0, 0xA, 0x0, 0x0,
    0x0, 0x0, 0x1, 0x0,
    0x0, 0x0, 0x0, 0x9,
};

static const word8 DELTA_C_STAR[16] = {
    0xB, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x4,
    0x0, 0x0, 0x7, 0x0,
    0x0, 0x7, 0x0, 0x0,
};

// Fixed key for the SmallScaleAES experiments. Differential probability is
// (heuristically) key-independent, so any key will do.
static const word8 KEY[16] = {
    0x2, 0xB, 0x7, 0xE,
    0x1, 0x5, 0x1, 0x6,
    0x2, 0x8, 0xA, 0xE,
    0xD, 0x2, 0xA, 0x6,
};

static void random_state(std::mt19937_64& rng, word8 state[16]) {
    uint64_t x = rng();
    for (int i = 0; i < 16; i++) {
        state[i] = x & 0xF;
        x >>= 4;
    }
}

static inline bool eq16(const word8 a[16], const word8 b[16]) {
    return std::memcmp(a, b, 16) == 0;
}

static uint64_t one_aes_trial(uint64_t seed) {
    std::mt19937_64 rng(seed);
    word8 P[16], P_xor[16], C[16], C_xor[16], D[16];
    uint64_t hits = 0;

    for (uint64_t i = 0; i < N; i++) {
        random_state(rng, P);
        for (int j = 0; j < 16; j++) P_xor[j] = P[j] ^ DELTA_P[j];

        encrypt_noMC_rounds(P,     KEY, CIPHER_ROUNDS, C);
        encrypt_noMC_rounds(P_xor, KEY, CIPHER_ROUNDS, C_xor);

        for (int j = 0; j < 16; j++) 
            D[j] = C[j] ^ C_xor[j];

        if (eq16(D, DELTA_C_STAR)) hits++;
    }
    return hits;
}

static uint64_t one_random_trial(uint64_t seed) {
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

// Poisson tail: P[X >= k] where X ~ Poisson(lambda).
static double poisson_pmf(int k, double lambda) {
    double logp = -lambda + k * std::log(lambda) - std::lgamma(k + 1.0);
    return std::exp(logp);
}

int main(int argc, char* argv[]) {
    init_inv_sbox();

    int trials = 20;
    if (argc >= 2) trials = std::atoi(argv[1]);

    std::cout << "3-round SmallScaleAES differential distinguisher\n";
    std::cout << "N        = 2^20 = " << N << " pairs per trial\n";
    std::cout << "expected lambda_0 = N * 2^{-18} = " << LAMBDA0 << "\n";
    std::cout << "trials   = " << trials << "\n\n";

    std::cout << "Delta P  : ";
    for (int i = 0; i < 16; i++) std::cout << std::hex << (int)DELTA_P[i];
    std::cout << "\nDelta C* : ";
    for (int i = 0; i < 16; i++) std::cout << std::hex << (int)DELTA_C_STAR[i];
    std::cout << std::dec << "\n\n";

    // Run trials.
    std::vector<uint64_t> aes_counts(trials), rnd_counts(trials);
    uint64_t aes_total = 0, rnd_total = 0;

    std::cout << " trial |  AES hits  | random hits\n";
    std::cout << "-------+-----------+-------------\n";
    for (int t = 0; t < trials; t++) {
        uint64_t aes_seed = 20260514ULL + 1000ULL * t;
        uint64_t rnd_seed = 0xDEADBEEF1234ULL + 1000ULL * t;

        uint64_t a = one_aes_trial(aes_seed);
        uint64_t r = one_random_trial(rnd_seed);

        aes_counts[t] = a;
        rnd_counts[t] = r;
        aes_total += a;
        rnd_total += r;

        std::cout << "  " << std::setw(4) << (t + 1)
                  << "  |   " << std::setw(6) << a
                  << "  |   " << std::setw(6) << r << "\n";
    }

    double aes_mean = double(aes_total) / trials;
    double rnd_mean = double(rnd_total) / trials;

    std::cout << "\nmean AES hits    = " << std::fixed << std::setprecision(3) << aes_mean
              << "   (expected " << LAMBDA0 << " from single-trail bound)\n";
    std::cout << "mean random hits = " << rnd_mean
              << "   (expected ~ N * 2^{-64} = " << double(N) / std::pow(2.0, 64.0) << ")\n";

    // Histogram of AES hit counts vs Poisson(lambda_0).
    int hmax = 0;
    for (int t = 0; t < trials; t++) if ((int)aes_counts[t] > hmax) hmax = (int)aes_counts[t];
    if (hmax < (int)std::ceil(2 * LAMBDA0)) hmax = (int)std::ceil(2 * LAMBDA0);

    std::cout << "\nAES hit-count histogram vs Poisson(" << LAMBDA0 << "):\n";
    std::cout << "  k  | observed | expected\n";
    std::cout << " ----+----------+----------\n";
    for (int k = 0; k <= hmax; k++) {
        int obs = 0;
        for (int t = 0; t < trials; t++) if ((int)aes_counts[t] == k) obs++;
        double exp_count = trials * poisson_pmf(k, LAMBDA0);
        std::cout << "  " << std::setw(2) << k
                  << " |   " << std::setw(4) << obs
                  << "   |  " << std::setw(6) << std::setprecision(2) << exp_count << "\n";
    }

    // Decision rule M >= 1.
    int aes_positive = 0, rnd_positive = 0;
    for (int t = 0; t < trials; t++) {
        if (aes_counts[t] >= 1) aes_positive++;
        if (rnd_counts[t] >= 1) rnd_positive++;
    }
    std::cout << "\nWith threshold eta = 1:\n";
    std::cout << "  empirical TP = " << aes_positive << " / " << trials
              << " = " << std::setprecision(3) << double(aes_positive) / trials
              << "   (Poisson predicts " << (1.0 - std::exp(-LAMBDA0)) << ")\n";
    std::cout << "  empirical FP = " << rnd_positive << " / " << trials
              << " = " << double(rnd_positive) / trials << "\n";

    return 0;
}
