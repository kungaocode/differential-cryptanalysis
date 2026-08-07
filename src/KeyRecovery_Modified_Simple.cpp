// Simplified Modified 2.5+1 round differential key recovery for SmallScaleAES
//
// Modification: The first 8 S-boxes in round 1 are replaced with identity.
// This saves 2^{-16} in probability (8 S-boxes × 2^{-2} each).
//
// Modified trail probability: (1/4)^13 = 2^{-26}
//
// This is a BASIC implementation without filtering, suitable for students.

#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <random>
#include <vector>
#include <algorithm>

#include "SmallScaleAES.h"

// Modified encryption with first 8 S-boxes as identity in round 1
void encrypt_modified_4rounds(const word8 pt[16], const word8 key[16], word8 ct[16]) {
    word8 rk[NUM_ROUNDS+1][16];
    key_expansion(key, rk);

    word8 state[16], tmp[16];

    // Initial round key addition
    add_round_key(pt, rk[0], state);

    // Round 1: First 8 S-boxes are IDENTITY (positions 0-7)
    for (int i = 0; i < 16; i++) {
        if (i < 8) {
            tmp[i] = state[i];  // Identity for first 8 S-boxes
        } else {
            tmp[i] = SBOX[state[i]];  // Normal S-box for last 8
        }
    }
    shift_rows(tmp, state);
    mix_column(state, tmp);
    add_round_key(tmp, rk[1], state);

    // Round 2: Normal
    sub_bytes(state, tmp);
    shift_rows(tmp, state);
    mix_column(state, tmp);
    add_round_key(tmp, rk[2], state);

    // Round 3: Normal (with MixColumns for 4-round version)
    sub_bytes(state, tmp);
    shift_rows(tmp, state);
    mix_column(state, tmp);
    add_round_key(tmp, rk[3], state);

    // Round 4: Final round (no MixColumns)
    sub_bytes(state, tmp);
    shift_rows(tmp, state);
    add_round_key(state, rk[4], ct);
}

// Input difference for the modified 2.5-round trail
static const word8 DELTA_P_KR[16] = {
    0x6, 0x3, 0x2, 0xA,
    0xC, 0x5, 0xD, 0x9,
    0x7, 0x8, 0x4, 0xA,
    0x4, 0x6, 0x6, 0xF
};

// Expected difference after round 3 MixColumns: MC(1,0,0,0) = (2,1,1,3)
static const word8 DELTA_X3[4] = {0x2, 0x1, 0x1, 0x3};

// Active positions in ciphertext after ShiftRows: {0, 13, 10, 7}
static const int ACTIVE_POS[4] = {0, 13, 10, 7};

// Fixed key for experiments
static const word8 KEY[16] = {
    0x2, 0xB, 0x7, 0xE,
    0x1, 0x5, 0x1, 0x6,
    0x2, 0x8, 0xA, 0xE,
    0xD, 0x2, 0xA, 0x6
};

static void random_state(std::mt19937_64& rng, word8 state[16]) {
    uint64_t x = rng();
    for (int i = 0; i < 16; i++) {
        state[i] = x & 0xF;
        x >>= 4;
    }
}

// Partial decryption: given ciphertext and key guess, check if difference matches
static bool partial_decrypt_check(const word8 C[16], const word8 C_prime[16],
                                   const word8 k_guess[4]) {
    // For each active position, partially decrypt
    for (int i = 0; i < 4; i++) {
        int pos = ACTIVE_POS[i];
        word8 x3 = INV_SBOX[(C[pos] ^ k_guess[i]) & 0xF];
        word8 x3_prime = INV_SBOX[(C_prime[pos] ^ k_guess[i]) & 0xF];
        word8 delta_x3_computed = x3 ^ x3_prime;

        if (delta_x3_computed != DELTA_X3[i]) {
            return false;
        }
    }
    return true;
}

int main(int argc, char* argv[]) {
    init_inv_sbox();

    // Parameters
    uint64_t N = 1ULL << 26;  // Default: 2^26 pairs
    if (argc >= 2) {
        N = 1ULL << std::atoi(argv[1]);
    }

    int threshold = 1;  // eta = 1
    if (argc >= 3) {
        threshold = std::atoi(argv[2]);
    }

    double p_modified = std::pow(0.25, 13);  // 2^{-26}
    double lambda = N * p_modified;

    std::cout << "Modified 2.5+1 Round Differential Key Recovery (Basic Implementation)\n";
    std::cout << "======================================================================\n\n";
    std::cout << "Modification: First 8 S-boxes in round 1 are identity\n";
    std::cout << "  - Original probability: 2^{-42}\n";
    std::cout << "  - Modified probability: 2^{-26} (saved 2^{-16})\n\n";
    std::cout << "Parameters:\n";
    std::cout << "  N (pairs)  = 2^" << std::log2(N) << " = " << N << "\n";
    std::cout << "  Threshold  = " << threshold << "\n";
    std::cout << "  Expected lambda = N * p = " << lambda << "\n";
    std::cout << "  P[correct key survives] ≈ " << (1.0 - std::exp(-lambda)) << "\n\n";

    // Generate plaintext pairs and do key recovery
    std::cout << "Generating plaintext pairs and performing key recovery...\n";
    std::mt19937_64 rng(20260514ULL);

    std::vector<uint64_t> counter(65536, 0);

    for (uint64_t i = 0; i < N; i++) {
        word8 P[16], P_prime[16], C[16], C_prime[16];

        random_state(rng, P);
        for (int j = 0; j < 16; j++) {
            P_prime[j] = P[j] ^ DELTA_P_KR[j];
        }

        encrypt_modified_4rounds(P, KEY, C);
        encrypt_modified_4rounds(P_prime, KEY, C_prime);

        // Try all subkey candidates for this pair
        for (uint32_t k = 0; k < 65536; k++) {
            word8 k_guess[4] = {
                (word8)((k >> 0) & 0xF),   // K_4[0]
                (word8)((k >> 4) & 0xF),   // K_4[13]
                (word8)((k >> 8) & 0xF),   // K_4[10]
                (word8)((k >> 12) & 0xF)   // K_4[7]
            };

            if (partial_decrypt_check(C, C_prime, k_guess)) {
                counter[k]++;
            }
        }

        if ((i + 1) % (N / 10) == 0) {
            std::cout << "  Progress: " << (i + 1) << " / " << N << "\n";
        }
    }

    std::cout << "\nKey recovery complete!\n\n";

    // Find candidates with count >= threshold
    std::vector<std::pair<uint32_t, uint64_t>> candidates;
    for (uint32_t k = 0; k < 65536; k++) {
        if (counter[k] >= (uint64_t)threshold) {
            candidates.push_back({k, counter[k]});
        }
    }

    // Sort by count (descending)
    std::sort(candidates.begin(), candidates.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    std::cout << "======================================================================\n";
    std::cout << "Key Recovery Results\n";
    std::cout << "======================================================================\n\n";
    std::cout << "Candidates with count >= " << threshold << ": " << candidates.size() << "\n\n";

    // Get correct subkey from actual round keys
    word8 rk[NUM_ROUNDS+1][16];
    key_expansion(KEY, rk);
    word8 correct_subkey[4] = {
        rk[4][0],   // K_4[0]
        rk[4][13],  // K_4[13]
        rk[4][10],  // K_4[10]
        rk[4][7]    // K_4[7]
    };
    uint32_t correct_k = (correct_subkey[0]) | (correct_subkey[1] << 4) |
                         (correct_subkey[2] << 8) | (correct_subkey[3] << 12);

    std::cout << "Correct subkey: (K_4[0], K_4[13], K_4[10], K_4[7]) = "
              << "(" << std::hex << (int)correct_subkey[0] << ", "
              << (int)correct_subkey[1] << ", "
              << (int)correct_subkey[2] << ", "
              << (int)correct_subkey[3] << ")" << std::dec << "\n";
    std::cout << "Correct subkey count: " << counter[correct_k] << "\n\n";

    bool found_correct = false;
    for (size_t i = 0; i < candidates.size(); i++) {
        if (candidates[i].first == correct_k) {
            found_correct = true;
            std::cout << "✓ Correct subkey found at rank " << (i + 1) << "!\n\n";
            break;
        }
    }
    if (!found_correct && candidates.size() > 0) {
        std::cout << "✗ Correct subkey not in candidate list.\n\n";
    }

    std::cout << "Top 20 candidates:\n";
    std::cout << "Rank | Subkey (K_4[0,13,10,7]) | Count  | Correct?\n";
    std::cout << "-----+-------------------------+--------+---------\n";

    for (size_t i = 0; i < std::min(size_t(20), candidates.size()); i++) {
        uint32_t k = candidates[i].first;
        uint64_t count = candidates[i].second;
        word8 k0 = (k >> 0) & 0xF;
        word8 k13 = (k >> 4) & 0xF;
        word8 k10 = (k >> 8) & 0xF;
        word8 k7 = (k >> 12) & 0xF;

        bool is_correct = (k == correct_k);

        std::cout << std::setw(4) << (i + 1) << " | "
                  << "(" << std::hex << (int)k0 << ", " << (int)k13 << ", "
                  << (int)k10 << ", " << (int)k7 << ")" << std::dec
                  << std::setw(12) << " | " << std::setw(6) << count
                  << " | " << (is_correct ? "YES ✓" : "") << "\n";
    }

    return 0;
}
