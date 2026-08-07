#include <cstdlib>
/*
 * kr_configurable.cpp — Configurable differential key recovery
 *
 * Allows adjusting the number of identity S-boxes in round 1,
 * which changes the trail probability and thus the SNR.
 *
 * n_id = 8  → p = 2^{-26}  (original, SNR = 1/1024)
 * n_id = 12 → p = 2^{-18}  (SNR = 0.25)
 * n_id = 14 → p = 2^{-14}  (SNR = 4.0)   ← clearly distinguishable
 * n_id = 16 → p = 2^{-10}  (SNR = 64)     ← trivial
 */

#include "SmallScaleAES.h"
#include "key_recovery.h"
#include <iostream>
#include <iomanip>
#include <random>
#include <cstring>
#include <vector>
#include <algorithm>
#include <cmath>

static const word8 FIXED_KEY[16] = {0x2,0xB,0x7,0xE,0x1,0x5,0x1,0x6,0x2,0x8,0xA,0xE,0xD,0x2,0xA,0x6};

// Modified encryption: first n_id S-boxes = identity in round 1
void encrypt_modified_n(const word8 pt[16], const word8 key[16], int n_id, word8 ct[16]) {
    word8 rk[NUM_ROUNDS+1][16];
    key_expansion(key, rk);
    word8 state[16], tmp[16];
    add_round_key(pt, rk[0], state);
    for (int i = 0; i < 16; i++)
        tmp[i] = (i < n_id) ? state[i] : SBOX[state[i]];
    shift_rows(tmp, state); mix_column(state, tmp);
    add_round_key(tmp, rk[1], state);
    sub_bytes(state, tmp); shift_rows(tmp, state);
    mix_column(state, tmp); add_round_key(tmp, rk[2], state);
    sub_bytes(state, tmp); shift_rows(tmp, state);
    mix_column(state, tmp); add_round_key(tmp, rk[3], state);
    sub_bytes(state, tmp); shift_rows(tmp, state);
    add_round_key(state, rk[4], ct);
}

static void random_state(std::mt19937_64& rng, word8 state[16]) {
    uint64_t x = rng();
    for (int i = 0; i < 16; i++) { state[i] = x & 0xF; x >>= 4; }
}

int main(int argc, char* argv[]) {
    init_inv_sbox();
    int n_id = 8;  // default: 8 identity S-boxes
    if (argc >= 2) n_id = std::atoi(argv[1]);
    uint64_t N = 1ULL << 22;  // default: 2^22
    if (argc >= 3) N = 1ULL << std::atoi(argv[2]);

    double p_orig = std::pow(0.25, 13);  // 2^{-26} — active S-boxes in non-identity positions
    double p = p_orig;
    if (n_id > 8) p = p_orig * std::pow(4.0, n_id - 8);  // each extra identity S-box saves factor 4

    double lambda_signal = N * p;
    double lambda_noise = (double)N / 65536.0;
    double snr = lambda_signal / lambda_noise;

    std::cout << "============================================================\n";
    std::cout << "  可配置差分密钥恢复\n";
    std::cout << "============================================================\n\n";
    std::cout << "  Identity S-boxes: " << n_id << " / 16\n";
    std::cout << "  Trail probability p = 2^{-" << (26 - 2*(n_id-8)) << "} ≈ " << p << "\n";
    std::cout << "  N = 2^" << (int)std::log2(N) << " = " << N << "\n";
    std::cout << "  Expected signal (correct key): λ_s = " << lambda_signal << "\n";
    std::cout << "  Expected noise (per wrong key): λ_n = " << lambda_noise << "\n";
    std::cout << "  SNR = " << snr << " (need >> 1 for clear detection)\n\n";

    std::mt19937_64 rng(20260514ULL);
    uint64_t counter[65536] = {0};
    word8 rk[6][16];
    key_expansion(FIXED_KEY, rk);
    word8 correct_sk[4] = {rk[4][0], rk[4][13], rk[4][10], rk[4][7]};
    uint32_t correct_k = correct_sk[0] | (correct_sk[1]<<4) | (correct_sk[2]<<8) | (correct_sk[3]<<12);

    std::cout << "  Correct subkey (K4[0,13,10,7]): ("
              << std::hex << (int)correct_sk[0] << "," << (int)correct_sk[1] << ","
              << (int)correct_sk[2] << "," << (int)correct_sk[3] << ")" << std::dec << "\n\n";

    // Phase 1: Filter pairs (using modified encryption with n_id identity S-boxes)
    // Count how many pairs satisfy the trail for the CORRECT subkey only
    std::cout << "  Phase 1: Filtering pairs... " << std::flush;
    const word8 DELTA_P_KR[16] = {0x6,0x3,0x2,0xA,0xC,0x5,0xD,0x9,0x7,0x8,0x4,0xA,0x4,0x6,0x6,0xF};

    struct { word8 P[16], C[16], Cp[16]; } *survivors = nullptr;
    int n_surv = 0, cap = 1024;
    survivors = (decltype(survivors))malloc(cap * sizeof(*survivors));

    for (uint64_t i = 0; i < N; i++) {
        word8 P[16], Pp[16], C[16], Cp[16];
        random_state(rng, P);
        for (int j = 0; j < 16; j++) Pp[j] = P[j] ^ DELTA_P_KR[j];
        encrypt_modified_n(P, FIXED_KEY, n_id, C);
        encrypt_modified_n(Pp, FIXED_KEY, n_id, Cp);

        // Check if this pair satisfies the trail for the correct subkey
        if (partial_decrypt_check(C, Cp, correct_sk)) {
            if (n_surv < cap) {
                memcpy(survivors[n_surv].P, P, 16);
                memcpy(survivors[n_surv].C, C, 16);
                memcpy(survivors[n_surv].Cp, Cp, 16);
            }
            n_surv++;
        }
    }
    std::cout << "done\n";
    std::cout << "  Surviving pairs (voting for correct key): " << n_surv << "\n";
    std::cout << "  (Expected: " << lambda_signal << ")\n\n";

    // Phase 2: Key recovery — test ALL subkeys against surviving pairs
    std::cout << "  Phase 2: Key recovery (" << n_surv << " pairs × 65536 candidates)... " << std::flush;
    for (int pi = 0; pi < n_surv; pi++) {
        for (uint32_t k = 0; k < 65536; k++) {
            word8 kg[4] = {(word8)(k&0xF),(word8)((k>>4)&0xF),
                          (word8)((k>>8)&0xF),(word8)((k>>12)&0xF)};
            if (partial_decrypt_check(survivors[pi].C, survivors[pi].Cp, kg))
                counter[k]++;
        }
    }
    free(survivors);
    std::cout << "done\n\n";

    // Results
    uint32_t rank = 1;
    for (int k = 0; k < 65536; k++)
        if (counter[k] > counter[correct_k]) rank++;

    std::vector<std::pair<uint32_t,uint64_t>> cands;
    for (int k = 0; k < 65536; k++)
        if (counter[k] > 0) cands.push_back({(uint32_t)k, counter[k]});
    std::sort(cands.begin(), cands.end(),
              [](auto& a, auto& b) { return a.second > b.second; });

    std::cout << "============================================================\n";
    std::cout << "  RESULTS\n";
    std::cout << "============================================================\n\n";
    std::cout << "  Correct subkey count: " << counter[correct_k] << "\n";
    std::cout << "  Correct subkey rank:  " << rank << " / 65536\n";
    std::cout << "  SNR (signal/noise):   " << snr << "\n\n";

    if (counter[correct_k] > 0 && rank <= 5) {
        std::cout << "  ✓ KEY RECOVERY SUCCESSFUL! Correct key at rank " << rank << ".\n\n";
    } else if (counter[correct_k] > 0) {
        std::cout << "  △ Signal detected but rank too low (" << rank << ").\n";
        std::cout << "    Increase n_id or N for better SNR.\n\n";
    } else {
        std::cout << "  ✗ No signal detected for correct key.\n\n";
    }

    int show = std::min(15, (int)cands.size());
    std::cout << "  Top " << show << " candidates:\n";
    std::cout << "  Rank | Subkey         | Count | Correct?\n";
    std::cout << "  -----+----------------+-------+---------\n";
    for (int i = 0; i < show; i++) {
        uint32_t k = cands[i].first;
        bool is_c = (k == correct_k);
        std::cout << "  " << std::setw(4) << (i+1) << " | ("
                  << std::hex << ((k>>0)&0xF) << "," << ((k>>4)&0xF) << ","
                  << ((k>>8)&0xF) << "," << ((k>>12)&0xF) << ")" << std::dec
                  << std::setw(6) << " | " << std::setw(5) << cands[i].second
                  << " | " << (is_c ? "YES ✓" : "") << "\n";
    }
    std::cout << "\n";
    return 0;
}
