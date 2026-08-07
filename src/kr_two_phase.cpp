#include <cstring>
/*
 * kr_two_phase.cpp — Two-phase differential key recovery
 *
 * Phase 1: Run the 3-round distinguisher to collect pairs satisfying
 *          the differential trail. Count how many survive.
 * Phase 2: Use only the surviving pairs for 4-round key recovery
 *          (tests 65536 subkey candidates per surviving pair).
 *
 * This matches the report standard: "通过数学过滤从噪声数据中
 * 分离出具有密钥依赖关系的数据对"
 */

#include "SmallScaleAES.h"
#include "key_recovery.h"
#include <iostream>
#include <iomanip>
#include <random>
#include <vector>
#include <algorithm>

static const word8 FIXED_KEY[16] = {0x2,0xB,0x7,0xE,0x1,0x5,0x1,0x6,0x2,0x8,0xA,0xE,0xD,0x2,0xA,0x6};

static void random_state(std::mt19937_64& rng, word8 state[16]) {
    uint64_t x = rng();
    for (int i = 0; i < 16; i++) { state[i] = x & 0xF; x >>= 4; }
}

struct Pair { word8 P[16], P_prime[16], C[16], C_prime[16]; };

int main(int argc, char* argv[]) {
    init_inv_sbox();
    
    // Phase 1 N (distinguisher filtering)
    uint64_t N1 = 1ULL << 20;  // default 2^20
    if (argc >= 2) N1 = 1ULL << std::atoi(argv[1]);
    
    // Phase 2 N (key recovery — use surviving pairs)
    // Default: all surviving pairs from Phase 1
    
    double p3 = std::pow(0.25, 9);   // 3-round trail: 2^{-18}
    double lambda_filter = N1 * p3;
    
    std::cout << "============================================================\n";
    std::cout << "  实验四: 两阶段差分密钥恢复\n";
    std::cout << "============================================================\n\n";
    std::cout << "Phase 1 — 数学过滤 (3轮区分器):\n";
    std::cout << "  N1 = 2^" << std::log2(N1) << " = " << N1 << " pairs\n";
    std::cout << "  Trail probability p = 2^{-18}\n";
    std::cout << "  Expected surviving pairs λ = " << lambda_filter << "\n\n";
    
    // Phase 1: Run distinguisher, collect surviving pairs
    std::mt19937_64 rng(20260514ULL);
    std::vector<Pair> survivors;
    
    const word8 DELTA_P[16] = {0xF,0x0,0x0,0x0, 0x0,0xA,0x0,0x0, 0x0,0x0,0x1,0x0, 0x0,0x0,0x0,0x9};
    const word8 DELTA_C_STAR[16] = {0xB,0x0,0x0,0x0, 0x0,0x0,0x0,0x4, 0x0,0x0,0x7,0x0, 0x0,0x7,0x0,0x0};
    
    for (uint64_t i = 0; i < N1; i++) {
        Pair pr;
        random_state(rng, pr.P);
        for (int j = 0; j < 16; j++) pr.P_prime[j] = pr.P[j] ^ DELTA_P[j];
        encrypt_noMC_rounds(pr.P, FIXED_KEY, 3, pr.C);
        encrypt_noMC_rounds(pr.P_prime, FIXED_KEY, 3, pr.C_prime);
        word8 D[16];
        for (int j = 0; j < 16; j++) D[j] = pr.C[j] ^ pr.C_prime[j];
        if (memcmp(D, DELTA_C_STAR, 16) == 0) {
            survivors.push_back(pr);
        }
    }
    
    int n_surv = (int)survivors.size();
    std::cout << "  ✓ 过滤完成: " << n_surv << " 对满足3轮差分约束\n";
    std::cout << "  (理论期望: " << lambda_filter << ", Poisson P[M>=1] = "
              << (1.0 - std::exp(-lambda_filter)) << ")\n\n";
    
    // Phase 2: Key recovery using ONLY the surviving pairs
    std::cout << "Phase 2 — 密钥恢复 (4轮Modified):\n";
    std::cout << "  Surviving pairs: " << n_surv << "\n";
    std::cout << "  Subkey candidates: 65536\n";
    std::cout << "  Total operations: " << n_surv << " × 65536 ≈ "
              << (n_surv * 65536) << "\n\n";
    
    uint64_t counter[65536] = {0};
    word8 rk[6][16];
    key_expansion(FIXED_KEY, rk);
    word8 correct_sk[4] = {rk[4][0], rk[4][13], rk[4][10], rk[4][7]};
    uint32_t correct_k = correct_sk[0] | (correct_sk[1]<<4) | (correct_sk[2]<<8) | (correct_sk[3]<<12);
    
    std::cout << "  Correct subkey (K4[0,13,10,7]): ("
              << std::hex << (int)correct_sk[0] << ", " << (int)correct_sk[1] << ", "
              << (int)correct_sk[2] << ", " << (int)correct_sk[3] << ")" << std::dec << "\n\n";
    
    for (int pi = 0; pi < n_surv; pi++) {
        for (uint32_t k = 0; k < 65536; k++) {
            word8 kg[4] = {(word8)(k&0xF),(word8)((k>>4)&0xF),
                          (word8)((k>>8)&0xF),(word8)((k>>12)&0xF)};
            if (partial_decrypt_check(survivors[pi].C, survivors[pi].C_prime, kg))
                counter[k]++;
        }
    }
    
    // Results
    std::cout << "============================================================\n";
    std::cout << "  实验结果\n";
    std::cout << "============================================================\n\n";
    std::cout << "  正确子密钥计数: " << counter[correct_k] << " 对\n";
    
    int candidates_over_0 = 0, candidates_over_1 = 0;
    for (int k = 0; k < 65536; k++) {
        if (counter[k] > 0) candidates_over_0++;
        if (counter[k] > 1) candidates_over_1++;
    }
    
    uint32_t rank = 1;
    for (int k = 0; k < 65536; k++)
        if ((uint64_t)counter[k] > counter[correct_k]) rank++;
    
    std::cout << "  正确子密钥排名: " << rank << " / 65536\n";
    std::cout << "  计数>0的候选: " << candidates_over_0 << "\n";
    std::cout << "  计数>1的候选: " << candidates_over_1 << "\n\n";
    
    // Top candidates
    std::vector<std::pair<uint32_t,uint64_t>> cands;
    for (int k = 0; k < 65536; k++)
        if (counter[k] > 0) cands.push_back({(uint32_t)k, counter[k]});
    std::sort(cands.begin(), cands.end(),
              [](auto& a, auto& b) { return a.second > b.second; });
    
    int show = std::min(10, (int)cands.size());
    std::cout << "  Top " << show << " candidates:\n";
    std::cout << "  Rank | Subkey           | Count | Correct?\n";
    std::cout << "  -----+------------------+-------+---------\n";
    for (int i = 0; i < show; i++) {
        uint32_t k = cands[i].first;
        bool is_c = (k == correct_k);
        std::cout << "  " << std::setw(4) << (i+1) << " | ("
                  << std::hex << ((k>>0)&0xF) << "," << ((k>>4)&0xF) << ","
                  << ((k>>8)&0xF) << "," << ((k>>12)&0xF) << ")" << std::dec
                  << std::setw(8) << " | " << std::setw(5) << cands[i].second
                  << " | " << (is_c ? "YES ✓" : "") << "\n";
    }
    
    std::cout << "\n";
    return 0;
}
