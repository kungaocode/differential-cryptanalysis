/*
 * bench_perf.cpp — Differential Analysis Performance Benchmark
 */
#include "SmallScaleAES.h"
#include "distinguisher.h"
#include "key_recovery.h"
#include <iostream>
#include <iomanip>
#include <chrono>

static double now_ms() {
    using namespace std::chrono;
    return duration<double,std::milli>(steady_clock::now().time_since_epoch()).count();
}

int main() {
    init_inv_sbox();
    std::cout << "=== Differential Analysis Performance Benchmark ===\n\n";

    /* 1. Distinguisher: 3 trials timing */
    std::cout << "Distinguisher (3 trials of 2^20 pairs each):\n";
    double t0=now_ms();
    for(int t=0;t<3;t++) distinguisher_trial(20260514ULL+1000ULL*t);
    double t1=now_ms();
    std::cout << "  Total: " << (t1-t0) << " ms, per trial: " << (t1-t0)/3.0 << " ms\n";

    /* 2. Key recovery: small scale N=2^18 for speed */
    std::cout << "\nKey recovery (N=2^18 pairs, all 65536 subkeys):\n";
    uint64_t counter[65536]={0};
    uint32_t correct_k;
    t0=now_ms();
    uint32_t result = run_key_recovery(1ULL<<18, counter, &correct_k);
    t1=now_ms();
    std::cout << "  Total: " << (t1-t0) << " ms\n";
    std::cout << "  Correct subkey count: " << counter[correct_k] << "\n";
    std::cout << "  Correct subkey rank:  " << result << "\n";

    std::cout << "\n=== Benchmark complete ===\n";
    return 0;
}
