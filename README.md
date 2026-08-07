# SmallScaleAES Differential Cryptanalysis

Differential cryptanalysis of SmallScaleAES (a 4-bit nibble-based AES variant) with a two-phase attack framework: differential distinguishing and key recovery.

## Project Structure

```
.
├── src/                    # Source code
│   ├── SmallScaleAES.h     # SmallScaleAES cipher (nibble-based, GF(2^4))
│   ├── SmallScaleAES.cpp
│   ├── distinguisher.h     # 3-round differential distinguisher
│   ├── distinguisher_lib.cpp
│   ├── DifferentialDistinguisher.cpp   # Distinguisher demo
│   ├── key_recovery.h      # Key recovery library
│   ├── key_recovery_lib.cpp
│   ├── KeyRecovery_Modified_Simple.cpp # Key recovery with modified S-box
│   ├── kr_configurable.cpp  # Configurable identity S-box key recovery
│   ├── kr_two_phase.cpp     # Two-phase key recovery
│   ├── bench_perf.cpp       # Performance benchmark
│   ├── test_correctness.cpp # Correctness tests
│   └── Makefile
├── reports/                # Compiled PDF reports
├── result.txt              # Project summary (Chinese)
└── .gitignore
```

## Build

```bash
cd src
make          # Build test_correctness and bench_perf
make test     # Run correctness tests
make bench    # Run performance benchmark
make clean    # Remove build artifacts
```

## Approach

- **Phase 1 (Distinguisher):** A 3-round differential distinguisher filters random plaintext pairs using Poisson-distribution-based hypothesis testing. With 2^20 pairs per trial and an expected λ=4 hits, it achieves 100% TPR / 0% FPR across 20 independent trials.

- **Phase 2 (Key Recovery):** Modified differential trail with configurable identity S-boxes (n_id=8~14) to boost differential probability. Full 65536 subkey candidate search with voting. Signal-to-noise ratio (SNR = p·2^16) determines key recovery feasibility.

## Key Results

| SNR   | Correct Key Rank | Outcome                        |
|-------|-------------------|--------------------------------|
| 0.001 | 24404/65536       | Buried in noise                |
| 0.016 | 1                 | Successfully recovered         |
| 4.0   | 1 (71 vs 35)      | 2× margin over 2nd candidate   |

Correct subkey K4[0,13,10,7] = (4,3,6,6).
