/*
 * distinguisher.h — 3-round SmallScaleAES differential distinguisher
 *
 * Verifies the 3-round trail DeltaP → DeltaC* with probability 2^{-18}.
 * Generates N=2^20 plaintext pairs per trial, counts hits matching
 * the expected output difference.
 */
#pragma once
#include "SmallScaleAES.h"
#include <cstdint>

/* Differential trail parameters */
extern const word8 DELTA_P[16];       /* input difference  */
extern const word8 DELTA_C_STAR[16];  /* expected output difference */
extern const int CIPHER_ROUNDS;       /* 3 rounds (no MC in last) */
extern const uint64_t N;              /* pairs per trial (2^20) */
extern const double LAMBDA0;          /* expected hits per trial */
extern const word8 KEY[16];           /* fixed experiment key */

/* Run one trial with given seed. Returns hit count. */
uint64_t distinguisher_trial(uint64_t seed);

/* Run one random-permutation trial (null hypothesis). Returns hit count. */
uint64_t random_trial(uint64_t seed);

/* Poisson PMF: P[X=k] for X ~ Poisson(lambda) */
double poisson_pmf(int k, double lambda);
