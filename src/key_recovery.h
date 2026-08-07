/*
 * key_recovery.h — Modified 2.5+1 round differential key recovery
 *
 * Modification: first 8 S-boxes in round 1 replaced with identity,
 * saving 2^{-16} in probability. Trail probability: 2^{-26}.
 * Uses 2^26 plaintext pairs and recovers K_4 bytes at positions {0,13,10,7}.
 */
#pragma once
#include "SmallScaleAES.h"
#include <cstdint>

/* Modified encryption: first 8 S-boxes = identity in round 1 */
void encrypt_modified_4rounds(const word8 pt[16], const word8 key[16], word8 ct[16]);

/* Input difference for the modified trail */
extern const word8 DELTA_P_KR[16];

/* Expected difference after round 3 MixColumns */
extern const word8 DELTA_X3[4];

/* Active ciphertext positions: {0, 13, 10, 7} */
extern const int ACTIVE_POS[4];

/* Key recovery: given N pairs, fills counter[65536] with survival counts.
   Returns the correct subkey index. */
uint32_t run_key_recovery(uint64_t N, uint64_t counter[65536],
                          uint32_t *correct_k);

/* Partial decrypt check for one subkey guess */
bool partial_decrypt_check(const word8 C[16], const word8 C_prime[16],
                           const word8 k_guess[4]);
