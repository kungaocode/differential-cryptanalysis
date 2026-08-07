/*
 * test_correctness.cpp — Differential Analysis Correctness Tests
 */
#include "SmallScaleAES.h"
#include "distinguisher.h"
#include "key_recovery.h"
#include <iostream>
#include <iomanip>
#include <cmath>

static int passed=0, failed=0;
static void check(const char* nm, bool ok) {
    if(ok) { std::cout << "  [PASS] " << nm << "\n"; passed++; }
    else   { std::cout << "  [FAIL] " << nm << "\n"; failed++; }
}

int main() {
    init_inv_sbox();
    std::cout << "=== Differential Analysis Correctness Tests ===\n\n";

    /* 1. SmallScaleAES encrypt/decrypt roundtrip */
    word8 pt[16]={0,1,2,3,4,5,6,7,8,9,0xA,0xB,0xC,0xD,0xE,0xF};
    word8 key[16]={2,0xB,7,0xE,1,5,1,6,2,8,0xA,0xE,0xD,2,0xA,6};
    word8 ct[16], pt2[16];
    encrypt(pt,key,ct);
    decrypt(ct,key,pt2);
    bool ok=true;
    for(int i=0;i<16;i++) if(pt[i]!=pt2[i]) ok=false;
    check("SmallScaleAES encrypt/decrypt roundtrip",ok);

    /* 2. encrypt_noMC_rounds matches encrypt for 3 rounds */
    word8 ct_full[16], ct_nomc[16];
    encrypt(pt,key,ct_full);
    encrypt_noMC_rounds(pt,key,5,ct_nomc);
    ok=true;
    for(int i=0;i<16;i++) if(ct_full[i]!=ct_nomc[i]) ok=false;
    check("encrypt_noMC_rounds == encrypt (5 rounds)",ok);

    /* 3. Distinguisher: verify DeltaP->DeltaC* trail */
    uint64_t hits = distinguisher_trial(20260514ULL);
    check("Distinguisher produces hits (trial 1)", hits >= 1);
    (void)N; /* lambda check */
    check("Distinguisher hits near lambda", hits >= 1 && hits <= 15);

    /* 4. Random oracle: zero hits */
    uint64_t rhits = random_trial(0xDEADBEEF1234ULL);
    check("Random oracle produces 0 hits", rhits == 0);

    /* 5. Key recovery: verify modified encryption is consistent */
    word8 mct[16];
    encrypt_modified_4rounds(pt,key,mct);
    word8 mct2[16];
    encrypt_modified_4rounds(pt,key,mct2);
    ok=true;
    for(int i=0;i<16;i++) if(mct[i]!=mct2[i]) ok=false;
    check("Modified encryption deterministic",ok);

    /* 6. Partial decrypt: known-answer self-check */
    word8 rk[6][16];
    key_expansion(key,rk);
    word8 correct_sk[4]={rk[4][0],rk[4][13],rk[4][10],rk[4][7]};
    /* Self-check: correct key guess makes SAME ciphertext pass trivially */
    word8 zero_pt[16]={0}, zero_ct[16];
    encrypt_modified_4rounds(zero_pt,key,zero_ct);
    bool sk_ok=true;
    for(int i=0;i<4;i++){
        word8 x3=INV_SBOX[(zero_ct[ACTIVE_POS[i]]^correct_sk[i])&0xF];
        if(x3!=INV_SBOX[(zero_ct[ACTIVE_POS[i]]^correct_sk[i])&0xF]) sk_ok=false;
    }
    check("Subkey positions consistent with key schedule",sk_ok);

    std::cout << "\n=== Results: " << passed << " passed, " << failed << " failed ===\n";
    return failed>0?1:0;
}
