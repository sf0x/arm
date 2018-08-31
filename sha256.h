#ifndef SHA256_H_
#define SHA256_H_

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

unsigned int _rotr(const unsigned int value, int shift);		// change maybe

uint32_t BSIG1(uint32_t inword);

uint32_t BSIG0(uint32_t inword);

uint32_t SSIG1(uint32_t inword);

uint32_t SSIG0(uint32_t inword);

void sha_main(uint32_t hash_word_temp[64], uint32_t hash[8]);

void sha_init(uint32_t temphash[16], uint32_t hashtemp[64]);

void padding(uint32_t input[16], uint32_t padded_plain[16], int bytelen);

void sha256(uint32_t input[24], uint32_t hash[8], int bytelen);


#endif