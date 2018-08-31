#ifndef SHA256_H_
#define SHA256_H_

#include <stdint.h>
#include "shasm.h"

void padding(uint32_t input[16], uint32_t padded_plain[16], int bytelen);

void sha256_padding(uint32_t input[32], uint32_t hash[8], int bytelen, uint32_t tmpBuf[64]);


#endif
