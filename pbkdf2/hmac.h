#ifndef HMAC_H_
#define HMAC_H_
#include <stdint.h>
#include "sha256.h"

void hmac(uint32_t key[8], uint32_t input[8], uint32_t hash[8], unsigned int round);


#endif
