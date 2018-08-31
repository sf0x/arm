#ifndef PBKDF2_H_
#define PBKDF2_H_
#include <stdint.h>
#include "hmac.h"

void pbkdf2(uint8_t password[6], uint8_t derivedKey[16]);

#endif