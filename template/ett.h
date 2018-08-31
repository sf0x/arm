/* convert uint8_t to uint32_t*/
#ifndef ETT_H_
#define ETT_H_
#include <stdint.h>

void _ett(uint8_t *in, uint32_t *out, unsigned int inlen);

void _tte(uint32_t *in, uint8_t *out, unsigned int outlen)

#endif