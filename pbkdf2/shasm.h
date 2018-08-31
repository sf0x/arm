#ifndef SHASM_H_
#define SHASM_H_

void _SHA256_INIT(uint32_t temphash[16], uint32_t hash_word_temp[64]);

void _SHA256_MAIN(uint32_t hash_word_temp[64], uint32_t hash[8]);

#endif
