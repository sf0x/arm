/* convert uint8_t to uint32_t*/

#include "ett.h"
#include <stdio.h>

void _ett(uint8_t *in, uint32_t *out, unsigned int inlen){
	uint32_t tmp;
	for(int i=0; i<inlen; i++){
			tmp=in[i]<<((24-((i%4)*8)));			// tmp = password, shifted to the future pos
			out[i/4]|=tmp;							// hash is tmp or'ed
	}
}

void _tte(uint32_t *in, uint8_t *out, unsigned int outlen){
	uint32_t tmp;
	uint8_t tmp2;
	for(int i=0; i<outlen; i++){
		tmp=in[i/4]>> 24-((i%4)*8);
		out[i]=(uint8_t)tmp;
	}
}