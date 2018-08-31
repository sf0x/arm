#include "hmac.h"

uint32_t ipad[16]={ 0x36363636, 0x36363636, 0x36363636, 0x36363636, 0x36363636, 0x36363636, 0x36363636, 0x36363636, 
				    0x36363636, 0x36363636, 0x36363636, 0x36363636, 0x36363636, 0x36363636, 0x36363636, 0x36363636 };

uint32_t opad[16]={ 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 
				    0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c };


/* H(key xor opad || H(key xor ipad || input)) */
void hmac(uint32_t key[8], uint32_t input[8], uint32_t hash[8], unsigned int round){
	uint32_t x[24]={0};
	uint32_t y[24]={0};
	uint32_t tmp[8]={0};
	int inlen=0;
	
	if(round==0)
		inlen=10;
	else
		inlen=32;
	
	for(int i=0; i<24;i++){
		if(i<8){
			y[i]=key[i]^ipad[i];
		}
		else if(i<16 && i>=8){
			y[i]=ipad[i];
		}
		else{
			y[i]=input[i-16];
		}
	}

	sha256(y, tmp, 64+inlen);

	for(int i=0; i<24; i++){
		if(i<8){
			x[i]=key[i]^opad[i];
		}
		else if(i<16 && i>=8){
			x[i]=opad[i];
		}
		else{
			x[i]=tmp[i-16];
		}
	}
	sha256(x, hash, 96);
}
