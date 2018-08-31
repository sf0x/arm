#include "hmac.h"

uint32_t ipad[16]={ 0x36363636, 0x36363636, 0x36363636, 0x36363636, 0x36363636, 0x36363636, 0x36363636, 0x36363636, 
				    0x36363636, 0x36363636, 0x36363636, 0x36363636, 0x36363636, 0x36363636, 0x36363636, 0x36363636 };

uint32_t opad[16]={ 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 
				    0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c, 0x5c5c5c5c };

uint32_t tmpBuf[64]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
					 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

/* H(key xor opad || H(key xor ipad || input)) */
void hmac(uint32_t key[8], uint32_t input[8], uint32_t hash[8], unsigned int round){
	uint32_t x[32]={0};			// array for the second part with opad
	uint32_t y[32]={0};			// array for the first part with ipad
	uint32_t tmp[8]={0};
	int inlen=0;				// byte length of the input
	
	if(round==0)
		inlen=10;				// in first round, salt + INT
	else
		inlen=32;				// in all other rounds, input is a 256 bit Ui-1 hash
	
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

	sha256_padding(y, tmp, 64+inlen, tmpBuf);

	for(int i=0; i<64; i++){
		tmpBuf[i]=0;
	}

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
	sha256_padding(x, hash, 96, tmpBuf);
}
