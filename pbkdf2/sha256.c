#include "sha256.h"

uint32_t H[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
					     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };


void padding(uint32_t input[16], uint32_t padded_plain[16], int bytelen){
	int padstart=(bytelen%64)/4;		// calculate the pos of the first padding byte

	
	for(int i=0; i<16; i++){
		padded_plain[i]=input[i];
	}
	padded_plain[padstart]|=0x8<<(28-((bytelen%4)*8));
}

void sha256_padding(uint32_t input[32], uint32_t hash[8], int bytelen, uint32_t tmpBuf[64]){

	int runs=(bytelen/64)+1;		// rounds to run till all input is hashed

	for(int i=0; i<8; i++)								
		hash[i]=H[i];


	for(int i=0; i<runs; i++){

		uint32_t padded_plain[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

		uint32_t tmp[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

		if(i==runs-1){
			// normal padding
			if((bytelen%64)<56){
				for(int j=0; j<((bytelen-(64*i))/4)+(bytelen%4); j++){
					tmp[j]=input[(i*16)+j];
				}
				padding(tmp, padded_plain, bytelen);
				padded_plain[14]=0x00000000;
				padded_plain[15]=bytelen*8;
			}
			// special padding
			if((bytelen%64)>=56){
				for(int j=0; j<((bytelen-(64*i))/4)+1; j++)
					tmp[j]=input[(i*16)+j];
				padding(tmp, padded_plain, bytelen);

				// initialize tmpBuf words
				_SHA256_INIT(padded_plain, tmpBuf);

				// core hash function
				_SHA256_MAIN(tmpBuf, hash);


				// insert empty plain
				for(int j=0; j<64;j++)
					tmpBuf[j]=0x00000000;

				// empty out input
				for(int j=0; j<16; j++)
					padded_plain[j]=0x00000000;
				padded_plain[14]=0x00000000;
				padded_plain[15]=bytelen*8;
			}
		}
		else{
			for(int j=0; j<16; j++)
				padded_plain[j]=input[(i*16)+j];		// process full the current input
		}

		//sha_init(padded_plain, hash_word_temp);
		_SHA256_INIT(padded_plain, tmpBuf);

		//sha_main(hash_word_temp, hash);
		_SHA256_MAIN(tmpBuf, hash);

		// empty the arrays
		for(int j=0; j<16; j++){
			tmp[j]=0x00000000;
			padded_plain[j]=0x00000000;
		}
	}
}
