#include "pbkdf2.h"
#include "ett.h"

void pbkdf2(uint8_t password[6], uint8_t derivedKey[16]){
	uint8_t salt[6]={0x10,0x80,0x14,0x23,0x64,0x63,0x00,0x00,0x00,0x01};
	uint32_t T[8]={0};
	uint32_t key[8]={0};
	uint32_t input[8]={0};
	uint32_t U1[8]={0};
	uint32_t U2[8]={0};

	_ett(password, key, 6);
	_ett(salt, input, 10);
	
	int round=0;

	hmac(key, input, U1, round);

	round++;

	

	for(int i=0; i<8; i++)
		T[i]=U1[i];

	for(; round<10000; round++){
		if(round%2){
			hmac(key, U1, U2, round);
			for(int i=0; i<8; i++)
				T[i]^=U2[i];
		}
		else{
			hmac(key, U2, U1, round);
			for(int i=0; i<8; i++)
				T[i]^=U1[i];
		}

	}
	_tte(T, derivedKey, 16);	
}