#include "sha256.h"

static uint32_t H[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
					     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };


static uint32_t K[64]= { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
					     0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
					     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
					     0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
					     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
					     0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
					     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
					     0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
					     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
					     0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
					     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
					     0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
					     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
					     0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
					     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
					     0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };		

// TODO: stolen!!!
// rotate right
unsigned int _rotr(const unsigned int value, int shift) {
    if ((shift &= sizeof(value)*8 - 1) == 0)
      return value;
    return (value >> shift) | (value << (sizeof(value)*8 - shift));
}

#define CH(x,y,z) ((x & y) ^ ((~x) & z))

#define MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))

uint32_t BSIG1(uint32_t inword){
	return _rotr(inword, 6) ^ _rotr(inword, 11) ^ _rotr(inword, 25);
}

uint32_t BSIG0(uint32_t inword){
	return _rotr(inword, 2) ^ _rotr(inword, 13) ^ _rotr(inword, 22);
}

uint32_t SSIG1(uint32_t inword){
	return _rotr(inword, 17) ^ _rotr(inword, 19) ^ (inword >> 10);
}

uint32_t SSIG0(uint32_t inword){
	return _rotr(inword, 7) ^ _rotr(inword,18) ^ (inword >> 3);
}

void sha_main(uint32_t hash_word_temp[64], uint32_t hash[8]){
	// initialize working variables a-h
	uint32_t a=hash[0],
			 b=hash[1],
			 c=hash[2],
			 d=hash[3],
			 e=hash[4],
			 f=hash[5],
			 g=hash[6],
			 h=hash[7];

	// hashing loop
	for(int i=0; i<64; i++){
		uint32_t T1 = (h + BSIG1(e) + CH(e,f,g) % 0xFFFFFFFF) + K[i] + hash_word_temp[i] % 0xFFFFFFFF;
		uint32_t T2 = BSIG0(a) + MAJ(a,b,c) % 0xFFFFFFFF;
		h=g;
		g=f;
		f=e;
		e=d+T1 % 0xFFFFFFFF;
		d=c;
		c=b;
		b=a;
		a=T1+T2 % 0xFFFFFFFF;
	}
	hash[0]=hash[0]+a % 0xFFFFFFFF;
	hash[1]=hash[1]+b % 0xFFFFFFFF;
	hash[2]=hash[2]+c % 0xFFFFFFFF;
	hash[3]=hash[3]+d % 0xFFFFFFFF;
	hash[4]=hash[4]+e % 0xFFFFFFFF;
	hash[5]=hash[5]+f % 0xFFFFFFFF;
	hash[6]=hash[6]+g % 0xFFFFFFFF;
	hash[7]=hash[7]+h % 0xFFFFFFFF;
}

// initialize hash_word_temp with W[t]=M[t] and further
void sha_init(uint32_t temphash[16], uint32_t hash_word_temp[64]){
	for(int i=0; i<16; i++){
		hash_word_temp[i]=temphash[i];
	}
	for(int i=16;i<64;i++){
		hash_word_temp[i]=((SSIG1(hash_word_temp[i-2]) + hash_word_temp[i-7] % 0xFFFFFFFF) + SSIG0(hash_word_temp[i-15]) + hash_word_temp[i-16]) % 0xFFFFFFFF;
	}

	/*
	// DEBUG
	for(int i=0; i<64; i++){
		printf("ht[%d]=0x%lx, ", i, hash_word_temp[i]);
		if(!(i%4))
			puts("");
	}
	puts("");
	puts("---------");
	puts("---------");
	puts("");*/
}

void padding(uint32_t input[16], uint32_t padded_plain[16], int bytelen){
	int padstart=(bytelen%64)/4;
	//uint32_t padval=bytelen*8;

	
	for(int i=0; i<16; i++){
		padded_plain[i]=input[i];
	}
	padded_plain[padstart]|=0x8<<(28-((bytelen%4)*8));
	//padded_plain[15]|=padval;
}

void sha256(uint32_t input[24], uint32_t hash[8], int bytelen){
	//printf("Bytelen=%d\n", bytelen);

	int runs=(bytelen/64)+1;

	for(int i=0; i<8; i++)								
		hash[i]=H[i];	

	

	for(int i=0; i<runs; i++){
		uint32_t hash_word_temp[64] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
									   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};				// processing space
		uint32_t padded_plain[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		uint32_t tmp[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

		if(i==runs-1){
			if((bytelen%64)<56){
				//puts("LOWPADD");
				for(int j=0; j<((bytelen-(64*i))/4)+(bytelen%4); j++){
					tmp[j]=input[(i*16)+j];
					//printf("tmp[%d]=input[%d]=%lx\n", j, j, input[(i*16)+j]);
				}
				padding(tmp, padded_plain, bytelen);
				padded_plain[14]=0x00000000;
				padded_plain[15]=bytelen*8;
			}
			if((bytelen%64)>=56){
				//puts("DOUBLEPADD");
				for(int j=0; j<((bytelen-(64*i))/4)+1; j++)
					tmp[j]=input[(i*16)+j];
				padding(tmp, padded_plain, bytelen);

				// insert hashing
				sha_init(padded_plain, hash_word_temp);

				sha_main(hash_word_temp, hash);
				//
				// insert empty plain
				for(int j=0; j<64;j++)
					hash_word_temp[j]=0x00000000;

				for(int j=0; j<16; j++)
					padded_plain[j]=0x00000000;
				padded_plain[14]=0x00000000;
				padded_plain[15]=bytelen*8;
			}
		}
		else{
			//puts("NOPADD");
			for(int j=0; j<16; j++)
				padded_plain[j]=input[(i*16)+j];
		}

		sha_init(padded_plain, hash_word_temp);

		sha_main(hash_word_temp, hash);

		for(int j=0; j<16; j++){
			tmp[j]=0x00000000;
			padded_plain[j]=0x00000000;
		}
		
	}

	/*for(int i=0; i<8; i++){
		printf("%lx", hash[i]);
	}
	puts("");
	puts("XXXXXXXXXXXXXXX++++++++++++++XXXXXXXXXXXXXXXXXX");	*/
}