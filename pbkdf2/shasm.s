.syntax unified

// return _rotr(inword, 7) ^ _rotr(inword,18) ^ (inword >> 3);
_SSIG0:
	push {r1-r2,lr}
	ror r1,r0,#0x7				// rotr 7
	ror r2,r0,#0x12				// rotr 18
	lsr r0,r0,#0x3				// rotr 3
	eor r0,r0,r1				// xor
	eor r0,r0,r2				// xor
	pop {r1-r2,pc}

// return _rotr(inword, 17) ^ _rotr(inword, 19) ^ (inword >> 10);
_SSIG1:
	push {r1-r2,lr}
	ror r1,r0,#0x11				// rotr 17
	ror r2,r0,#0x13				// rotr 19
	lsr r0,r0,#0xa				// right shift 10
	eor r0,r0,r1				// xor
	eor r0,r0,r2				// xor
	pop {r1-r2,pc}

.global _SHA256_INIT
_SHA256_INIT:
	push {r0-r12,lr}


	mov r3, #0x0				// loop index for tmpBuf=plain -> 16 steps
plain_in:
	ldr r2,[r0]					// load padded plaintext
	str r2,[r1]					// store into tmpBuf
	add r0,#0x4					// increment padded plaintext
	add r1,#0x4					// increment tmpBuf
	//add r3,#0x1					// increment loop index t++

	ldr r2,[r0]					// load padded plaintext
	str r2,[r1]					// store into tmpBuf
	add r0,#0x4					// increment padded plaintext
	add r1,#0x4					// increment tmpBuf
	//add r3,#0x1

	ldr r2,[r0]					// load padded plaintext
	str r2,[r1]					// store into tmpBuf
	add r0,#0x4					// increment padded plaintext
	add r1,#0x4					// increment tmpBuf
	//add r3,#0x1

	ldr r2,[r0]					// load padded plaintext
	str r2,[r1]					// store into tmpBuf
	add r0,#0x4					// increment padded plaintext
	add r1,#0x4					// increment tmpBuf
	//add r3,#0x1

	ldr r2,[r0]					// load padded plaintext
	str r2,[r1]					// store into tmpBuf
	add r0,#0x4					// increment padded plaintext
	add r1,#0x4					// increment tmpBuf
	//add r3,#0x1

	ldr r2,[r0]					// load padded plaintext
	str r2,[r1]					// store into tmpBuf
	add r0,#0x4					// increment padded plaintext
	add r1,#0x4					// increment tmpBuf
	//add r3,#0x1

	ldr r2,[r0]					// load padded plaintext
	str r2,[r1]					// store into tmpBuf
	add r0,#0x4					// increment padded plaintext
	add r1,#0x4					// increment tmpBuf
	//add r3,#0x1

	ldr r2,[r0]					// load padded plaintext
	str r2,[r1]					// store into tmpBuf
	add r0,#0x4					// increment padded plaintext
	add r1,#0x4					// increment tmpBuf
	//add r3,#0x1

	ldr r2,[r0]					// load padded plaintext
	str r2,[r1]					// store into tmpBuf
	add r0,#0x4					// increment padded plaintext
	add r1,#0x4					// increment tmpBuf
	//add r3,#0x1

	ldr r2,[r0]					// load padded plaintext
	str r2,[r1]					// store into tmpBuf
	add r0,#0x4					// increment padded plaintext
	add r1,#0x4					// increment tmpBuf
	//add r3,#0x1

	ldr r2,[r0]					// load padded plaintext
	str r2,[r1]					// store into tmpBuf
	add r0,#0x4					// increment padded plaintext
	add r1,#0x4					// increment tmpBuf
	//add r3,#0x1

	ldr r2,[r0]					// load padded plaintext
	str r2,[r1]					// store into tmpBuf
	add r0,#0x4					// increment padded plaintext
	add r1,#0x4					// increment tmpBuf
	//add r3,#0x1

	ldr r2,[r0]					// load padded plaintext
	str r2,[r1]					// store into tmpBuf
	add r0,#0x4					// increment padded plaintext
	add r1,#0x4					// increment tmpBuf
	//add r3,#0x1

	ldr r2,[r0]					// load padded plaintext
	str r2,[r1]					// store into tmpBuf
	add r0,#0x4					// increment padded plaintext
	add r1,#0x4					// increment tmpBuf
	//add r3,#0x1

	ldr r2,[r0]					// load padded plaintext

	mov r7,r2					// copy to r7 for later W[t-2]

	str r2,[r1]					// store into tmpBuf
	add r0,#0x4					// increment padded plaintext
	add r1,#0x4					// increment tmpBuf
	//add r3,#0x1

	ldr r2,[r0]					// load padded plaintext

	mov r6,r2					// copy to r6 for later W[t-2]

	str r2,[r1]					// store into tmpBuf
	add r0,#0x4					// increment padded plaintext
	add r1,#0x4					// increment tmpBuf

	add r3,#0x10

	// now:
	// hash_word_temp[i]=((SSIG1(hash_word_temp[i-2]) + hash_word_temp[i-7] % 0xFFFFFFFF) +
	//   SSIG0(hash_word_temp[i-15]) + hash_word_temp[i-16]) % 0xFFFFFFFF;

word_calc:
	mov r4,r1					// load tmpBuf pointer to r4 for faster increment
	mov r0,r7					// get W[t-2]

	//sub r4,#0x8					// pos to W[t-2]		-2*4 byte
	//ldr r0,[r4]					// load W[t-2]
	bl _SSIG1					// SSIG1(W[t-2])
	mov r5,r0					// save return val
	sub r4,#0x1c				// pos to W[t-7]		-5*4 byte
	ldr r0,[r4]					// load value
	add r5,r5,r0				// + to other values
	sub r4,#0x20				// pos to W[t-15]		-8*4 byte
	ldr r0,[r4]					// load value
	bl _SSIG0					// SSIG0(W[t-15])
	add r5,r5,r0				// + to other values
	sub r4,#0x4					// pos to W[t-16]		-1*4 byte
	ldr r0,[r4]					// load value
	add r5,r5,r0				// add value

	mov r7,r6					// move W[t-2]
	mov r6,r5					// move current W[t-2]

	str r5,[r1]					// store W[t]
	add r3,#0x1					// t++
	add r1,#0x4					// W[t++]
	cmp r3,#0x40				// is 64?
	bne word_calc				// if not goto word_calc

	//sub r1,#0x100				// set pointer to tmpBuf[0]		-64*4 byte
	pop {r0-r12,pc}


//////////////////////////////////////////////////////////////////////////

// CH(x,y,z) ((x & y) ^ ((~x) & z))
_CH:
	push {r3-r4,lr}
	and r3,r0,r1				// x & y
	bic r4,r2,r0				// ~x & z
	eor r0,r3,r4				// xor
	pop {r3-r4,pc}

// MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
_MAJ:
	push {r3-r5,lr}
	and r4,r0,r1				// x & y
	and r5,r0,r2				// x & z
	and r0,r1,r2				// y & z
	eor r0,r0,r4				// xor
	eor r0,r0,r5				// xor
	pop {r3-r5,pc}

// return _rotr(inword, 2) ^ _rotr(inword, 13) ^ _rotr(inword, 22);
_BSIG0:
	push {r1-r2,lr}
	ror r1,r0,#0x2				// rotr by 2
	ror r2,r0,#0xd				// rotr by 13
	ror r0,r0,#0x16				// rotr by 22
	eor r0,r0,r1				// xor
	eor r0,r0,r2				// xor
	pop {r1-r2,pc}

// return _rotr(inword, 6) ^ _rotr(inword, 11) ^ _rotr(inword, 25);
_BSIG1:
	push {r1-r2,lr}
	ror r1,r0,#0x6				// rotr by 6
	ror r2,r0,#0xb				// rotr by 11
	ror r0,r0,#0x19				// rotr by 25
	eor r0,r0,r1				// xor
	eor r0,r0,r2				// xor
	pop {r1-r2,pc}

.global _SHA256_MAIN
_SHA256_MAIN:
	/*push {r0-r12,lr}

	mov r3,r0					// store tmpBuf
	mov r4,r1					// store hash[]
	adr r5,kstates				// load kstates address
	eor r12,r12					// loop index

	// push a-h on stack
	ldr r6,[r4]					// load a=H[0]
	push {r6}					// push on stack
	add r4,#0x4					// next word
	ldr r6,[r4]					// load b=H[1]
	push {r6}					// push on stack
	add r4,#0x4					// next word
	ldr r6,[r4]					// load c=H[2]
	push {r6}					// push on stack
	add r4,#0x4					// next word
	ldr r6,[r4]					// load d=H[3]
	push {r6}					// push on stack
	add r4,#0x4					// next word
	ldr r6,[r4]					// load e=H[4]
	push {r6}					// push on stack
	add r4,#0x4					// next word
	ldr r6,[r4]					// load f=H[5]
	push {r6}					// push on stack
	add r4,#0x4					// next word
	ldr r6,[r4]					// load g=H[6]
	push {r6}					// push on stack
	add r4,#0x4					// next word
	ldr r6,[r4]					// load h=H[7]
	push {r6}					// push on stack

	sub r4,#0x1c

hashing:
	// T1:
	pop {r6}					// load h, can be lost
	mov r11,r6					// T1=h
	pop {r2}					// load g
	pop {r1}					// load f
	pop {r0}					// load e
	mov r6,r0					// copy e
	bl _BSIG1					// BSIG1(e)
	add r11,r0					// T1=T1+BSIG1(e)
	mov r0,r6					// restore e
	bl _CH						// CH(e,f,g)
	add r11,r0					// T1=T1+CH(e,f,g)

	ldr r7,[r5]					// load K[i]
	add r11,r7					// T1=T1+K[i]
	add r5,#0x4					// increment: K[i++]

	ldr r7,[r3]					// load W[i]
	add r11,r7					// T1=T1+W[i]
	add r3,#0x4					// increment: W[i++]

	// T2:

	// r1=f, r2=g, r6=e
	mov r8,r1					// move f to r8
	mov r9,r2					// move g to r9
	pop {r10}					// load d into r10
	pop {r2}					// load c
	pop {r1}					// load b
	pop {r0}					// load a
	push {r6}					// e on stack
	push {r8}					// f on stack
	push {r9}					// g on stack
	// stack now:
	// lr
	// e
	// f
	// g
	mov r6,r0					// copy a
	bl _BSIG0					// BSIG0(a)
	mov r9,r10					// copy d to r9
	mov r10,r0					// T2=BSIG0(a)
	mov r0,r6					// copy a to r0
	bl _MAJ						// MAJ(a,b,c)
	add r10,r0					// T2=T2+MAJ(a,b,c)
	mov r0,r6					// copy a to r0
	// now: r0=a, r1=b, r2=c, r9=d, r10=T2, r11=T1
	pop {r6}					// load g
	pop {r7}					// load f
	pop {r8}					// load e
	// now: r0=a, r1=b, r2=c, r6=g, r7=f, r8=e r9=d, r10=T2, r11=T1
	add r10,r10,r11				// a=T1+T2
	push {r10}					// store a on stack
	push {r0}					// store b=a
	push {r1}					// store c=b
	push {r8}					// store d=e
	add r11,r11,r9				// e=d+T1
	push {r11}					// store e
	push {r8}					// store f=e
	push {r7}					// store g=f
	push {r6}					// store h=g

	add r12,#0x1				// increment loop counter
	cmp r12,#0x40				// if counter = 64
	bne	hashing					// loop hash


	eor r12,r12					// loop counter for H[8]
store_hash:
	pop {r6}					// load h
	ldr r7,[r4]					// load H[i]
	add r8,r7,r6				// H[i]=H[i]+X
	str r8,[r4]					// store H[i]
	sub r4,#0x4					// H[i--]
	add r12,#0x1
	cmp r12,#0x8				// if counter != 8
	bne store_hash				// loop storing

	mov r1,r4

	pop {r0-r12,pc}*/

	push {r0-r12,lr}

	// TODO: könnte r3 noch aktiv nutzen

	// load H[i]
	ldr r2,[r1]					// load H[0]
	mov r12,r2					// r12
	add r1,#0x4					// H[i++]
	ldr r2,[r1]					// load H[1]
	mov r11,r2					// r12
	add r1,#0x4					// H[i++]
	ldr r2,[r1]					// load H[2]
	mov r10,r2					// r12
	add r1,#0x4					// H[i++]
	ldr r2,[r1]					// load H[3]
	mov r9,r2					// r12
	add r1,#0x4					// H[i++]
	ldr r2,[r1]					// load H[4]
	mov r8,r2					// r12
	add r1,#0x4					// H[i++]

	ldr r7,[r1]					// load H[5]
	add r1,#0x4					// H[i++]

	ldr r6,[r1]					// load H[6]
	add r1,#0x4					// H[i++]

	ldr r5,[r1]					// load H[7]
	add r1,#0x4					// H[i++]

	sub r1,#0x20				// H[i=0]

	adr r2,kstates				// load K[i]

	push {r1}					// H[i] on stack
	push {r0}					// tmpBuf on stack
	push {r2}					// K[i] on stack

	eor r4,r4					// r4=0, =counter

hashing:
	mov r0,r8					// r0=e
	bl _BSIG1					// BSIG1(e)
	add r5,r0					// T1=h+BSIG1(e)
	mov r0,r8					// r0=e
	mov r1,r7					// r1=f
	mov r2,r6					// r2=g
	bl _CH						// CH(e,f,g)
	add r5,r0					// T1=(h+BSIG1(e)) + CH(e,f,g)

	pop {r0}					// get K[i]
	pop {r1}					// get tmpBuf
	ldr r2,[r1]					// load tmpBuf[i]
	ldr r3,[r0]					// load K[i]
	add r5,r3					// T1=(h+BSIG1(e)) + CH(e,f,g) + K[t]
	add r5,r2					// T1=(h+BSIG1(e)) + CH(e,f,g) + K[t] + W[t]
	add r1,#0x4					// K[i++]
	add r0,#0x4					// W[i++]
	push {r1}					// tmpBuf[i] back to stack
	push {r0}					// K[i] back to stack
	push {r5}					// T1 on stack

	mov r0,r12					// r0=a
	bl _BSIG0					// BSIG0(a)
	mov r5,r0					// T2=BIS0(a)
	mov r0,r12					// r0=a
	mov r1,r11					// r1=b
	mov r2,r10					// r2=c
	bl _MAJ						// MAJ(a,b,c)
	add r5,r0					// T2=BSIG0(a)+MAJ(a,b,c)

	pop {r0}					// r0=T1
	mov r1,r5					// r1=T2


	mov r5,r6					// h=g
	mov r6,r7					// g=f
	mov r7,r8					// f=e
	mov r8,r9					// e=d...
	add r8,r0					// e=d+T1
	mov r9,r10					// d=c
	mov r10,r11					// c=b
	mov r11,r12					// b=a
	mov r12,r0					// a=T1..
	add r12,r1					// a=T1+T2

	add r4,#0x1					// counter++

	cmp r4,#0x40				// if counter==64
	bne hashing					// loop


	pop {r0}					// delete k[i] from stack
	pop {r0}					// delete tmpBuf from stack
	pop {r0}					// get H[0]

	ldr r1,[r0]					// load H[0]
	add r1,r12					// add a
	str r1,[r0]					// store H[0]=H[0]+a
	add r0,#0x4					// H[i++]

	ldr r1,[r0]					// load H[1]
	add r1,r11					// add b
	str r1,[r0]					// store H[1]=H[1]+b
	add r0,#0x4					// H[i++]

	ldr r1,[r0]					// load H[2]
	add r1,r10					// add c
	str r1,[r0]					// store H[2]=H[2]+c
	add r0,#0x4					// H[i++]

	ldr r1,[r0]					// load H[3]
	add r1,r9					// add d
	str r1,[r0]					// store H[3]=H[3]+d
	add r0,#0x4					// H[i++]

	ldr r1,[r0]					// load H[4]
	add r1,r8					// add e
	str r1,[r0]					// store H[4]=H[4]+e
	add r0,#0x4					// H[i++]

	ldr r1,[r0]					// load H[5]
	add r1,r7					// add f
	str r1,[r0]					// store H[5]=H[5]+f
	add r0,#0x4					// H[i++]

	ldr r1,[r0]					// load H[6]
	add r1,r6					// add g
	str r1,[r0]					// store H[6]=H[6]+g
	add r0,#0x4					// H[i++]

	ldr r1,[r0]					// load H[7]
	add r1,r5					// add h
	str r1,[r0]					// store H[7]=H[7]+h
	add r0,#0x4					// H[i++]

	pop {r0-r12,pc}


kstates:
.word 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

hstart:
.word 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
