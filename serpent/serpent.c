#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "h/serpent.h"


#define B32 32
#define FRAC 0x9e3779b9
#define ROTL(A, n) (A << n) | (A >> (32 - n))

void printhex(uint32_t);
void printascii(uint32_t);
void copyu324(uint32_t *, uint32_t *);

static void init_key(const char *K, uint32_t *k) {
	unsigned short i, j, eok = 0;
	for (i = 0; i < 8; i++) {
		for (j = 0; j < 4; j++, K++) {
			if (!eok && *K == '\0') {
				eok = 1;
				k[i] = (k[i] << 8) | 0x80;
				continue;
			}
			k[i] = (k[i] << 8) | ((eok) ? 0x00 : *K);
		}
	}
}

static void w(uint32_t *w) { /* key schedule: get words */
	for (unsigned short i = 8; i < 140; i++) {
		w[i] = ROTL((w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ FRAC ^ (i - 8)), 11);
	}
}

static uint8_t glue(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3) {
	return b0 | (b1 << 1) | (b2 << 2) | (b3 << 3);
}

static uint8_t mask(uint32_t b, uint8_t p) {
	return (uint8_t) ((b >> p) & 0x1);
}

static void k(uint32_t *w, uint32_t (*sk)[4]) { /* key schedule: get subkeys */

	uint8_t i, p, j, s, k;
	uint32_t K[132] = {0x0};

	for (i = 0; i < 33; i++) {
		p = (32 + 3 - i) % 32;
		for (k = 0; k < 32; k++) {
			s = S[p][glue (	mask(w[ 0 + i + 8], k),
					mask(w[33 + i + 8], k),
					mask(w[66 + i + 8], k),
					mask(w[99 + i + 8], k))];
			for (j = 0; j < 4; j++) {
				K[33 * j + i] |= ((s >> j) & 0x1) << k;
			}
		}
	}

	for (i = 0; i < 33; i++) {
		for (j = 0; j < 4; j++) {
			sk[i][j] = K[4 * i + j];
		}
	}
	CLEARMEM(K, 132); /* clear K mem */
}

static void ip(const uint32_t *in, uint32_t *out) { /* initital permutation */
	uint8_t i, r;
	out[0] |= in[0] & 0x1;
	out[3] |= ((in[3] >> 31) & 0x1) << 31;
	for (i = 1; i < 127; i++) {
		r = (32 * i) % 127;
		out[i/B32] |= ((in[r/B32] >> (r % B32)) & 0x1) << (i % B32);
	}
}

static void fp(const uint32_t *in, uint32_t *out) { /* final permutation */
	uint8_t i, r;
	out[0] |= in[0] & 0x1;
	out[3] |= ((in[3] >> 31) & 0x1) << 31;
	for (i = 1; i < 127; i++) {
		r = (4 * i) % 127;
		out[i/B32] |= ((in[r/B32] >> (r % B32)) & 0x1) << (i % B32);
	}
}

static void set(uint32_t *v, const uint32_t x) {
	for (short i = 0; i < 4; v++, i++) {
		*v = x;
	}
}

static uint8_t getb(const uint32_t *b, const uint8_t p) {
// get value of bit at position p of 32-bit u_int b
	return (b[p/B32] >> (p % B32)) & (uint32_t) 0x1;
}

static void setb(uint32_t *x, const uint8_t p, const uint8_t b) {
// set bit at position p, if 8-bit u_int b is active
	if (b) {
		x[p/B32] |=  ((uint32_t) 0x1 << (p % B32));
	} else {
		x[p/B32] &= ~((uint32_t) 0x1 << (p % B32));
	}
}

void serpent_encrypt(const char *_k, const uint32_t *_m, uint32_t *C) {

	uint32_t words[140];
	uint32_t _subkey[33][4], subkey[33][4] = {0x0};
	uint32_t m[4] = {0x0};

	/* key schedule */
	init_key(_k, words); // initialize key; padd if necessary

	w(words);
	k(words, _subkey);
	CLEARMEM(words, 140); /* clear words mem */

	/* initial permutation on key */
	for (short i = 0, j = 0; i < 33; i++, j++) {
		ip(_subkey[i], subkey[i]);
		CLEARMEM(_subkey[j], 4); /* clear pre ip subkey mem */
	}
	
	/* initial permutation on message */
	ip(_m, m);

	/* linear transformation */
	uint32_t Z[4] = {0x0};
	uint32_t X[4] = {0x0};

	copyu324(m, Z);
	CLEARMEM(m, 4); /* clear ip message mem */

	for (short r = 0; r < 32; r++) {

		uint32_t Y[4] = {0x0};

		for (short i = 0; i < 4; i++) {
			X[i] = Z[i] ^ subkey[r][i];
		}
		CLEARMEM(subkey[r], 4); /* clear subkey mem */

		for (short i = 0; i < 4; i++) {
			for (short j = 0; j < 8; j++) {
				Y[i] |= (S[r][(uint8_t) 0xf & (X[i] >> (4 * j))]) << (j * 4);
			}
		}

		if (r == 31) { // last round
			for (short i = 0; i < 4; i++) {
				Z[i] = Y[i] ^ subkey[B32][i];
			}
			CLEARMEM(Y, 4); /* clear Y mem */
		} else {
			uint8_t b;
			uint8_t p, i, d;
			for (i = 0; i < 128; i++) {
				b = 0x0;
				for (p = 0, d = 0; p < 8; p++) { // always iterate 8 times!
					if (!d) { 
						if (L[i][p] == NONE) {
							d = 1;
							continue;
						}
						b ^= getb(Y, L[i][p]);
					} else {
					// perform work as if there was a value at p
						getb(Y, 0x0); // remove? 
					}
				}
				setb(Z, i, b);
			}
		}
	}

	/* final permutation */
	uint32_t CX[4] = {0x0};

	fp(Z, CX);

	CLEARMEM(X, 4); /* clear X mem */
	CLEARMEM(Z, 4); /* clear Z mem */

	for (short i = 0; i < 4; i++) {
		C[i] = CX[i];
		printf("0x");
		printhex(C[i]);
		printf(" ");
	}
}

void counter_encrypt(const uint32_t *C, const uint32_t *min, uint32_t *COUT) {
/*  encrypt 128-bit message min using counter mode, xoring  *
 *  cipher text C from serpent encryption with  message  m  *
 *  storing the 128-bit output in COUT, C functions as key  */
	for (short i = 0; i < 4; i++) {
		COUT[i] = *C++ ^ *min++;
	}
}

void counter_decrypt(const uint32_t *C, const uint32_t *cin, uint32_t *MOUT) {
/*  decrypt 128-bit cipher text cin using counter mode, xoring  *
 *  cipher text cin with cipher text C from serpent encryption  *
 *  storing the 128-bit output in MOUT,  C  functions  as  key  */
	for (short i = 0; i < 4; i++) {
		MOUT[i] = *C++ ^ *cin++;
	}
}

void copyu324(uint32_t *from, uint32_t *to) {
	for (short i = 0; i < 4; i++) {
		*to++ = *from++;
	}
}

void printhex(uint32_t c) {
	printf("%08" PRIx32, c);
}

void printascii(uint32_t p) {
	char c;
	for (short i = 0; i < 4; i++) {
		c = (char) (p >> (24 - 8 * i));
		if (c == '\0')
			break;
		printf("%c", c);
	}
}


int main(int argc, char *argv[]) {

	char *k_in = argv[2], *m_in = argv[1];
	int mlen = strlen(m_in), klen = strlen(k_in), outlen = 0;

	uint32_t nonce[4] = {0x8648aa, 0x77ee8, 0x8648aa, 0x0};
	uint32_t m_in32[4] = {0x0};
	uint32_t COUT[10028][4] = {0x0}, MOUT[10028][4] = {0x0};

	if (argc >= 4) { //create new nonce if specified
		uint32_t x = atoi(argv[3]);
		for (short i = 0; i < 3; i++) {
			nonce[i] |= x;
			x = nonce[i];
		}
	}

	printf("\n - serpent encryption output -\n");
	for (short m = 0; m < (mlen + 15) / 16; m++) {

		for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				m_in32[i] = (m_in32[i] << 8) | ((j+(4*i) + (16 * m) > mlen) ? 0x0 : m_in[j+(4*i)]);
			}
		}

		nonce[3]++;

		uint32_t C[4], CX[4];

		//serpent_encrypt(k_in, m_in32, C);
		serpent_encrypt(k_in, nonce, C);
		printf("\n");

		counter_encrypt(C, m_in32, COUT[m]);
		
		counter_decrypt(C, COUT[m], MOUT[m]);

		CLEARMEM(m_in, 16); /* clear last 16 char of message mem */
		m_in += 16;
		++outlen;
	}

	CLEARMEM(k_in, klen); /* clear key mem */
	CLEARMEM(m_in32, 4); /* clear message mem */

	printf("\n - encrypted w/ counter -\n");
	for (int i = 0; i < outlen; i++) {
		for (int j = 0; j < 4; j++) {
			printf("0x");
			printhex(COUT[i][j]);
			printf(" ");
		}
	}
	printf("\n");

	printf("\n - decrypted w/ counter -\n");
	for (int i = 0; i < outlen; i++) {
		for (int j = 0; j < 4; j++) {
			printascii(MOUT[i][j]);
		}
	}
	printf("\n\n");

}


