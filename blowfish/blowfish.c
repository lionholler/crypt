#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include "h/blowfish.h"

#define MAXPLAINTEXT 10024
#define swap32(A, B) {uint32_t tmp; tmp = *A; *A = *B; *B = tmp;}

uint32_t P[18] = {0x243f6a88l, 0x85a308d3l, 0x13198a2el, 0x03797344l, 0xa4093822l, 0x299f31d0l, 
									0x082efa98l, 0xec4e6c89l, 0x452821e6l, 0x38d01377l, 0xbe5466cfl, 0x34e90c6cl, 
									0xc0ac29b7l, 0xc97c50ddl, 0x3f84d5d5l, 0xb5470917l, 0x9216d5d9l, 0x8979fb1bl};

uint32_t f(uint32_t u32) {
	return (S[0][u32 >> 24] + 
		   		S[1][(uint8_t) (u32 >> 16)]) ^ 
					S[2][(uint8_t) (u32 >> 8)]   + 
		    	S[3][(uint8_t) u32];
}
static void printhex(uint64_t e) {
	printf("%08" PRIx64, e);
}

void blowfish_encrypt(uint32_t *L, uint32_t *R) {
	for (short r = 0; r < 16; r++) {
		*L = *L ^ P[r];
		*R = f(*L) ^ *R;
		swap32(L, R);
	}
	swap32(L, R);
	*R = *R ^ P[16];
	*L = *L ^ P[17];
}

void blowfish_decrypt(uint32_t *L, uint32_t *R) {
	for (short r = 17; r > 1; r--) {
		*L = *L ^ P[r];
		*R = f(*L) ^ *R;
		swap32(L, R);
	}
	swap32(L, R);
	*R = *R ^ P[1];
	*L = *L ^ P[0];
}

/* use: ./a.out <message> <key>                              *
 * decryption not yet added!                                 *
 * TODO: add funcitonailty (flags) for encryption/decryption */
int main(int argc, char *argv[]) {

	char *message = argv[1];
	char *key = argv[2];
	char plaintext[MAXPLAINTEXT];

	int message_len = strlen(message);
	int key_len = strlen(key);

	/* initialize P box w/ key */
	uint32_t k;
	for (short i = 0, p = 0; i < 18; i++) {
		k = 0x00;
		for (short j = 0; j < 4; j++) {
			k = (k << 8) | (uint8_t) key[p];
			p = (p + 1) % key_len;
		}
		P[i] ^= k;
	}

	/* blowfish key expansion (521 iterations) */
	uint32_t l = 0x00, r = 0x00;
	for (short i = 0; i < 18; i+=2) {
		blowfish_encrypt(&l, &r);
		P[i] = l; 
		P[i+1] = r;
	}
	for (short i = 0; i < 4; i++) {
		for (short j = 0; j < 256; j+=2) {
			blowfish_encrypt(&l, &r);
			S[i][j] = l;
			S[i][j+1] = r;
		}
	}

	for (int j = 0; j < (message_len + 7) / 8; j++) {
		uint64_t m = 0x00;

		/* split 8-byte message in left and right part */
		for (short i = 0; i < 4; i++) {
			l = (l << 8) | ((j * 8 + i > message_len) ? 0x00 : message[i]);
			r = (r << 8) | ((j * 8 + i > message_len) ? 0x00 : message[i+4]);
		}

		/* encrypt */
		blowfish_encrypt(&l, &r);

		printhex(((m | l) << 32) | r);

		/* decrypt */
		blowfish_decrypt(&l, &r);

		for (short i = 0; i < 8; i++) {
			plaintext[j*8+i] = (char) (i < 4) ? (l >> ((3-i) * 8)) : (r >> ((7-i) * 8));
		}

		message += 8;
	}

	printf("\n");
	printf("%s\n", plaintext);
	
	return 0;
}

