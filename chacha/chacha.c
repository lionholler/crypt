#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include "h/cha.h"


#define ROTL32(u32, n) u32 = (u32 << n) | (u32 >> (32 - n))

enum f{ENCRYPT, DECRYPT, PASSPHRASE, NONCE, OFFSET, SPLIT};

const uint32_t K[4] = {0x65787061, 0x6e642033, 0x322d6279, 0x7465206b};

static void quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
	*a += *b; *d ^= *a; ROTL32(*d, 16);
	*c += *d; *b ^= *c; ROTL32(*b, 12);
	*a += *b; *d ^= *a; ROTL32(*d, 8 );
	*c += *d; *b ^= *c; ROTL32(*b, 7 );
}

static void scramble_column(uint32_t *m) {
	quarter_round(&m[0], &m[4], &m[8 ], &m[12]);
	quarter_round(&m[1], &m[5], &m[9 ], &m[13]);
	quarter_round(&m[2], &m[6], &m[10], &m[14]);
	quarter_round(&m[3], &m[7], &m[11], &m[15]);
}

static void scramble_diagonal(uint32_t *m) {
	quarter_round(&m[0], &m[5], &m[10], &m[15]);
	quarter_round(&m[1], &m[6], &m[11], &m[12]);
	quarter_round(&m[2], &m[7], &m[8 ], &m[13]);
	quarter_round(&m[3], &m[4], &m[9 ], &m[14]);
}

static uint32_t *cpyblock(const uint32_t *b) {
	uint32_t *new_block = (uint32_t *) malloc(16);
	for (int i = 0; i < 16; i++) {
		new_block[i] = b[i];
	}
	return new_block;
}

static void block_addition(uint32_t *b, const uint32_t *ob) {
	for (int i = 0; i < 16; i++) {
		b[i] += ob[i];
	}
}

uint32_t u8tou32(uint8_t *b8, const int s, const int lim) {
	uint32_t u32t = b8[s];
	for (int i = 1; i < 4; i++) {
		u32t = (s+i > lim) ? (u32t << 8) + 0x00 : (u32t << 8) + b8[s+i];
	}
	return u32t;
}

static int strlenu8(const uint8_t *m) {
	int i = 0;
	while (*m++ != '\0')
		i++;
	return i;
}

int init_block(uint32_t *block) {
	int i;
	for (i = 0; i < 4; i++) {
		block[i] = K[i];
	}
	return i;
}

void chacha_encrypt(uint32_t *p, uint32_t *b, uint32_t *c) {
	for (int i = 0; i < 16; i++) {
		c[i] = *p++ ^ *b++;
	}
}

void chacha_decrypt(uint32_t *p, uint32_t *b, uint32_t *c) {
	for (int i = 0; i < 16; i++) {
		p[i] = *c++ ^ *b++;
	}
}

static void printhex(uint32_t *c, const short debug, const short lb) {
	for (int i = 0; i < 16; i++) {
		if (!(i%4) && i != 0 && lb)
			printf("\n");
		if (debug)
			printf("0x");
		printf("%08" PRIx32, c[i]);
		if (debug)
			printf(" ");
	}
	if (lb)
		printf("\n");
}

static void printp(uint32_t *p) { // print plain text u8 ascii
	uint8_t print[65], i;
	for (i = 0; i < 64; p++) {
		for (short j = 3; j >= 0; j--) {
			print[i++] = (uint8_t) (*p >> 8*j);
		}
	}
	print[i] = '\0';
	printf("%s", print);
}


int main(int argc, char* argv[]) {

	char *message, *key_s, *cipher_s;
	uint64_t nonce = 123123123123; // default nonce
	uint64_t offset = 0;
	int offset_adjust = 0;

	uint8_t flag = 0;

	if (argc < 2) {
		printf("error: too few arguments specified \n");
		return -1;
	} else {
		for (int i = 1; i < argc; i++) {
			if (*(argv[i]) == '-') {
				switch (*(++argv[i])) {
					case 'e':
						message = argv[i+1];
						flag = activate_bit(flag, ENCRYPT);
						break;
					case 'd':
						cipher_s = argv[i+1];
						flag = activate_bit(flag, DECRYPT);
						break;
					case 'p':
						key_s = argv[i+1];
						flag = activate_bit(flag, PASSPHRASE);
						break;
					case 'n':
						nonce = atoi(argv[i+1]);
						flag = activate_bit(flag, NONCE);
						break;
					case 'o': // offset
						if (!check_bit_mask(flag, DECRYPT)) {
							printf("error: -n can only be used after -d flag \n");
							return -1;
						}
						offset = atoi(argv[i+1]);
						if (*(++argv[i]) == 's') { //split
							offset_adjust = offset;
							flag = activate_bit(flag, SPLIT);
						} else if (offset > strlenu8((uint8_t *) cipher_s) / 128 - 1) { 
							printf("error: offset out of bounds \n");
							return -1;
						}
						flag = activate_bit(flag, OFFSET);
						break;
					case 'h':
						printf("Usage:\n\tencrypt:\t%s -e <message> -p <passphrase> -n <nonce>\n\tdecrypt:\t%s -d <ciphertext> -p <passphrase> -n <nonce>\n\n\t-e\tencryption flag, must be followed by message to encrypt\n\t\ttype: ascii string\n\t-d\tdecryption flag, must be followed by ciphertext to decrypt\n\t\ttype: hex string\n\t-p\tpassphrase flag, max length is 8 bytes/64 bits\n\t\ttype: ascii string\n\t-n\t(optional) nonce flag, default value: %llu, max 64 bit int\n\t-o\t(optional) offset flag, allows to offset to a certain block, must be an int\n\t-os\t(optional) combines offset with split flag, allows to feed cipher in parts, must be an int\n\n", argv[0], argv[0], nonce);
						return 0;
					default:
						printf("error: unknown flag specified \n");
						return -1;
				}
			}
		}
	}

	if (!check_bit_mask(flag, PASSPHRASE)) {
		printf("error: no passphrase specified \n");
		return -1;
	}
	if (!check_bit_mask(flag, NONCE))
		printf("info: nonce not specified, using default nonce: %llu \n\n", nonce);

	short i, outofkey = 0, outofmessage, outofciphertext;
	int nblocks;

	uint32_t b[16], key[8];
	uint32_t cipher[16], plain[16];

	for (i = 0; i < 8; i++) { // key from 8 bit to 32 bit
		if (!outofkey && i*4 > strlenu8((uint8_t *) key_s)) {
			outofkey = 1;
		}
		key[i] = (outofkey) ? 0x00 : u8tou32((uint8_t *) key_s, i*4, strlenu8((uint8_t *) key_s));
	}

	i = init_block(b);

	for (; i < 12; i++) { // add key
		b[i] = key[i-4];
	}

	for (; i < 16; i++) { // add nonce
		b[i] = (uint32_t) (nonce >> 32*(i-14));
	}

	// main block work done

	short mpos;
	uint64_t r;

	// let's encrypt
	if (check_bit_mask(flag, ENCRYPT)) {
		nblocks = (strlenu8((uint8_t *) message) + 63) / 64; // how many rounds/blocks?

		for (r = 0, mpos = 0; r < nblocks; r++) {
			outofmessage = 0;

			for (short i = 12; i < 14; i++) { // add counter
				b[i] = (uint32_t) (r >> 32*(i-12));
			}

			uint32_t *orig_block = cpyblock(b);
		
			for (short i = 0; i < 10; i++) { // 20 rounds
				scramble_column(b);
				scramble_diagonal(b);
			}

			block_addition(b, orig_block);
			free(orig_block);

			for (int j = 0; mpos < 16 * (r+1); mpos++, j++) { //message from 8 bit to 32 bit
				if (!outofmessage && mpos*4 > strlenu8((uint8_t *) message)) {
					outofmessage = 1;
				}
				plain[j] = (outofmessage) ? 0x00 : u8tou32((uint8_t *) message, mpos*4, strlenu8((uint8_t *) message));
			}

			chacha_encrypt(plain, b, cipher); // encrypt and put in cipher[]

			printhex(cipher, 0, 0);
		}
		printf("\n");
		return 0; // end of encryption
	}

	// let's decrypt 
	if (check_bit_mask(flag, DECRYPT)) {
		nblocks = strlenu8((uint8_t *) cipher_s) / 128 + offset_adjust;

		for (r = 0; r < nblocks; r++) {
			outofciphertext = 0;

			(r >= offset) ? parsehex(cipher_s, cipher) : NULL;
			if (!check_bit_mask(flag, SPLIT) || r >= offset) {
				cipher_s += 128;
			} 

			for (short i = 12; i < 14; i++) { // add counter
				b[i] = (uint32_t) (r >> 32*(i-12));
			}

			uint32_t *orig_block = cpyblock(b);
		
			for (short i = 0; i < 10; i++) { // 20 rounds
				scramble_column(b);
				scramble_diagonal(b);
			}

			block_addition(b, orig_block);
			free(orig_block);

			if (check_bit_mask(flag, OFFSET) && r < offset) 
				continue;

			chacha_decrypt(plain, b, cipher); // decrypt and put in plain[]

			printp(plain);
		}
		printf("\n");

		return 0; // end of decryption
	}

	printf("Prorgam unexpected exit -2 return code \n");
	return -2; // unexpected return
}
