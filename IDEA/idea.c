#include <stdio.h>
#include <inttypes.h>


typedef struct {
	uint16_t x0, x1, x2, x3;
} plain;

typedef struct {
	uint64_t b0;
	uint64_t b1;
} uint128_t;

#define PRIME_2161 65537


void printb(uint16_t n) {
	for (int i = 15; i >= 0; i--) {
		if (n & (0x1 << i)) {
			printf("1");
		} else 
			printf("0");
	}
	printf("\n");
}

void split_plain(uint64_t plain64, plain *p) {
	p->x3 |=  plain64;
	p->x2 |= (plain64 >> 16);
	p->x1 |= (plain64 >> 32);
	p->x0 |= (plain64 >> 48);
}

void split_key(uint128_t *key128, uint16_t *k, short r) {
	for (int i = r * 8; i < r * 8 + 8; i++) {
		if (r > 5 && i > 52)
			k[i] = 0x00;
		else if (i < r * 8 + 4)
			k[i] = (key128->b0 >> (3 - i) * 16);
		else
			k[i] = (key128->b1 >> (3 - i) * 16);
	}
}

void rotl25(uint128_t *key128) {
	uint64_t t = key128->b0 & 0xffffff8000000000;
	key128->b0 = (key128->b0 << 25) | ((key128->b1 & 0xffffff8000000000) >> 39);
	key128->b1 = (key128->b1 << 25) | (t >> 39);
}

void gen_subkeys(uint16_t *k, uint128_t key128) {
	for (int i = 0; i < 7; i++) {
		split_key(&key128, k, i);
		rotl25(&key128);
	}
}

uint16_t add_mod216(uint16_t a, uint16_t b) {
	return (a + b); //% 65536; overflow handles mod 216
}

uint16_t mul_mod217(register uint16_t a, register uint16_t b) {

	register uint32_t p;
	register uint16_t h, l;

	if (a == 0)
		return -b + 1;

	else if (b == 0)
		return -a + 1;

	p = (uint32_t) a * b;
	h = p >> 16;
	l = p;
 
	return l - h + (l < h);
}

uint16_t sub_mod216(uint16_t a, uint16_t b) {
	return (a - b); // % 65536;
}

uint16_t div_mod217(uint32_t a, uint32_t b) {

	register int _b, tmp, q, x, y;
	_b = b;
	x = 0;
	y = 1;

	if (!b)
		return 0;

	if (a <= 1)
		return a;

	while (a > 1) {
		q = a / b;
		tmp = b;

		b = a % b;
		a = tmp;

		tmp = x;
		x = y - q * x;
		y = tmp;
	}

	if (y < 0)
		y += _b;

	return y;
}

void key_schedule_full_round(plain *p, uint16_t *k) {

	register uint16_t r0, r1, r2, r3, r4, r5, t0, t1;

	r0 = mul_mod217(p->x0, k[0]); // X1 * K1	1
	r1 = add_mod216(p->x1, k[1]); // X2 + K2 	2
	r2 = add_mod216(p->x2, k[2]); // X3 + K3 	3
	r3 = mul_mod217(p->x3, k[3]); // X4 * K4 	4

	t0 = r0 ^ r2; //			5
	t1 = r1 ^ r3; //			6

	r4 = mul_mod217(t0, k[4]);  //			7
	r5 = add_mod216(t1, r4  );  //			8
	r5 = mul_mod217(r5, k[5]);  //			9
	r4 = add_mod216(r4, r5  );  //			10

	p->x0 = r5 ^ r0;  //			11
	p->x1 = r4 ^ r1;  //			12
	p->x2 = r5 ^ r2;  //			13
	p->x3 = r4 ^ r3;  //			14

	t0    = p->x1;   // swap
	p->x1 = p->x2;
	p->x2 = t0;
}

void key_schedule_half_round(plain *p, uint16_t *k) {

	uint16_t ____t;
	____t = p->x1;

	p->x0 = mul_mod217(p->x0, k[0]); 		// X1 * K1	1
	p->x1 = add_mod216(p->x2, k[1]); 		// X3 + K2 	2 (undo last swap)
	p->x2 = add_mod216(____t, k[2]);		// X2 + K3 	3
	p->x3 = mul_mod217(p->x3, k[3]);		// X4 * K4 	4	
}

void invert_subkeys(uint16_t *subkeys, uint16_t *isubkeys) {

	isubkeys[0] = div_mod217(subkeys[48], PRIME_2161);
	isubkeys[1] = -subkeys[49];
	isubkeys[2] = -subkeys[50];
	isubkeys[3] = div_mod217(subkeys[51], PRIME_2161);

	for (int i = 4; i < 52; i += 6) {
		isubkeys[i    ] = subkeys[52 - i - 2];
		isubkeys[i + 1] = subkeys[52 - i - 1];

		isubkeys[i + 2] = div_mod217(subkeys[52 - i - 6], PRIME_2161);
		isubkeys[i + 3] = -subkeys[52 - i - ((i == 46) ? 5 : 4)];
		isubkeys[i + 4] = -subkeys[52 - i - ((i == 46) ? 4 : 5)];
		isubkeys[i + 5] = div_mod217(subkeys[52 - i - 3], PRIME_2161);
	}
}

void idea_encrypt(plain *p, uint16_t *skptr) {

	for (int r = 0; r < 9; r++) {
		if (r == 8) {
			key_schedule_half_round(p, skptr);
		} else {
			key_schedule_full_round(p, skptr);
			skptr += 6;
		}
	}
}

void idea_decrypt(plain *p, uint16_t *sk, uint16_t *iskptr) {

	invert_subkeys(sk, iskptr);
	
	for (int r = 0; r < 9; r++) {
		if (r == 8) {
			key_schedule_half_round(p, iskptr);
		} else {
			key_schedule_full_round(p, iskptr);
			iskptr += 6;
		}
	}
}

int main() {

	plain p = {0x0, 0x0, 0x0, 0x0};

	uint128_t test = {17029236090990592u, 340280075381581500u};

	printf("\nKEY: \n");
	printf("%llu %llu\n", test.b0, test.b1);
	printf("%08llX %08llX\n", test.b0, test.b1);
	printf("\n");

	uint16_t subkeys[56], isubkeys[52];
	uint16_t *skptr = subkeys, *iskptr = isubkeys;
	gen_subkeys(subkeys, test);

	split_plain(4752452479604228900u, &p);

	printf("INPUT DATA\n");
	printf("%04X %04X %04X %04X\n", p.x0, p.x1, p.x2, p.x3);
	printb(p.x0);
	printb(p.x1);
	printb(p.x2);
	printb(p.x3);
	printf("\n");

	idea_encrypt(&p, skptr);
  
	printf("ENCRYPTED DATA\n");
	printf("%04X %04X %04X %04X\n", p.x0, p.x1, p.x2, p.x3);
	printb(p.x0);
	printb(p.x1);
	printb(p.x2);
	printb(p.x3);
	printf("\n");

	idea_decrypt(&p, subkeys, iskptr);

	printf("DECRYPTED DATA\n");
	printf("%04X %04X %04X %04X\n", p.x0, p.x1, p.x2, p.x3);
	printb(p.x0);
	printb(p.x1);
	printb(p.x2);
	printb(p.x3);
	printf("\n");

	return 0;
}
