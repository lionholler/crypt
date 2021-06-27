
#define min(a, b) (a > b) ? a : b
#define max(a, b) (a > b) ? a : b

static void populate(uint32_t *c) {
	for (int i = 0; i < 16; i++) {
		*c++ = 0x00;
	}
}

static int hextoint(const char c) {
	return (c < 58) ? c - '0' : c - 87;
}

static unsigned long long pow(const int b, const int n) {
	unsigned long long p = 1;
	for (int i = 0; i < n; i++) {
		p *= b;
	}
	return p;
}

void parsehex(const char *s, uint32_t *c) {
	populate(c);
	for (int j = 0; j < 16; s+=8, j++) {
		for (int i = 0; i < 8; i++) {
			c[j] += hextoint(s[i]) * pow(16, 7 - i);
		}
	}
}

/* flag manipulations */
uint8_t activate_bit(const uint8_t b, const short n) {
// activate a bit at the nth position
	return b | (1 << n);
}	

int check_bit_mask(const uint8_t b, const short n) {
// check if bit at nth position is active
	return b & (1 << n);
}
