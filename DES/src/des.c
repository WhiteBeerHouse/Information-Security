#include "des.h"

const int LS[16] = {1,  1,  2,  2,  2,  2,  2,  2,  1,  2,  2,  2,  2,  2,  2,  1};

uint64_t initial_displace(uint64_t M) {
	uint64_t M0 = 0;
	for (int i = 0; i < 64; ++i) {
		M0 = M0 << 1;
		M0 |= (M >> (64 - IP[i])) & UNIT64;
	}
	return M0;
}

void generate_subkey(uint64_t K) { // OK!
	uint64_t pre_K = 0;
	uint32_t pre_C = 0, pre_D = 0;
	uint32_t cur_C, cur_D;

	for (int i = 0; i < 56; ++i){
		pre_K = pre_K << 1;
		pre_K |= (K >> (64 - PC1[i])) & UNIT64;
	}
	pre_C = (uint32_t)((pre_K >> 28) & GET_INT28); //C0
	pre_D = (uint32_t)(pre_K & GET_INT28); //D0

	for (int i = 0; i < 16; ++i) {
		int n = LS[i];
		cur_C = ((pre_C << n) & 0x0fffffff)|(pre_C >> (28-n)); //循环左移 n 位
		cur_D = ((pre_D << n) & 0x0fffffff)|(pre_D >> (28-n));

		uint64_t CD = 0;
		CD |= cur_C;
		CD <<= 28;
		CD |= cur_D;

		subkey[i] = 0;
		for (int j = 0; j < 48; ++j) {
			subkey[i] = subkey[i] << 1;
			subkey[i] |= (CD >> (56 - PC2[j])) & UNIT64;
		}

		pre_C = cur_C;
		pre_D = cur_D;
	}
}

uint8_t S_transform(int index, uint8_t input) {	
	int col = (int)((input >> 1) & 0b00001111);
	int row = ((input >> 5) << 1) | (input & 0b00000001);
	return (uint8_t)(S[index][row*16+col]);
}

uint64_t feistel(int index, uint32_t R) { // OK!
	uint64_t expanded = 0; //48 bits
	for (int i = 0; i < 48; ++i) {
		expanded = expanded << 1;
		expanded |= (R >> (32 - E[i])) & UNIT64;
	}

	expanded ^= subkey[index];

	uint32_t P_input = 0;
	/* S box */
	for (int i = 0; i < 8; ++i) {
		uint8_t S_input = (uint8_t)(expanded & 0x000000000000003f); //6 bits
		expanded = expanded >> 6;
		P_input |= ((uint32_t)S_transform(8-i-1, S_input)) << (4*i); // lowest 8 bits with S8
	}

	uint32_t P_output = 0;
	for (int i = 0; i < 32; ++i) {
		P_output = P_output << 1;
		P_output |= (P_input >> (32 - P[i])) & UNIT32;// 32 or 64?
	}
	return P_output;
}

uint64_t iteration(uint32_t L0, uint32_t R0, int flag) { //flag 0 represents encryption, flag 1 represents decryption
	uint32_t pre_L = L0, pre_R = R0;
	uint32_t cur_L, cur_R;
	for (int i = 0; i < 16; ++i){
		cur_L = pre_R;
		if (flag == 0)
			cur_R = pre_L ^ feistel(i, pre_R);
		else 
			cur_R = pre_L ^ feistel(16-i-1, pre_R);

		pre_L = cur_L;
		pre_R = cur_R;
	}
	return ((uint64_t)cur_L << 32) | (uint64_t)cur_R;
}

uint64_t swap_displace(uint64_t LR) {
	uint64_t RL = 0;
	RL |= (LR & GET_INT32);//LR's low 32 bits
	RL = RL << 32;
	LR = LR >> 32;
	RL |= (LR & GET_INT32);//LR's high 32 bits
	return RL;
}

uint64_t inverse_displace(uint64_t W) {
	uint64_t C = 0;
	for (int i = 0; i < 64; ++i) {
		C = C << 1;
		C |= (W >> (64 - IP_INV[i])) & UNIT64;
	}
	return C;
}

uint64_t des(uint64_t input, uint64_t K, int flag) {
    generate_subkey(K);
	uint64_t output = 0;
	output = initial_displace(input); // OK!
	uint32_t L0 = (uint32_t)((output >> 32) & GET_INT32), R0 = output & GET_INT32; // OK!
	output = iteration(L0, R0, flag); // OK!
	output = swap_displace(output); // OK!
	output = inverse_displace(output); // OK!
	return output;
}

uint64_t to_uint64_t(uint8_t buf[]) {
	uint64_t res = 0;
	for (int i = 0; i < 8; ++i) {
		res = res << 8;
		res |= (uint64_t)(buf[i] & 0xff);
	}
	return res;
}

void to_uint8_t(uint64_t output, uint8_t * buf) {
	for (int i = 7; i >= 0; --i) {
		buf[i] = output & 0xff;
		output = output >> 8;
	}
	return;
}

int parity_count(uint8_t arg) {
	int count = 0;
	for (int i = 0; i < 8; ++i) {
		if (arg & 0x01)	count++;
		arg = arg >> 1;
	}
	return count;
}

uint64_t generate_key() {
	uint64_t K = 0;
	for (int i = 0; i < 8; ++i) {
		K = K << 8;
		uint8_t _8bits = rand() & 0xfe;
		K |= (uint64_t)(_8bits);
		if (parity_count(_8bits) % 2)	//odd
			K |= (uint64_t)0;
		else							//even
			K |= (uint64_t)1;
	}
	return K;
}