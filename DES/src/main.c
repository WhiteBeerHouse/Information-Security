#include "des.h"

int main(int argc, char *argv[]) { // ./des input.txt output.txt -e
	if ((argc != 4) || (strcmp(argv[3], "-e") != 0 && strcmp(argv[3], "-d") != 0)) {
		printf("Command should be like: ./des [input file][output file][-e | -d]\n");
		return 0;
	}

	FILE *Input = fopen(argv[1], "rb");
	if (!Input) {
		perror(argv[1]);
		return 0;
	}

	FILE *Output = fopen(argv[2], "wb");
	if (!Output) {
		perror(argv[2]);
		return 0;
	}

	/* generate a key*/
	time_t t;
	srand((unsigned) time(&t));
	uint64_t K;

	FILE *Key_file = fopen("key.txt", "rb");
	if (!Key_file) {
		Key_file = fopen("key.txt", "wb");
		K = generate_key();
		uint8_t kbuf[8];
		to_uint8_t(K, kbuf);
		fwrite(kbuf, sizeof(uint8_t), 8, Key_file);
	}
	else {
		uint8_t kbuf[8];
		fread(kbuf, sizeof(uint8_t), 8, Key_file);
		K = to_uint64_t(kbuf);
	}
	fclose(Key_file);

	/* if encrypt */
	if (strcmp(argv[3], "-e") == 0) {
		int rlen = 0;
		while(1) {
			uint8_t rbuf[8];
			rlen = fread(rbuf, sizeof(uint8_t), 8, Input);

			if (rlen < 8 && rlen >= 0) {
				uint8_t filling = (uint8_t)(8-rlen);
				for (int i = rlen; i < 8; ++i) {
					rbuf[i] = filling;
				}
				uint64_t ciphertext = des(to_uint64_t(rbuf), K, 0);
				uint8_t wbuf[8];
				to_uint8_t(ciphertext, wbuf);
				fwrite(wbuf, sizeof(uint8_t), 8, Output);
				break;			
			}
			else if (rlen == 8){
				uint64_t ciphertext = des(to_uint64_t(rbuf), K, 0);
				uint8_t wbuf[8];
				to_uint8_t(ciphertext, wbuf);
				fwrite(wbuf, sizeof(uint8_t), 8, Output);
			}
			else {
				perror("Error");
			}
		}
	}
	/* if decrypt */
	else if (strcmp(argv[3], "-d") == 0) {
		int rlen = 0;
		uint8_t rbuf[8];
		rlen = fread(rbuf, sizeof(uint8_t), 8, Input);
		if (rlen != 8) {
			printf("Error: Something wrong happened when reading the ciphertext.\n");
			return 0;
		}
		uint64_t decipher = des(to_uint64_t(rbuf), K, 1);
		uint8_t wbuf[8];
		to_uint8_t(decipher, wbuf);
		int num = 8 - (int)(wbuf[rlen-1]);

		while(1) {
			rlen = fread(rbuf, sizeof(uint8_t), 8, Input);
			if (rlen == 0) {
				fwrite(wbuf, sizeof(uint8_t), num, Output);
				break;
			}
			else if (rlen == 8) {
				fwrite(wbuf, sizeof(uint8_t), 8, Output);
				decipher = des(to_uint64_t(rbuf), K, 1);
				to_uint8_t(decipher, wbuf);
				num = 8 - (int)(wbuf[rlen-1]);
			}
			else {
				printf("Error: Something wrong happened when reading the ciphertext.\n");
				return 0;
			}
		}
	}

	fclose(Input);
	fclose(Output);
}