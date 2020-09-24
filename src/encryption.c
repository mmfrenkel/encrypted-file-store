/*
 * encryption.c
 *
 *  Created on: Sep 23, 2020
 *      Author: meganfrenkel
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "encryption.h"
#include "aes.h"
#include "sha256.h"

/**
 * Converts key submitted by user into a 32 byte (256 bit) hash via
 * SHA-256.
 */
BYTE* convert_password_to_cryptographic_key(char *pt_password) {
	BYTE *new_hash;
	BYTE *temp;

	// make this temporary memory allocation, as to not delete original pw
	int len_pt_pw = strlen(pt_password);
	temp = (BYTE *) malloc(sizeof(unsigned char) * len_pt_pw);
	strncpy((char *) temp, pt_password, strlen(pt_password));

	// repeatedly run sha-256 hash function
	for (int i = 0; i < PW_CRYPT_ITER; i++) {
		if (!(new_hash = hash_sha_256(temp, len_pt_pw))) {
			printf("Unable to create cryptographic key from submitted password\n");
			exit(1);
		}
		free(temp);  // free memory allocated to older version of hash
		temp = new_hash;
	}

    for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++) {
    	printf("%x", temp[i] & 0xff);  // trick to print out unsigned hex
    }
    printf("\n");
	return temp;
}

/**
 *  Setup modeled from source test examples by Brad Conte here:
 *  https://github.com/B-Con/crypto-algorithms/blob/master/sha256_test.c
 */
BYTE* hash_sha_256(BYTE *text, int len_pt) {

	BYTE *buffer = (BYTE *) malloc(sizeof(BYTE) * SHA256_BLOCK_SIZE);
	if (!buffer) {
		printf("Could not perform SHA256 hash function because buffer could "
				"not be allocated.\n");
		return NULL;
	}

	SHA256_CTX ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, text, len_pt);
	sha256_final(&ctx, buffer);

	return buffer;
}

/**
 *
 */
BYTE* create_padded_plaintext(BYTE *pt, int len_pt) {

	int pad_size = AES_BLOCK_SIZE - (len_pt % AES_BLOCK_SIZE);  // size of pad needed

	printf("We need a pad of %d; we have %d.\n", pad_size, len_pt);

	BYTE *padded_pt = (BYTE*) malloc(sizeof(BYTE) * (len_pt + pad_size));
	memcpy(padded_pt, pt, len_pt);

	for (int i = 0; i < pad_size; i++) {
		int shift = len_pt + i;
		memcpy(&padded_pt[shift], &pad_size, 1);
	}

	for (int i = 0; i < len_pt; i++) {
		printf("%x", pt[i] & 0xff);  // trick to print out unsigned hex
	}
	printf("\n");
	for (int i = 0; i < len_pt + pad_size; i++) {
		printf("%x |", padded_pt[i] & 0xff);  // trick to print out unsigned hex
	}
	printf("\n");

	return padded_pt;
}

/**
 * AES takes 16 bytes (128 bits) at a time to produce 16 bytes;
 * here this is done using the ECB routine (encrypt 16 bytes at a time,
 * with constant mapping between plaintext blocks and cipher blocks).
 *
 * First adds padding (in the form of the number of padding chars added),
 * then runs AES over each section of bytes.
 */
BYTE* ecb_aes_encrypt(BYTE *plaintext, int len_pt, BYTE *key) {

	BYTE *padded_plaintext = create_padded_plaintext(plaintext, len_pt);

	// figure out how many blocks (iterations of AES we need)
	int n_blocks = len_pt / AES_BLOCK_SIZE;
	n_blocks = len_pt % AES_BLOCK_SIZE != 0 ? n_blocks + 1 : n_blocks;

	/* --- setup --- */
	WORD key_schedule[60];                            // taken from implementers tests
	int ciphertext_size = n_blocks * AES_BLOCK_SIZE;

	BYTE buf_in[AES_BLOCK_SIZE], buf_out[AES_BLOCK_SIZE];
	BYTE *ciphertext = (BYTE *) malloc(sizeof(BYTE) * ciphertext_size);

	// key setup step performs generates keys that are used in encryption rounds
	aes_key_setup(key, key_schedule, KEY_SIZE);

	/** --- do the thing --- **/
	for (int i = 0; i < n_blocks; i++) {

		// copy next block into buf_in; this will be encrypted
		memcpy(buf_in, &padded_plaintext[i * AES_BLOCK_SIZE], AES_BLOCK_SIZE);

		// AES step, saving to buf_out
		aes_encrypt(buf_in, buf_out, key_schedule, KEY_SIZE);

		// move the results of buf_out into the final
		memcpy(&ciphertext[i * AES_BLOCK_SIZE], buf_out, AES_BLOCK_SIZE);
	}


	for (int i = 0; i < ciphertext_size; i++) {
		printf("%x |", ciphertext[i] & 0xff);  // trick to print out unsigned hex
	}
	printf("\n");
	printf("Length of ciphertext: %lu\n", strlen((char *) ciphertext));
	return ciphertext;
}

/**
 * Decrypts AES ciphertext.
 */
BYTE* ecb_aes_decrypt(BYTE *ciphertext, BYTE *key) {

	// figure out how many blocks (iterations of AES we need)
	int n_blocks = strlen((char*) ciphertext) / AES_BLOCK_SIZE;

	/* --- setup --- */
	WORD key_schedule[60];
	int plaintext_size = n_blocks * AES_BLOCK_SIZE;

	BYTE buf_in[AES_BLOCK_SIZE], buf_out[AES_BLOCK_SIZE];
	BYTE *plaintext = (BYTE *) malloc(sizeof(BYTE) * plaintext_size);

	// key setup step performs generates keys that are used in encryption rounds
	aes_key_setup(key, key_schedule, KEY_SIZE);

	/** --- do the thing --- **/
	for (int i = 0; i < n_blocks; i++) {

		// copy next block into buf_in; this will be encrypted
		memcpy(buf_in, &ciphertext[i * AES_BLOCK_SIZE], AES_BLOCK_SIZE);

		// AES step, saving to buf_out
		aes_decrypt(buf_in, buf_out, key_schedule, KEY_SIZE);

		// move the results of buf_out into the final
		memcpy(&plaintext[i * AES_BLOCK_SIZE], buf_out, AES_BLOCK_SIZE);
	}


	for (int i = 0; i < plaintext_size; i++) {
		printf("%x |", plaintext[i] & 0xff);  // trick to print out unsigned hex
	}
	printf("\n");
	printf("DECRYPTED PLAINTEXT: %s\n", plaintext);

	return plaintext;
}


/**
 *
 */
int aes_decrypt_file(char *filename) {
	return 0;
}
