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
	strncpy(temp, pt_password, strlen(pt_password));

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
BYTE* get_padded_plaintext(BYTE *pt, int len_pt) {

	int pad_size = AES_BLOCK_SIZE - (len_pt % AES_BLOCK_SIZE);  // size of pad needed
	if (pad_size == 0) {
		return pt;
	}
	printf("We need a pad of %d; we have %d.\n", pad_size, len_pt);

	BYTE *padded_pt = (BYTE*) malloc(sizeof(BYTE) * (len_pt + pad_size));
	memcpy(padded_pt, pt, len_pt);
	printf("Added bytes: %s", padded_pt);

	for (int i = 0; i < pad_size; i++) {
		int shift = len_pt + i;
		memcpy(&padded_pt[shift], &pad_size, 1);
	}

	for (size_t i = 0; i < len_pt; i++) {
		printf("%x", pt[i] & 0xff);  // trick to print out unsigned hex
	}
	printf("\n");
	for (size_t i = 0; i < len_pt + pad_size; i++) {
		printf("%x |", padded_pt[i] & 0xff);  // trick to print out unsigned hex
	}
	printf("\n");

	return padded_pt;
}

/**
 * AES takes 16 bytes (128 bits) at a time to produce 16 bytes;
 * here this is done using the ECB routine (encrypt 16 bytes at a time,
 * with constant mapping between plaintext blocks and cipher blocks)
 */
int ecb_aes_encrypt() {

	//  int n_blocks = len_plaintext / AES_BLOCK_SIZE;
	// print("%s\t", padded_pt);

	// WORD key_schedule[60];  // this is taken from implementers tests
	// BYTE buffer[len_plaintext];

	// BYTE buf_in[AES_BLOCK_SIZE], buf_out[AES_BLOCK_SIZE];
	// int n_blocks, idx;

	// key setup step performs the action of generating keys that are used in every
	// round of the encryption.
	// aes_key_setup(key, key_schedule, KEY_SIZE);

	// break up plaintext in blocks of 16 bytes and run AES on those individually
	// n_blocks = len_plaintext / AES_BLOCK_SIZE;


	// aes_encrypt(plaintext, buffer, key_schedule, KEY_SIZE);
}

/**
 *
 */
int aes_decrypt_file(char *filename) {
	return 0;
}

