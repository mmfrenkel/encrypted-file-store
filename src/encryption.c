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
#include "file_io.h"


/* ----- methods that shouldn't be called externally ---- */

BYTE* hash_sha_256(BYTE *text, int len_pt);

BYTE* create_padded_plaintext(BYTE *pt, int len_pt, int block_size);

/* ------------------------------------------------------ */

/**
 * Converts key submitted by user into a 32 byte (256 bit) hash via
 * SHA-256.
 */
BYTE* convert_password_to_cryptographic_key(char *pt_password) {
	BYTE *new_hash;
	BYTE *temp;

	// make this temporary memory allocation, as to not delete original pw
	int len_pt_pw = strlen(pt_password);
	temp = (BYTE*) malloc(sizeof(unsigned char) * (len_pt_pw + 1));
	if (!temp) {
		printf("Failed to allocate memory for temporary hash storage.\n ");
		return NULL;
	}
	strncpy((char* ) temp, pt_password, len_pt_pw);

	// repeatedly run sha-256 hash function
	for (int i = 0; i < PW_CRYPT_ITER; i++) {
		if (!(new_hash = hash_sha_256(temp, len_pt_pw))) {
			printf("Unable to create cryptographic key from submitted password\n");
			free(temp);
			return NULL;
		}
		free(temp);      // free memory allocated to older version of hash
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
BYTE* create_padded_plaintext(BYTE *pt, int len_pt, int block_size) {

	int pad_size = block_size - (len_pt % block_size);  // size of pad needed

	printf("We need a pad of %d; we have %d.\n", pad_size, len_pt);

	BYTE *padded_pt = (BYTE*) malloc(sizeof(BYTE) * (len_pt + pad_size));
	if (!padded_pt) {
		printf("Could not create padded plaintext due to issue allocating memory.\n");
		return NULL;
	}

	memcpy(padded_pt, pt, len_pt);

	for (int i = 0; i < pad_size; i++) {
		int shift = len_pt + i;
		memcpy(&padded_pt[shift], &pad_size, 1);
	}

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
int ecb_aes_encrypt(FileContent *fcontent, BYTE *key) {

	BYTE *padded_plaintext;
	if (!(padded_plaintext = create_padded_plaintext(fcontent->plaintext,
			fcontent->n_plaintext_bytes, AES_BLOCK_SIZE))) {
		return -1;
	}

	/* ----- setup ---- */
	int n_blocks = (fcontent->n_plaintext_bytes / AES_BLOCK_SIZE) + 1;          // how many AES blocks do we need?
	int ciphertext_size = n_blocks * AES_BLOCK_SIZE;
	WORD key_schedule[60];  													// taken from implementer's tests

	BYTE buf_in[AES_BLOCK_SIZE], buf_out[AES_BLOCK_SIZE];                		// intermediate buffers

	BYTE *ciphertext = (BYTE*) malloc(sizeof(BYTE) * ciphertext_size);
	if (!ciphertext) {
		printf("Could not encrypt file %s\n, due to issue allocating memory for ciphertext",
				fcontent->filename);
		return -1;
	}

	aes_key_setup(key, key_schedule, KEY_SIZE);									// performs generates keys that are used in encryption rounds

	/** --- do the encryption --- **/
	for (int i = 0; i < n_blocks; i++) {

		memcpy(buf_in, &padded_plaintext[i * AES_BLOCK_SIZE], AES_BLOCK_SIZE);  // copy next block into buf_in; this will be encrypted

		aes_encrypt(buf_in, buf_out, key_schedule, KEY_SIZE);                   // AES step, saving to buf_out

		memcpy(&ciphertext[i * AES_BLOCK_SIZE], buf_out, AES_BLOCK_SIZE);       // move the results of buf_out into the final
	}

	fcontent->ciphertext = ciphertext;
	fcontent->n_ciphertext_bytes = ciphertext_size;
	return 0;
}


/**
 * Decrypts AES ciphertext.
 */
int ecb_aes_decrypt(FileContent *fcontent, BYTE *key) {

	unsigned char *ciphertext = fcontent->ciphertext;

	/* --- setup --- */
	WORD key_schedule[60];   													// taken from implementer's tests
	int n_blocks = fcontent->n_ciphertext_bytes / AES_BLOCK_SIZE;           	// how many AES blocks do we need?
	int size = n_blocks * AES_BLOCK_SIZE;

	BYTE buf_in[AES_BLOCK_SIZE], buf_out[AES_BLOCK_SIZE], pt_buffer[size];  	// intermediate buffers

	aes_key_setup(key, key_schedule, KEY_SIZE);									// performs generates keys that are used in encryption rounds

	/** --- do the decryption --- **/
	for (int i = 0; i < n_blocks; i++) {

		memcpy(buf_in, &ciphertext[i * AES_BLOCK_SIZE], AES_BLOCK_SIZE);  		// copy next block into buf_in; this will be encrypted

		aes_decrypt(buf_in, buf_out, key_schedule, KEY_SIZE);             		// AES step, saving to buf_out

		memcpy(&pt_buffer[i * AES_BLOCK_SIZE], buf_out, AES_BLOCK_SIZE);  		// move the results of buf_out into the final
	}

	// the padding is held in the last BYTE of the decrypted buffer; this allows us to determine
	// how many ACTUAL bytes of plaintext we started with
	int n_bytes_plaintext = size - pt_buffer[size - 1];

	BYTE *plaintext = (BYTE*) malloc(sizeof(BYTE) * (n_bytes_plaintext + 1));
	if (!plaintext) {
		printf("Could not decrypt AES ciphertext because plaintext could not be allocated.\n");
		return -1;
	}

	// copy over the buffered plaintext into the final plaintext arr
	memcpy(plaintext, pt_buffer, n_bytes_plaintext);
	memcpy(plaintext + n_bytes_plaintext, "\0", 1);

	fcontent->plaintext = plaintext;
	fcontent->n_plaintext_bytes = n_bytes_plaintext;
	return 0;
}


