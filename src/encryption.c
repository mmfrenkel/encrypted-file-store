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
	temp = (BYTE *) malloc(sizeof(unsigned char) * (len_pt_pw + 1));
	strncpy((char *) temp, pt_password, len_pt_pw);

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

	printf("\n\nPlaintext: ");
	for (int i = 0; i < len_pt; i++) {
		printf("%x", pt[i] & 0xff);  // trick to print out unsigned hex
	}
	printf("\n\nPadded Plaintext: ");
	for (int i = 0; i < len_pt + pad_size; i++) {
		printf("%x |", padded_pt[i] & 0xff);  // trick to print out unsigned hex
	}
	printf("\n\n");

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
	// figure out how many blocks (iterations of AES we need)
	int n_blocks = (fcontent->n_plaintext_bytes / AES_BLOCK_SIZE) + 1;
	int ciphertext_size = n_blocks * AES_BLOCK_SIZE;

	WORD key_schedule[60];  // taken from implementer's tests

	BYTE buf_in[AES_BLOCK_SIZE], buf_out[AES_BLOCK_SIZE];

	BYTE *ciphertext = (BYTE*) malloc(sizeof(BYTE) * ciphertext_size);
	if (!ciphertext) {
		printf("Could not encrypt file %s\n, due to issue allocating memory for ciphertext",
				fcontent->filename);
		return -1;
	}

	// key setup step performs generates keys that are used in encryption rounds
	aes_key_setup(key, key_schedule, KEY_SIZE);

	/** --- do the encryption --- **/
	for (int i = 0; i < n_blocks; i++) {

		// copy next block into buf_in; this will be encrypted
		memcpy(buf_in, &padded_plaintext[i * AES_BLOCK_SIZE], AES_BLOCK_SIZE);

		// AES step, saving to buf_out
		aes_encrypt(buf_in, buf_out, key_schedule, KEY_SIZE);

		// move the results of buf_out into the final
		memcpy(&ciphertext[i * AES_BLOCK_SIZE], buf_out, AES_BLOCK_SIZE);
	}

	if (fcontent->ciphertext) {
		free(fcontent->ciphertext);
	}
	fcontent->ciphertext = ciphertext;
	fcontent->n_ciphertext_bytes = ciphertext_size;

	printf("Ciphertext: ");
	for (int i = 0; i < ciphertext_size; i++) {
		printf("%x |", ciphertext[i] & 0xff); // trick to print out unsigned hex
	}
	return 0;
}


/**
 * Decrypts AES ciphertext.
 */
int ecb_aes_decrypt(FileContent *fcontent, BYTE *key) {

	/* --- setup --- */
	WORD key_schedule[60];   // taken from implementer's tests

	int n_blocks = fcontent->n_ciphertext_bytes / AES_BLOCK_SIZE;
	int size = n_blocks * AES_BLOCK_SIZE;
	unsigned char *ciphertext = fcontent->ciphertext;

	BYTE buf_in[AES_BLOCK_SIZE], buf_out[AES_BLOCK_SIZE];
	BYTE *pt_buffer[size];

	// key setup step performs generates keys that are used in encryption rounds
	aes_key_setup(key, key_schedule, KEY_SIZE);

	/** --- do the decryption --- **/
	for (int i = 0; i < n_blocks; i++) {

		// copy next block into buf_in; this will be encrypted
		memcpy(buf_in, &ciphertext[i * AES_BLOCK_SIZE], AES_BLOCK_SIZE);

		// AES step, saving to buf_out
		aes_decrypt(buf_in, buf_out, key_schedule, KEY_SIZE);

		// move the results of buf_out into the final
		memcpy(&pt_buffer[i * AES_BLOCK_SIZE], buf_out, AES_BLOCK_SIZE);
	}

	// find the padding and remove it for the final plaintext
	int padding = (int) pt_buffer[size - 1];
	printf("PADDING WAS %d\n", padding);
	int n_bytes_plaintext = size - padding;

	BYTE* plaintext = (BYTE *) malloc(sizeof(BYTE) * n_bytes_plaintext);
	if (!plaintext) {
		printf("Could not decrypt AES ciphertext because plaintext message could not be allocated.\n");
		return -1;
	}
	memcpy(plaintext, pt_buffer, n_bytes_plaintext);

	if (fcontent->plaintext) {
		free(fcontent->plaintext);
	}
	fcontent->plaintext = plaintext;
	fcontent->n_plaintext_bytes = n_bytes_plaintext;

	printf("DECRYPT: Ciphertext Size: %lu, Plaintext Size: %d\n", fcontent->n_ciphertext_bytes, n_bytes_plaintext);

	printf("The last digit value is %x, %d\n", plaintext[size -1], plaintext[size -1]);

	for (int i = 0; i < size - 16; i++) {
		printf("%x |", plaintext[i] & 0xff);  // trick to print out unsigned hex
	}
	printf("\n");
	printf("DECRYPTED PLAINTEXT:\n\"%s\" \nEND OF PLAINTEXT\n", plaintext);

	return 0;
}


