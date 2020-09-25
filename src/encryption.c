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

BYTE* compute_hmac_256(BYTE *key, BYTE *ct, size_t len_ct);

void xor(BYTE *in1, BYTE *in2, BYTE *out, size_t length);

BYTE* get_random(size_t n_bytes);

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
 * Concept for appraoch to padding from: https://www.di-mgt.com.au/cryptopad.html
 */
BYTE* create_padded_plaintext(BYTE *pt, int len_pt, int block_size) {

	int pad_size = block_size - (len_pt % block_size);  // this is the size of pad we need

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
int cbc_aes_encrypt(FileContent *fcontent, BYTE *key) {

	// ------------------- SETUP -------------------

	BYTE *padded_plaintext = create_padded_plaintext(fcontent->plaintext,	// pad the plaintext be a multiple of the AES block size
			fcontent->n_plaintext_bytes, AES_BLOCK_SIZE);

	if (!padded_plaintext) {
		printf("Couldn't created padded plaintext");
		return -1;
	}

	int n_blocks = (fcontent->n_plaintext_bytes / AES_BLOCK_SIZE) + 1;		// how many AES blocks/iterations do we need?
	int ciphertext_size = n_blocks * AES_BLOCK_SIZE;
	WORD key_schedule[60];  												// taken from implementer's tests

	BYTE pt[AES_BLOCK_SIZE], ct[AES_BLOCK_SIZE];							// intermediate buffers
	BYTE tmp[AES_BLOCK_SIZE], xor_buf[AES_BLOCK_SIZE];

	BYTE *ciphertext = (BYTE*) malloc(sizeof(BYTE) * ciphertext_size); 		// this will hold the final full ciphertext
	if (!ciphertext) {
		printf("Could not encrypt file %s\n, due to issue allocating "
				"memory for ciphertext", fcontent->filename);
		return -1;
	}

	aes_key_setup(key, key_schedule, KEY_SIZE);								// generates keys that are used in encryption rounds

	memcpy(tmp, fcontent->iv, AES_BLOCK_SIZE);                              // initialization vector -> tmp to be ready for first block

	// ---------------- DO THE ENCRYPTION -----------

	for (int i = 0; i < n_blocks; i++) {

		memcpy(pt, &padded_plaintext[i * AES_BLOCK_SIZE], AES_BLOCK_SIZE); 	// pt is the next block of plaintext to be encrypted

		xor(tmp, pt, xor_buf, AES_BLOCK_SIZE);          					// XOR pt block with tmp -> xor buf

		aes_encrypt(xor_buf, ct, key_schedule, KEY_SIZE);                   // AES step, encrypted block goes to ciphertext (ct) block

		memcpy(&ciphertext[i * AES_BLOCK_SIZE], ct, AES_BLOCK_SIZE);        // move this ct block into final result

		memcpy(tmp, ct, AES_BLOCK_SIZE);       								// ct block becomes new tmp to XOR with next block of pt
	}

	// ----------------- SAVE CIPHERTEXT -------------------

	fcontent->ciphertext = ciphertext;
	fcontent->n_ciphertext_bytes = ciphertext_size;

	return 0;
}

/**
 *
 */
int cbc_aes_decrypt(FileContent *fcontent, BYTE *key) {

	// ------------------- SETUP -------------------

	WORD key_schedule[60];   												// taken from implementer's tests
	int n_blocks = fcontent->n_ciphertext_bytes / AES_BLOCK_SIZE;           // how many AES blocks do we need?
	int ct_size = n_blocks * AES_BLOCK_SIZE;

	BYTE pt[AES_BLOCK_SIZE], ct[AES_BLOCK_SIZE];							// intermediate buffers
	BYTE tmp[AES_BLOCK_SIZE], xor_buf[AES_BLOCK_SIZE], pt_buffer[ct_size];

	aes_key_setup(key, key_schedule, KEY_SIZE);								// generates keys used in decryption rounds

	memcpy(tmp, fcontent->iv, AES_BLOCK_SIZE);                              // initialization vector -> tmp to be ready for first block

	// ---------------- DO THE DECRYPTION ------------

	unsigned char *ciphertext = fcontent->ciphertext;

	for (int i = 0; i < n_blocks; i++) {

		memcpy(ct, &ciphertext[i * AES_BLOCK_SIZE], AES_BLOCK_SIZE); 		// ct is the next block of ciphertext to be decrypted

		aes_decrypt(ct, xor_buf, key_schedule, KEY_SIZE);                   // AES step, encrypted block goes to xor_buf

		xor(tmp, xor_buf, pt, AES_BLOCK_SIZE);          					// XOR xor_buf block with tmp -> plaintext (pt)!

		memcpy(&pt_buffer[i * AES_BLOCK_SIZE], pt, AES_BLOCK_SIZE);        	// move this pt block into result

		memcpy(tmp, ct, AES_BLOCK_SIZE);       								// ct block is new tmp to XOR with next block of ct
	}
	// ----------------- REMOVE BUFFER --------------------

	int n_bytes_pt = ct_size - pt_buffer[ct_size - 1]; 						// padding is held in last byte of decrypted buffer

	BYTE *plaintext = (BYTE*) malloc(sizeof(BYTE) * (n_bytes_pt + 1));
	if (!plaintext) {
		printf("Could not decrypt AES ciphertext because plaintext "
				"could not be allocated.\n");
		return -1;
	}
	memcpy(plaintext, pt_buffer, n_bytes_pt);             					// move only plaintext without buffer into final result
	memcpy(&plaintext[n_bytes_pt], "\0", 1);

	// ------------------ SAVE PLAINTEXT --------------------

	fcontent->plaintext = plaintext;
	fcontent->n_plaintext_bytes = n_bytes_pt;

	return 0;
}

/**
 *
 */
int assign_hmac_256(FileContent *fcontent, BYTE *key) {

	BYTE *hmac_hash = compute_hmac_256(key, fcontent->ciphertext,
			fcontent->n_ciphertext_bytes);

	if (!hmac_hash) {
		printf("Could not compute hmac for file.\n");
		return -1;
	}

	fcontent->hmac_hash = hmac_hash;
	return 0;
}


/**
 *  Compute a MAC - message authentication code
 *
 *  code = MAC(k, ciphertext)
 *
 *  HMAC(m, k) = H(opad XOR k, (H(ipad XOR k, m));
 *
 *  Note that key is assumed to be 32 bytes (otherwise this will not work!)
 *
 *   magic number values obtained from Krawcyzk et al. found here
 // http://cseweb.ucsd.edu/~mihir/papers/rfc2104.txt
 */
BYTE* compute_hmac_256(BYTE *key, BYTE *ct, size_t len_ct) {

	// ------- GET TWO KEYS FROM FIRST KEY  --------

	// user the two magic numbers
	BYTE o_key_buf[SHA256_BLOCK_SIZE] = { [0 ... SHA256_BLOCK_SIZE - 1] = 0x5c };
	BYTE i_key_buf[SHA256_BLOCK_SIZE] = { [0 ... SHA256_BLOCK_SIZE - 1] = 0x36 };

	BYTE key_o[SHA256_BLOCK_SIZE], key_i[SHA256_BLOCK_SIZE];
	xor(key, o_key_buf, key_o, SHA256_BLOCK_SIZE);
	xor(key, i_key_buf, key_i, SHA256_BLOCK_SIZE);

	// ------- RUN SHA-256 TWICE OVER  -------------

	size_t full_len = len_ct + SHA256_BLOCK_SIZE;
	BYTE ciphertext_key_i[full_len];

	memcpy(ciphertext_key_i, ct, len_ct);
	memcpy(ciphertext_key_i + len_ct, key_i, SHA256_BLOCK_SIZE);

	BYTE *first_hash;  	// hash for ciphertext + key_i = "ciphertext_key_i"
	if (!(first_hash = hash_sha_256(ciphertext_key_i, full_len))) {
		return NULL;
	}

	BYTE ciphertext_key_o[full_len];
	memcpy(ciphertext_key_o, first_hash, len_ct);
	memcpy(ciphertext_key_o + len_ct, key_o, SHA256_BLOCK_SIZE);

	BYTE *second_hash;  // hash for k_o + hash(ciphertext_key_i)
	if (!(second_hash = hash_sha_256(ciphertext_key_o, full_len))) {
		free(first_hash);
		return NULL;
	}

	free(first_hash);    // no longer need to keep the first hash
	return second_hash;
}

/**
 *
 */
void xor(BYTE *in1, BYTE *in2, BYTE *out, size_t length) {

	for (int i = 0; i < length; i++) {
		out[i] = in1[i] ^ in2[i];
	}
}

/**
 *
 */
int assign_iv(FileContent *fcontent) {

	BYTE *iv = get_random(AES_BLOCK_SIZE);
	if (!iv) {
		return -1;
	}

	fcontent->iv = iv;
	return 0;
}

/**
 * https://www.cs.yale.edu/homes/aspnes/pinewiki/C(2f)Randomization.html
 */
BYTE* get_random(size_t n_bytes) {

	BYTE *iv = malloc(sizeof(char) * n_bytes);
	if (!iv) {
		printf("Could not allocate memory for IV.\n");
		return NULL;
	}

	FILE *fp;
	if(!(fp = fopen("/dev/random", "r"))) {
		printf("Could not open /dev/random to generate IV.\n");
		free(iv);
		return NULL;
	}
	fread(iv, sizeof(BYTE), n_bytes, fp);
	fclose(fp);

	return iv;
}


