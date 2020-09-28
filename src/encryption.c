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

void xor(BYTE *in1, BYTE *in2, BYTE *out, size_t length);

BYTE* get_random(size_t n_bytes);

/* ------------------------------------------------------ */

/**
 * Converts password submitted by user into a 32 byte (256 bit)
 * key using a SHA-256 hash function, iteratively applied a
 * specified number of times. Note: this function allocates
 * memory on the heap for this new hash.
 *
 * Hash function supplied by Brad Conte, found here:
 * https://github.com/B-Con/crypto-algorithms
 *
 * @param pt_password, the plaintext password submitted by a user
 * @param iterations, the number of iterations of SHA-256 to perform
 * @return the new cryptographic key
 */
BYTE* convert_password_to_cryptographic_key(char *pt_password, int iterations) {
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
	for (int i = 0; i < iterations; i++) {
		if (!(new_hash = hash_sha_256(temp, len_pt_pw))) {
			printf("Unable to create cryptographic key from submitted password\n");
			free(temp);
			return NULL;
		}
		free(temp);      // free memory allocated to older version of hash
		temp = new_hash;
	}

	return temp;
}

/**
 *  Call to perform the SHA-256 hash on an array of BYTEs.
 *
 *  Setup modeled from source test examples by Brad Conte here:
 *  https://github.com/B-Con/crypto-algorithms/blob/master/sha256_test.c
 *
 *  @param text, the content to hash (an array of BYTEs)
 *  @param len_pt, the length of the content to hash
 *  @return 32-byte hash
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
 * Performs AES encryption on plaintext content within FileContent
 * struct. AES takes 16 bytes (128 bits) at a time to produce 16 bytes;
 * here this is done using a cipher block-chaining (CBC) routine,
 * where the output of each previous encryption block is combinted with
 * the next block. This allows two identical blocks of plaintext to be
 * encrypted different. CBC mode of encryption relies on an initialization
 * vector (IV), an extra block of truly random text, that must have already
 * been calculated and stored in the FileContent struct in order to call this
 * function. The newly created ciphertext will be stored in the FileContent.
 *
 * Steps of the encryption are outlined extensively below. Note that the
 * procedure used for CBC mode was heavily influenced by the code
 * written by Brad Conto here: https://github.com/B-Con/crypto-algorithms.
 *
 * @param fcontent, FileContent struct holding (1) plaintext, (2) plaintext
 * 				    length, and (3) an initialization vector (IV)
 * @param key, the key to use in the AES encryption
 * @return 0 if the encryption was successful, -1 if error
 */
int cbc_aes_encrypt(FileContent *fcontent, BYTE *key) {

	// make sure that the user has assigned an IV
	if (!fcontent->iv) {
		printf("You need to find an initialization vector before you"
				"may use this function.\n");
		return -1;
	}

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
 * Performs decryption of ciphertext content genereated by AES
 * encryption using cipher block-chaining (CBC). This function
 * also removes any padding added to the ciphertext for the
 * encryption step. The final plaintext and plaintext length are
 * stored in the provided FileContent. See more about AES and
 * CBC in the cbc_aes_encrypt() function.
 *
 * Steps of the decryption are outlined extensively below. Note that the
 * procedure used for CBC mode was heavily influenced by the code
 * written by Brad Conto here: https://github.com/B-Con/crypto-algorithms.
 *
 * @param fcontent, FileContent struct holding (1) ciphertext,
 * 					(2) ciphertext length, and (3) the original initialization
 * 					vector (IV) used for encryption
 * @param key, the key to use in the AES decryption; it should be
 * 		  the same as the key used in the initial encryption
 * @return 0 if the decryption was successful, -1 if error
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
	if (n_bytes_pt <= 0) {													// if wrong password/corrupted, this can be <0, which cannot be processed
		printf("Unable to decrypt file \"%s\". It is possible this "
				"file has been corrupted. Are you sure you submitted "
				"your password correctly?\n", fcontent->filename);
		return -1;
	}
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
 * Pads the plaintext in order to make sure that the new length
 * is a multiple of a specified block size (i.e., AES block size).
 *
 * The method used for padding was inspired by content read here:
 * https://www.di-mgt.com.au/cryptopad.html. More specifically, this
 * method pads with bytes all of the same value as the number of
 * padding bytes. This means that if four bytes are added as a pad,
 * then the last four bytes of the final padded plaintext hold the
 * number 4.
 *
 * Note: The method allocates heap memory for the padded plaintext.
 *
 * @param pt, plaintext content to pad
 * @param len_pt, the length of the plaintext content
 * @param block_size, the size of a single block
 * @param newly padded plaintext
 */
BYTE* create_padded_plaintext(BYTE *pt, int len_pt, int block_size) {

	// this is the size of pad we need
	int pad_size = block_size - (len_pt % block_size);

	BYTE *padded_pt = (BYTE*) malloc(sizeof(BYTE) * (len_pt + pad_size));
	if (!padded_pt) {
		printf("Could not create padded plaintext due to issue allocating memory.\n");
		return NULL;
	}

	// copy over the existing plaintext
	memcpy(padded_pt, pt, len_pt);

	// perform the padding; pad with same number as number of bytes to pad
	for (int i = 0; i < pad_size; i++) {
		int shift = len_pt + i;
		memcpy(&padded_pt[shift], &pad_size, 1);
	}
	return padded_pt;
}

/**
 * Computes a hash-based message authenticate code (HMAC) for the a
 * plaintext file uses the calculated ciphertext and the cryptographic key
 * derived from the user's initial password. This HMAC utilizes the
 * SHA-256 hash function from  Brad Conto, found here:
 * https://github.com/B-Con/crypto-algorithms.
 *
 * The resulting HMAC hash is assigned to the hmac_hash member of
 * FileContent.
 *
 * @param fcontent FileContent, holding ciphertext and a ciphertext length
 * @param key, the cryptographic key derived from a user's password
 * @return 0 if HMAC-SHA256 hash was performed successfully, -1 if error
 */
int assign_hmac_256(FileContent *fcontent, BYTE *key) {

	if (!fcontent->ciphertext) {
		printf("Ciphertext is necessary to generate an HMAC hash. "
				"Please derive the ciphertext and try again.\n");
		return -1;
	}

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
 * Conducts an integrity check on the ciphertext content read from
 * the encrypted file store in order to ensure that there wasn't an
 * corruption of the file. This integrity check is achieved by comparing
 * the initial hash-based message authenication code (HMAC) assigned
 * to an encrypted file (based on the ciphertext and cryptographic
 * key derived from a user's password) that is read in from a file
 * on decryption and the HMAC code that is recomputed from the ciphertext
 * read from file and the submitted user password. The integrity check
 * fails if the two HMAC hashes do not match. This can be achieved
 * if either (a) a user submits the wrong password or (b) a file
 * has been corrupted in storage.
 *
 * @param fcontent, FileContent where the ciphertext and ciphertext length
 *                  have been specified
 * @param key, cryptographic key derived from a user's submitted password
 * @retun 0 if HMAC hash function was completed successfully, -1 if error
 */
int integrity_check(FileContent *fcontent, BYTE *key) {

	if (!fcontent->hmac_hash) {
		printf("Cannot run integrity check without previous HMAC hash, "
				"so cannot say if integrity is compromised.\n");
		return 0;
	}

	BYTE *recomputed_hmac = compute_hmac_256(key, fcontent->ciphertext,
			fcontent->n_ciphertext_bytes);

	// comparison of original hmac hash and recomputed hash should determine
	// that (1) either the password (key) is not correct OR that
	// (2) the content of the ciphertext file has been changed.
	int is_corrupted = memcmp(recomputed_hmac, fcontent->hmac_hash,
			SHA256_BLOCK_SIZE);

	free(recomputed_hmac);
	return is_corrupted;
}


/**
 *  Compute a hash-based message authentication code (HMAC)
 *  based on a key and set of ciphertext. The algorithm for calculating
 *  the hash includes three distinct steps.
 *
 *  (1) Calculate two keys derived from the provided key. These are
 *      created using two "magic numbers," 0x5c (o_pad) and 0x36 (i_pad),
 *      and XOR-ing them with the key, k.
 *  (2) Find SHA-256 hash of a concatination of the first derived key
 *  	and the ciphertext.
 *  (3) Find SHA-256 hash of a concatination of the first hash and
 *  	the second derived key.
 *
 *  This looks like: HMAC(m, k) = H(opad XOR k, (H(ipad XOR k, m));
 *
 *  Note: The key used in this function is assumed to be 32 bytes
 *        (otherwise this will not work!)
 *
 *  So called "magic numbers" were obtained from Krawcyzk et al. found here:
 *   http://cseweb.ucsd.edu/~mihir/papers/rfc2104.txt on September 24, 2020.
 *
 * @param key, the cryptographic key, derived from a user's password. It is
 *        assumed that this key is 32 bytes in length.
 * @param ct, the ciphertext for a file
 * @param len_ct, the length of the ciphertext
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
	size_t len_ct_key_i = len_ct + SHA256_BLOCK_SIZE;
	BYTE ct_key_i[len_ct_key_i];

	memcpy(ct_key_i, ct, len_ct);
	memcpy(ct_key_i + len_ct, key_i, SHA256_BLOCK_SIZE);

	BYTE *first_hash;  	// hash for ciphertext + key_i = "ciphertext_key_i"
	if (!(first_hash = hash_sha_256(ct_key_i, len_ct_key_i))) {
		return NULL;
	}

	size_t len_ct_key_o = 2 * SHA256_BLOCK_SIZE;
	BYTE ct_key_o[len_ct_key_o];

	memcpy(ct_key_o, first_hash, SHA256_BLOCK_SIZE);
	memcpy(&ct_key_o[SHA256_BLOCK_SIZE], key_o, SHA256_BLOCK_SIZE);

	BYTE *second_hash;  // hash for k_o + hash(ciphertext_key_i)
	if (!(second_hash = hash_sha_256(ct_key_o, len_ct_key_o))) {
		free(first_hash);
		return NULL;
	}
	free(first_hash);    // no longer need to keep the first hash
	return second_hash;
}

/**
 * Performs an exclusive-OR (XOR) of bytes within two arrays.
 *
 * @param in1, first array of BYTES (unsigned char)
 * @param in2, second array of BYTES (unsigned char)
 * @param out, the array to store the XOR result
 * @param length, the length over which to perform the XOR
 * @return void
 */
void xor(BYTE *in1, BYTE *in2, BYTE *out, size_t length) {

	for (int i = 0; i < length; i++) {
		out[i] = in1[i] ^ in2[i];
	}
}

/**
 * Finds a truly random sequence of bytes the size
 * of a single AES block to be used as the initialization
 * vector (IV) in AES encryption using cipher block-chaining.
 * The IV is then assigned as the iv member of the provided
 * FileContent.
 *
 * @param fcontent, FileContent struct with unassigned iv member
 * @return 0 if successful, -1 if error
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
 * Gets a sequence of random numbers using /dev/random. Note
 * that this function allocates heap memory for the IV.
 *
 * Inspiration for this function came from the class notes of
 * James Aspnes at Yale University found here:
 * https://www.cs.yale.edu/homes/aspnes/pinewiki/C(2f)Randomization.html
 *
 * @param n_bytes, the number of random bytes to collect
 * @return a pointer to an array of random bytes
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


