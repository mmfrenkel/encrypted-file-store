/*
 * encryption.c
 *
 * Responsible for all encryption/decryption/hashing steps
 * associated with encrypted file store. Implements functionality
 * to convert a user's password into cryptographic key,
 * encrypt plaintext to ciphertext via AES encryption
 * using cipher block chaining (CBC) mode, and HMAC hash
 * calculations of key+ciphertext using SHA-256.
 *
 *  Created on: Sep 23, 2020
 *      Author: meganfrenkel
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "encryption.h"
#include "../encryption-algorithms/aes.h"
#include "../encryption-algorithms/sha256.h"
#include "file_io.h"

/* ----- methods that shouldn't be called externally ---- */

BYTE* hash_sha_256(BYTE *text, int len_pt);

BYTE* create_padded_plaintext(BYTE *pt, int len_pt, int block_size);

void xor(BYTE *in1, BYTE *in2, BYTE *out, size_t length);

BYTE* get_random(size_t n_bytes);

/* ------------------------------------------------------ */

/**
 * Converts some string of chars into a 32 byte (256 bit)
 * key using a SHA-256 hash function, iteratively applied a
 * specified number of times. Note: this function allocates
 * memory on the heap for this new hash.
 *
 * Hash function supplied by Brad Conte, found here:
 * https://github.com/B-Con/crypto-algorithms
 *
 * @param txt, some text that should be hashed (i.e., a user's password)
 * @param n_char, the number of characters, or length of the text
 * @param iterations, the number of iterations of SHA-256 to perform
 * @return the new cryptographic key
 */
BYTE* create_cryptographic_key(char *txt, int n_char, int iterations) {

	BYTE *new_hash;
	BYTE *temp;

	temp = (BYTE*) malloc(sizeof(unsigned char) * (n_char + 1));
	if (!temp) {
		printf("Failed to allocate memory for temporary hash storage.\n ");
		return NULL;
	}
	strncpy((char* ) temp, txt, n_char);

	// repeatedly run sha-256 hash function
	for (int i = 0; i < iterations; i++) {
		if (!(new_hash = hash_sha_256(temp, n_char))) {
			printf("Unable to create cryptographic key from submitted text.\n");
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

	BYTE *buffer = (BYTE*) malloc(sizeof(BYTE) * SHA256_BLOCK_SIZE);
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
		printf("This method uses cipher block chaining (CBC); you need "
				"to find an initialization vector for CBC before you "
				"may use this function.\n");
		return -1;
	}

	// ------------------- SETUP -------------------

	// pad the plaintext be a multiple of the AES block size
	BYTE *padded_plaintext = create_padded_plaintext(fcontent->plaintext,
			fcontent->n_plaintext_bytes, AES_BLOCK_SIZE);

	if (!padded_plaintext) {
		printf("Couldn't created padded plaintext");
		return -1;
	}

	// how many AES blocks/iterations do we need?
	int n_blocks = (fcontent->n_plaintext_bytes / AES_BLOCK_SIZE) + 1;
	int ciphertext_size = n_blocks * AES_BLOCK_SIZE;
	WORD key_schedule[60];  // taken from implementer's tests
	BYTE pt[AES_BLOCK_SIZE], ct[AES_BLOCK_SIZE];
	BYTE tmp[AES_BLOCK_SIZE], xor_buf[AES_BLOCK_SIZE];

	// this will hold the final full ciphertext
	BYTE *ciphertext = (BYTE*) malloc(sizeof(BYTE) * ciphertext_size);
	if (!ciphertext) {
		printf("Could not encrypt file %s\n, due to issue allocating "
				"memory for ciphertext", fcontent->filename);
		return -1;
	}

	// generates keys that are used in encryption rounds
	aes_key_setup(key, key_schedule, KEY_SIZE);

	// initialization vector -> tmp to be ready for first block
	memcpy(tmp, fcontent->iv, AES_BLOCK_SIZE);

	// ---------------- DO THE ENCRYPTION -----------

	for (int i = 0; i < n_blocks; i++) {

		// pt is the next block of plaintext to be encrypted
		memcpy(pt, &padded_plaintext[i * AES_BLOCK_SIZE], AES_BLOCK_SIZE);

		// XOR pt block with tmp -> xor buf
		xor(tmp, pt, xor_buf, AES_BLOCK_SIZE);

		// AES step, encrypted block goes to ciphertext (ct) block
		aes_encrypt(xor_buf, ct, key_schedule, KEY_SIZE);

		// move this ct block into final result
		memcpy(&ciphertext[i * AES_BLOCK_SIZE], ct, AES_BLOCK_SIZE);

		// ct block becomes new tmp to XOR with next block of pt
		memcpy(tmp, ct, AES_BLOCK_SIZE);
	}

	// ----------------- SAVE CIPHERTEXT -------------------

	fcontent->ciphertext = ciphertext;
	fcontent->n_ciphertext_bytes = ciphertext_size;

	free(padded_plaintext);  // we no longer need this padded pt
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

	// taken from implementer's tests
	WORD key_schedule[60];

	// how many AES blocks do we need?
	int n_blocks = fcontent->n_ciphertext_bytes / AES_BLOCK_SIZE;
	int ct_size = n_blocks * AES_BLOCK_SIZE;
	BYTE pt[AES_BLOCK_SIZE], ct[AES_BLOCK_SIZE];
	BYTE tmp[AES_BLOCK_SIZE], xor_buf[AES_BLOCK_SIZE], pt_buffer[ct_size];

	// generates keys used in decryption rounds
	aes_key_setup(key, key_schedule, KEY_SIZE);

	// initialization vector -> tmp to be ready for first block
	memcpy(tmp, fcontent->iv, AES_BLOCK_SIZE);

	// ---------------- DO THE DECRYPTION ------------

	unsigned char *ciphertext = fcontent->ciphertext;

	for (int i = 0; i < n_blocks; i++) {

		// ct is the next block of ciphertext to be decrypted
		memcpy(ct, &ciphertext[i * AES_BLOCK_SIZE], AES_BLOCK_SIZE);

		// AES step, encrypted block goes to xor_buf
		aes_decrypt(ct, xor_buf, key_schedule, KEY_SIZE);

		// XOR xor_buf block with tmp -> plaintext (pt)!
		xor(tmp, xor_buf, pt, AES_BLOCK_SIZE);

		// move this pt block into the final result
		memcpy(&pt_buffer[i * AES_BLOCK_SIZE], pt, AES_BLOCK_SIZE);

		// ct block is new tmp to XOR with next block of ct
		memcpy(tmp, ct, AES_BLOCK_SIZE);
	}

	// ----------------- REMOVE BUFFER --------------------

	// padding is held in last byte of decrypted buffer
	int n_bytes_pt = ct_size - pt_buffer[ct_size - 1];

	// if wrong password/corrupted, this can be <0, which cannot be processed
	if (n_bytes_pt <= 0) {
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

	// move only plaintext without buffer into final result
	memcpy(plaintext, pt_buffer, n_bytes_pt);
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
		printf("Could not create padded plaintext due to issue "
				"allocating memory.\n");
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
 * plaintext file using the calculated ciphertext and the cryptographic key
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
int assign_ciphertext_hmac_256(FileContent *fcontent, BYTE *key) {

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
 * Computes a hash-based message authenticate code (HMAC) for a
 * given combination of archive name and cryptographic key
 * derived from the user's initial password. By comparing the
 * resulting HMAC hash to the HMAC hash stored in the archive
 * metadata, it is possible to tell whether a user
 * has the capability of interacting with a specific archive
 * (i.e., did the submit the correct password?). Note that the key
 * used for the HMAC is the cryptographic key after another 10,000
 * iterations of SHA-256. This ensures that the same key is not used
 * for the HMAC of the ciphertext files.
 *
 * Recall: Metadata for achives is a concatination of two HMAC
 * hashes where the first is for user authentication.
 *
 * @param archive, the name of the archive
 * @param key, the cryptographic key derived from a user's password
 * @param metadata, a pointer to BYTES read in from metadata file
 * @return 0 if the user could be authenticated, else 1 for incorrect
 *           user or -1 for error
 */
int authenticate_user_for_archive(char *archive, BYTE *key, BYTE *metadata) {

	// create a new key, that is the cryptographic key provided,
	// but after 10,000 more iterations
	BYTE *second_key;
	if (!(second_key = create_cryptographic_key((char*) key, SHA256_BLOCK_SIZE,
			SECOND_KEY_ITER))) {
		printf("Could not generate second key for HMAC to authenticate "
				"user from metadata.\n");
		return -1;
	}

	BYTE *hmac_hash = compute_hmac_256(second_key, (unsigned char*) archive,
			strlen(archive));

	if (!hmac_hash) {
		printf("Could not compute hmac for user/archive combination.\n");
		return -1;
	}

	// compare the hmac hash generated with archive name and cryptrographic
	// key with the one stored in the archive's metadata file
	int invalid =  memcmp(hmac_hash, metadata, SHA256_BLOCK_SIZE) ? 1 : 0;

	// clean up
	free(hmac_hash);
	free(second_key);
	return invalid;
}

/**
 * Computes a hash-based message authenticate code (HMAC) for a
 * given combination of filenames (as a single concatinated string)
 * and the cryptographic key derived from the user's initial
 * password submission. By comparing the resulting HMAC hash
 * to the HMAC hash stored in the archive metadata, we can see
 * if any of the files in the archive have been deleted or renamed
 * or if any other files have been added. Note that the key
 * used for the HMAC is the cryptographic key after another 10,000
 * iterations of SHA-256. This ensures that the same key is not used
 * for the HMAC of the ciphertext files.
 *
 * Recall: Each metadata file for achives is a concatination of two HMAC
 * hashes, where the second hash is used for archive filename integrity.

 * @param key, the cryptographic key derived from a user's password
 * @param metadata, a pointer to BYTES read in from metadata file
 * @param filenames, a array of concatinated filenames in the archive
 * @return 0 if the user could be authenticated, else 1 for incorrect
 *           user or -1 for error
 */
int verify_archive_contents(BYTE *key, BYTE *metadata, char *filenames) {

	// create a new key, that is the cryptographic key provided,
	// but after 10,000 more iterations
	BYTE *second_key;
	if (!(second_key = create_cryptographic_key((char*) key, SHA256_BLOCK_SIZE,
			SECOND_KEY_ITER))) {
		printf("Could not generate second key for HMAC to authenticate "
				"filestore content from metadata.\n");
		return -1;
	}

	BYTE *hmac_hash = compute_hmac_256(second_key, (unsigned char*) filenames,
			strlen(filenames));

	if (!hmac_hash) {
		printf("Could not compute hmac for user/archive combination.\n");
		return -1;
	}

	// compare the hmac hash generated with filenames and cryptrographic
	// key with the one stored in the archive's metadata file
	// the metadata hash of interest is the second hmac hash in the content
	int invalid =  memcmp(hmac_hash, &metadata[SHA256_BLOCK_SIZE],
			SHA256_BLOCK_SIZE) ? 1 : 0;

	// clean up
	free(hmac_hash);
	free(second_key);
	return invalid;
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
	if (!(fp = fopen("/dev/random", "r"))) {
		printf("Could not open /dev/random to generate IV.\n");
		free(iv);
		return NULL;
	}
	fread(iv, sizeof(BYTE), n_bytes, fp);
	fclose(fp);

	return iv;
}

