#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/encryption.h"
#include "../src/file_io.h"


char password[5] = { "pass" };

int iterations = 10000;

BYTE key[SHA256_BLOCK_SIZE] = { 0x72, 0xd5, 0x8a, 0x21, 0x63, 0x12, 0x75, 0xd0,
		0x62, 0x57, 0x9f, 0x92, 0x19, 0x1a, 0x14, 0x5d, 0xfa, 0x8b, 0x91, 0xfb,
		0xc5, 0x7c, 0x56, 0x50, 0xa5, 0x72, 0x2f, 0x90, 0x25, 0x30, 0xf1, 0xf9 };

BYTE iv[AES_BLOCK_SIZE] = { 0x5f, 0x90, 0x81, 0xbc, 0xe5, 0x2c, 0x95, 0x59,
		0x9e, 0x7e, 0x6, 0xcb, 0xb8, 0x53, 0x4a, 0x51 };

BYTE pt[26] = { 0x46, 0x61, 0x6c, 0x6c, 0x20, 0x69, 0x6e, 0x20, 0x4e, 0x59,
		0x43, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x62, 0x65, 0x73,
		0x74, 0x2e, 0xa, 0xa };

BYTE ct[32] = { 0x7b, 0x42, 0x7e, 0xca, 0x74, 0x69, 0xba, 0x8, 0x5a, 0xdb, 0x48,
		0x6d, 0x89, 0x38, 0xb1, 0xa7, 0x92, 0x8d, 0xbb, 0x5d, 0xf5, 0xce, 0xdb,
		0x25, 0x49, 0xf3, 0x3e, 0xb8, 0xb3, 0xce, 0x19, 0x51 };

BYTE hmac_hash[SHA256_BLOCK_SIZE] = { 0xb6, 0x38, 0x5, 0xba, 0xcb, 0xd7, 0xf1,
		0xac, 0x86, 0x4a, 0xfb, 0xc1, 0x90, 0xdd, 0x5a, 0x73, 0x3f, 0xa3, 0x40,
		0xec, 0xf6, 0xa5, 0x4d, 0x29, 0x27, 0xcf, 0x8d, 0x21, 0x6f, 0xd3, 0x7a,
		0x4b };

int test_convert_password_to_cryptographic_key() {

	BYTE *encrypted_pass = convert_password_to_cryptographic_key(password, iterations);

	// 0 is a "not failed"
	int failed = memcmp(encrypted_pass, key, SHA256_BLOCK_SIZE);

	free(encrypted_pass);
	return failed;
}

int test_aes_decryption_cbc() {

	FileContent *fc = (FileContent*) malloc(sizeof(FileContent));
	fc->plaintext = pt;
	fc->n_plaintext_bytes = 26;
	fc->iv = iv;

	// encrypt and decrypt the concent; pt should come out the same
	cbc_aes_encrypt(fc, key);
	cbc_aes_decrypt(fc, key);

	int failed = memcmp(fc->plaintext, pt, 26) || !(fc->n_plaintext_bytes == 26);

	free(fc->ciphertext);
	free(fc->plaintext);
	free(fc);
	return failed;
}

int test_hmac_sha_256() {

	BYTE* hmac_produced = compute_hmac_256(key, ct, 32);

	int failed = memcmp(hmac_produced, hmac_hash, SHA256_BLOCK_SIZE);

	free(hmac_produced);
	return failed;
}


int test_integrity_check_pass() {

	FileContent *fc = (FileContent*) malloc(sizeof(FileContent));
	fc->ciphertext = ct;
	fc->n_ciphertext_bytes = 32;
	fc->hmac_hash = hmac_hash;    // this is the hash that could have been read from a file

	int failed = integrity_check(fc, key);

	free(fc);
	return failed;
}

int test_integrity_check_fail_swapped_byte() {

	BYTE corrupted_ciphertext[32] = { 0x7b, 0x42, 0x7e, 0xca, 0x74, 0x69, 0xba,
			0x8, 0x5a, 0xdb, 0x48, 0x6d, 0x89, 0x38, 0xb1, 0xa7, 0x90, 0x8d,
			0xbb, 0x5d, 0xf5, 0xce, 0xdb, 0x25, 0x49, 0xf3, 0x3e, 0xb8, 0xb3,
			0xce, 0x19, 0x51 };

	FileContent *fc = (FileContent*) malloc(sizeof(FileContent));
	fc->ciphertext = corrupted_ciphertext;
	fc->n_ciphertext_bytes = 32;
	fc->hmac_hash = hmac_hash;    // this is the hash that could have been read from a file

	int failed = !integrity_check(fc, key);

	free(fc);
	return failed;
}

int test_integrity_check_fail_length_extended() {

	BYTE corrupted_ciphertext[33] = { 0x7b, 0x42, 0x7e, 0xca, 0x74, 0x69, 0xba,
			0x8, 0x5a, 0xdb, 0x48, 0x6d, 0x89, 0x38, 0xb1, 0xa7, 0x92, 0x8d,
			0xbb, 0x5d, 0xf5, 0xce, 0xdb, 0x25, 0x49, 0xf3, 0x3e, 0xb8, 0xb3,
			0xce, 0x19, 0x51, 0x51 };

	FileContent *fc = (FileContent*) malloc(sizeof(FileContent));
	fc->ciphertext = corrupted_ciphertext;
	fc->n_ciphertext_bytes = 33;
	fc->hmac_hash = hmac_hash;    // this is the hash that could have been read from a file

	int failed = !integrity_check(fc, key);

	free(fc);
	return failed;
}


void run_tests() {

	int count_pass = 0;
	int count_failed = 0;
	int failed = 0;

	printf("------------------------------ TEST OUTCOMES ---------------------------\n");

	if ((failed = test_convert_password_to_cryptographic_key())) {
		printf("* Test conversion to cryptographic key FAILED! \n");
		count_failed++;
	} else {
		printf("* Test conversion to cryptographic key PASSED! \n");
		count_pass++;
	}

	if ((failed = test_aes_decryption_cbc())) {
		printf("* Test conversion of plaintext --> ciphertext --> plaintext FAILED! \n");
		count_failed++;
	} else {
		printf("* Test conversion of plaintext --> ciphertext --> plaintext PASSED! \n");
		count_pass++;
	}

	if ((failed = test_hmac_sha_256())) {
		printf("* Test production of HMAC-SHA FAILED! \n");
		count_failed++;
	} else {
		printf("* Test production of HMAC-SHA PASSED! \n");
		count_pass++;
	}

	if ((failed = test_integrity_check_pass())) {
		printf("* Test of Integrity (OK) FAILED! \n");
		count_failed++;
	} else {
		printf("* Test of Integrity (OK) PASSED! \n");
		count_pass++;
	}

	if ((failed = test_integrity_check_fail_swapped_byte())) {
		printf("* Test of Integrity (Corrupted - Byte Swapped) FAILED! \n");
		count_failed++;
	} else {
		printf("* Test of Integrity (Corrupted - Byte Swapped) PASSED! \n");
		count_pass++;
	}

	if ((failed = test_integrity_check_fail_length_extended())) {
		printf("* Test of Integrity (Corrupted - Length Extended) FAILED! \n");
		count_failed++;
	} else {
		printf("* Test of Integrity (Corrupted - Length Extended) PASSED! \n");
		count_pass++;
	}

	printf("-----------------------------------------------------------------------\n\n");
	printf("----------- TEST SUMMARY -------------\n");
	printf("Count passed: %d\n", count_pass);
	printf("Count failed: %d\n", count_failed);
	printf("--------------------------------------\n");

	return;
}

int main(int argc, char *argv[]) {

	run_tests();

	return(0);
}
