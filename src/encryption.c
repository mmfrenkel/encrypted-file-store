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

/**
 *
 */
int convert_password_to_cryptographic_key(char *pt_password) {

	for (int i = 0; i < PW_CRYPT_ITER; i++) {
	}

	return 0;

}

int aes_encrypt_file(char *filename) {

	// 32-bit word
	// WORD key_schedule[60], idx;

	// AES takes 16 bytes (128 bits) at a time => 16 bytes
	// BYTE enc_buf[128];  // a buffer to store encrypted bytes

	// Using ECB routine (encrypt 16 bytes at a time, with constant mapping between plaintext blocks and cipher blocks)

	// aes_key_setup();
	return 0;
}

/**
 *
 */
int aes_decrypt_file(char *filename) {
	return 0;
}

