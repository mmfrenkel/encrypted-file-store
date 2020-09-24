/*
 * encryption.h
 *
 *  Created on: Sep 23, 2020
 *      Author: meganfrenkel
 */

#ifndef SRC_ENCRYPTION_H_
#define SRC_ENCRYPTION_H_

#include "sha256.h"
#include "file_io.h"

#define PW_CRYPT_ITER 10000
#define KEY_SIZE 256 // key size will always be 256, because we SHA-256 hash the pw to find key

BYTE* convert_password_to_cryptographic_key(char *pt_password);

int ecb_aes_encrypt(FileContent *fcontent, BYTE *key);

int ecb_aes_decrypt(FileContent *fcontent, BYTE *key);

BYTE* hmac_256(BYTE *key, BYTE *ciphertext, size_t len_ciphertext);

#endif /* SRC_ENCRYPTION_H_ */
