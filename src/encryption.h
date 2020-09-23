/*
 * encryption.h
 *
 *  Created on: Sep 23, 2020
 *      Author: meganfrenkel
 */

#ifndef SRC_ENCRYPTION_H_
#define SRC_ENCRYPTION_H_

#include "sha256.h"

#define PW_CRYPT_ITER 10000
#define KEY_SIZE 256 // key size will always be 256, because we SHA-256 hash the pw to find key

BYTE* convert_password_to_cryptographic_key(char *pt_password);

BYTE* hash_sha_256(BYTE *text, int len_pt);

BYTE* get_padded_plaintext(BYTE *pt, int len_pt);

int ecb_aes_encrypt();

int aes_decrypt_file(char *filename);

#endif /* SRC_ENCRYPTION_H_ */
