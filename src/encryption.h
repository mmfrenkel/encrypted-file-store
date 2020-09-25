/*
 * encryption.h
 *
 *  Created on: Sep 23, 2020
 *      Author: meganfrenkel
 */

#ifndef SRC_ENCRYPTION_H_
#define SRC_ENCRYPTION_H_

#include "sha256.h"
#include "aes.h"
#include "file_io.h"

#define PW_CRYPT_ITER 10000
#define KEY_SIZE 256 // key size will always be 256, because we SHA-256 hash the pw to find key

BYTE* convert_password_to_cryptographic_key(char *pt_password);

int cbc_aes_encrypt(FileContent *fcontent, BYTE *key);

int cbc_aes_decrypt(FileContent *fcontent, BYTE *key);

int assign_hmac_256(FileContent *fcontent, BYTE *key);

int assign_iv(FileContent *fcontent);

int integrity_is_compromised(FileContent *fcontent, BYTE *key);

#endif /* SRC_ENCRYPTION_H_ */
