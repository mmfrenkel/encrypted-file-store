/*
 * encryption.h
 *
 *  Created on: Sep 23, 2020
 *      Author: meganfrenkel
 */

#ifndef SRC_ENCRYPTION_H_
#define SRC_ENCRYPTION_H_

#include "../encryption-algorithms/sha256.h"
#include "../encryption-algorithms/aes.h"
#include "file_io.h"

#define PW_CRYPT_ITER 10000
#define KEY_SIZE 256 // key size will always be 256, because we SHA-256 hash the pw to find key

BYTE* create_cryptographic_key(char *pt_password, int iterations);

int cbc_aes_encrypt(FileContent *fcontent, BYTE *key);

int cbc_aes_decrypt(FileContent *fcontent, BYTE *key);

int assign_ciphertext_hmac_256(FileContent *fcontent, BYTE *key);

int authenticate_user_for_archive(char *archive, BYTE *key, BYTE *metadata);

int verify_archive_contents(BYTE *key, BYTE *metadata, char *filenames);

BYTE* compute_hmac_256(BYTE *key, BYTE *ct, size_t len_ct);

int assign_iv(FileContent *fcontent);

int integrity_check(FileContent *fcontent, BYTE *key);

#endif /* SRC_ENCRYPTION_H_ */
