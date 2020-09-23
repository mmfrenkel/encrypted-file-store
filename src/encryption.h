/*
 * encryption.h
 *
 *  Created on: Sep 23, 2020
 *      Author: meganfrenkel
 */

#ifndef SRC_ENCRYPTION_H_
#define SRC_ENCRYPTION_H_

#define PW_CRYPT_ITER 10000

int convert_password_to_cryptographic_key(char *pt_password);

int aes_encrypt_file(char *filename);

int aes_decrypt_file(char *filename);

#endif /* SRC_ENCRYPTION_H_ */

