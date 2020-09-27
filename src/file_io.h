/*
 * file_io.h
 *
 *  Created on: Sep 23, 2020
 *      Author: meganfrenkel
 */

#ifndef SRC_FILE_IO_H_
#define SRC_FILE_IO_H_

#include <stdbool.h>

typedef unsigned char BYTE;  // 8-bit byte

typedef struct file_content {
	char *filename;
	BYTE *plaintext;
	unsigned long n_plaintext_bytes;
	BYTE *ciphertext;
	unsigned long n_ciphertext_bytes;
	BYTE *iv;
	BYTE *hmac_hash;
} FileContent;

void free_file_content(FileContent *fc);

bool archive_exists(char *archive_base_path, char *archive_name);

int list_archive_files(char *archive_base_path, char *archive_name);

char* create_archive_folder(char *arch_base_path, char *archive_name);

FileContent* open_plaintext_file(char *filename);

FileContent* open_encrypted_file(char *base_path, char *archive, char *filename,
		size_t len_iv, size_t len_hmac_hash);

int write_plaintext_to_file(FileContent *fcontent);

int write_ciphertext_to_file(char *base_path, char *archive,
		FileContent *fcontent, size_t len_iv, size_t len_hmac_hash);

int delete_file(char *file_path);

int delete_file_from_archive(char *base_path, char *archive, char *filename);

FileContent* init_file_content_ct(char *filename, BYTE *content, size_t n_bytes,
		size_t len_iv, size_t len_hmac_hash);

#endif /* SRC_FILE_IO_H_ */
