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
} FileContent;

bool archive_exists(char *archive_base_path, char *archive_name);

int list_archive_files(char *archive_base_path, char *archive_name);

char* create_archive_folder(char *arch_base_path, char *archive_name);

FileContent* get_plaintext_file(char *filename);

FileContent* get_encrypted_file(char *base_path, char *archive_name, char *filename);

int write_plaintext_to_file(FileContent *fcontent);

int write_ciphertext_to_file(char *base_path, char *archive, FileContent *fcontent);

int delete_file(char *file_path);

#endif /* SRC_FILE_IO_H_ */
