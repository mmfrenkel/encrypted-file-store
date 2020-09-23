/*
 * file_io.h
 *
 *  Created on: Sep 23, 2020
 *      Author: meganfrenkel
 */

#ifndef SRC_FILE_IO_H_
#define SRC_FILE_IO_H_

typedef unsigned char BYTE;  // 8-bit byte

typedef struct file_content {
	char *filename;
	BYTE *contents;
	unsigned long size;
} FileContent;


char *get_home_dir();

char* concat_path(char * str1, char *str2);

bool archive_exists(char *archive_base_path, char *archive_name);

char* create_archive_folder(char *rel_arc_base_path, char *archive_name);

FileContent* init_file_content(char *filename, BYTE *contents,
		unsigned long n_bytes);

FileContent* get_file(char *filename);

FileContent* extract_file_content(char *filename);

#endif /* SRC_FILE_IO_H_ */
