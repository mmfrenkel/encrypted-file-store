/*
 * file_io.c
 *
 *  Created on: Sep 23, 2020
 *      Author: meganfrenkel
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>

#include "file_io.h"

/* ----- methods that shouldn't be called externally ---- */

char* get_home_dir();

char* get_absolute_path_archive(char *rel_arc_base_path);

char* concat_path(char *str1, char *str2);

FileContent* init_file_content(char *filename, BYTE *content,
		unsigned long n_bytes, bool content_encrypted);

char* get_full_filepath_in_archive(char *base_path, char *archive,
		char *filename);

int write_content_to_file(char *file_path, BYTE *content, size_t n_bytes,
		char *write_mode);

FileContent* extract_file_content(char *filename, char *file_path,
bool is_encrypted);

/* ------------------------------------------------------ */

/**
 * Find if an archive exists in the archive directory.
 */
bool archive_exists(char *archive_base_path, char *archive_name) {

	bool found = false;

	char *archive_dir;
	if (!(archive_dir = get_absolute_path_archive(archive_base_path))) {
		printf("Could not construct archive path.\n");
		exit(1);
	}

	struct dirent *de;
	DIR *dir = opendir(archive_dir);
	if (!dir) {
		printf("Could not find the base archive location %s; run 'make base_archive' "
				"to create it before continuing\n", archive_dir);
		exit(1);
	}

	while ((de = readdir(dir)) != NULL) {
		if (strncmp(de->d_name, archive_name, strlen(archive_name)) == 0) {
			found = true;
			break;
		}
	}

	// clean-up
	closedir(dir);
	free(archive_dir);
	return found;
}

/**
 *
 */
int list_archive_files(char *archive_base_path, char *archive_name) {

	char *base_path;
	if (!(base_path = get_absolute_path_archive(archive_base_path))) {
		printf("Could not find base path of all archives.\n");
		return -1;
	}

	char *archive_dir = concat_path(base_path, archive_name);
	free(base_path);  // no longer need this intermediate path
	if (!archive_dir) {
		printf("Could not construct path for requested archive: %s.\n",archive_name);
		return -1;
	}

	struct dirent *de;
	DIR *dir = opendir(archive_dir);
	if (!dir) {
		printf("Could not find the base archive location %s; run 'make base_archive' "
				"to create it before continuing\n", archive_dir);
		free(archive_dir);
		return -1;
	}

	printf("Files currently encrypted within %s:\n", archive_name);
	int count_files = 0;
	while ((de = readdir(dir)) != NULL) {

		// we don't need to see the . and .. content in dir
		if (strcmp(".", de->d_name) && strcmp("..", de->d_name)) {
			printf("*  %s\n", de->d_name);
			count_files++;
		}
	}

	// give clarity to user; if there are no files in the archive, then say so.
	if (!count_files) {
		printf("* No files are in this archive yet.\n");
	}

	// clean-up
	closedir(dir);
	free(archive_dir);
	return 0;
}

char* create_archive_folder(char *arch_base_path, char *archive_name) {

	char *absolute_base_dir = get_absolute_path_archive(arch_base_path);
	char *new_archive_dir = concat_path(absolute_base_dir, archive_name);

	int error;
	// 0700 to provide owner rights only
	if ((error = mkdir(new_archive_dir, 0700))) {
		printf("Failed to create the new archive. Please try again.\n");
		exit(1);
	}

	free(absolute_base_dir);
	return new_archive_dir;
}

/**
 *
 */
FileContent* get_plaintext_file(char *filename) {

	printf("INSIDE PLAINTEXT FILE: %s\n", filename);
	FileContent *file_content;

	// here we assume that the plaintext file is given as a full path, or is in the current dir
	if (!(file_content = extract_file_content(filename, filename, false))) {
		printf("Could not open plaintext file content.\n");
		return NULL;
	}
	return file_content;
}

/**
 *
 */
FileContent* get_encrypted_file(char *base_path, char *archive, char *filename) {

	// get full path of where file should be
	char *file_path;

	if (!(file_path = get_full_filepath_in_archive(base_path, archive, filename))) {
		printf("Issue encountered creating the full file path.\n");
		return NULL;
	}
	printf("Full file path for encrypted file: %s\n", file_path);

	FileContent *file_content;
	if (!(file_content = extract_file_content(filename, file_path, true))) {
		return NULL;
	}

	// clean it all up
	free(file_path);
	return file_content;
}

/**
 *
 */
int write_ciphertext_to_file(char *base_path, char *archive,
		FileContent *fcontent) {

	int error;
	char *file_path;

	if (!(file_path = get_full_filepath_in_archive(base_path, archive,
			fcontent->filename))) {
		printf("Issue encountered creating the full file path.\n");
		return -1;
	}

	if ((error = write_content_to_file(file_path, fcontent->ciphertext,
			fcontent->n_ciphertext_bytes, "wb"))) {

		printf("Could not write ciphertext to file.\n");
		free(file_path);
		return -1;
	}

	free(file_path);
	return 0;
}

/**
 *
 */
int write_plaintext_to_file(FileContent *fcontent) {
	return write_content_to_file("meg_test_file.txt", fcontent->plaintext,
			fcontent->n_plaintext_bytes, "w");
}

/* Permanently deletes entire file */
int delete_file(char *file_path) {
	int del = remove(file_path);
	if (del) {
		printf("File did not delete properly. Please check on %s", file_path);
		return -1;
	}
	return 0;
}

/**
 *
 */
FileContent* init_file_content(char *filename, BYTE *content,
		unsigned long n_bytes, bool content_encrypted) {

	FileContent *file = (FileContent*) malloc(sizeof(FileContent));
	if (!file) {
		printf("Failed to allocate memory for new file.\n");
		return NULL;
	}

	if (content_encrypted) {
		file->filename = filename;
		file->ciphertext = content;
		file->n_ciphertext_bytes = n_bytes;
		file->plaintext = NULL;
		file->n_plaintext_bytes = 0;

	} else {
		file->filename = filename;
		file->plaintext = content;
		file->n_plaintext_bytes = n_bytes;
		file->ciphertext = NULL;
		file->n_ciphertext_bytes = 0;
	}
	return file;
}

/**
 *
 * https://stackoverflow.com/questions/22059189/read-a-file-as-byte-array
 * https://www.tutorialspoint.com/c_standard_library/c_function_ftell.htm
 */
FileContent* extract_file_content(char *filename, char *file_path,
		bool is_encrypted) {

	printf("File: %s...\n", file_path);
	FILE *fp = fopen(file_path, "rb");          // open file in binary mode

	if (!fp) {
		printf("Could not find/open file %s. Please make sure to specify an "
				"absolute path or make sure the file is in the current "
				"directory.\n", file_path);
		return NULL;
	}

	fseek(fp, 0, SEEK_END);                    // jump to the end of the file
	unsigned long int n_bytes = ftell(fp);     // return current file position
	rewind(fp);                                // go back to beginning of file

	// set memory for the file, including reading in content
	BYTE *file_buf = (BYTE*) malloc(n_bytes * sizeof(BYTE));
	if (!file_buf) {
		printf("Could not allocate memory for file buffer to read content.\n");
	}

	fread(file_buf, sizeof(BYTE), n_bytes, fp);
	fclose(fp);

	// now put into a FileContent
	return init_file_content(filename, file_buf, n_bytes, is_encrypted);
}

/**
 *
 */
int write_content_to_file(char *file_path, BYTE *content, size_t n_bytes,
		char *write_mode) {

	FILE *fp = fopen(file_path, write_mode);
	if (!fp) {
		printf("Unable to create file: %s\n", file_path);
		return -1;   // couldn't create file
	}

	for (int i = 0; i < n_bytes; i++) {
		fputc(content[i], fp);
	}
	fclose(fp);
	return 0;
}

/**
 * https://stackoverflow.com/questions/2910377/get-home-directory-in-linux
 */
char* get_home_dir() {

	struct passwd *pw = getpwuid(getuid());
	const char *dir = pw->pw_dir;

	char *home_dir = (char*) malloc(sizeof(char*) * (strlen(dir) + 1));
	if (!home_dir) {
		printf("Could not allocate memory for home directory.\n");
		return NULL;
	}

	memcpy(home_dir, dir, strlen(dir) + 1);
	return home_dir;
}

/**
 *
 */
char* get_absolute_path_archive(char *rel_arc_base_path) {

	char *base_dir = NULL;
	char *absolute_dir = NULL;

	// Used this approach because opendir() in archive_exists()
	// function seemingly couldn't find directory relative to ~.
	if (!(base_dir = get_home_dir()))
		return NULL;

	if (!(absolute_dir = concat_path(base_dir, rel_arc_base_path))) {
		printf("Unable to access path to base archive.\n");
		free(base_dir);
		return NULL;
	}

	free(base_dir);
	return absolute_dir;
}

/**
 *
 */
char* concat_path(char *str1, char *str2) {

	// get the full path of the archive
	int len1 = strlen(str1);
	int len2 = strlen(str2);
	char *new_str = (char*) malloc(sizeof(char) * (len1 + len2 + 1));

	if (!new_str) {
		printf("Could not allocate memory for concatenated string.\n");
		return NULL;
	}

	memcpy(new_str, str1, len1);
	memcpy(new_str + len1, str2, len2 + 1);
	return new_str;
}

/**
 *
 */
char* get_full_filepath_in_archive(char *base_path, char *archive,
		char *filename) {

	char *abs_base_dir, *archive_dir, *archive_dir_c, *full_file_path, *s;

	abs_base_dir = get_absolute_path_archive(base_path);
	if (!abs_base_dir) {
		return NULL;
	}

	archive_dir = concat_path(abs_base_dir, archive);
	free(abs_base_dir);
	if (!archive_dir) {
		return NULL;
	}

	s = "/";
	archive_dir_c = concat_path(archive_dir, s);
	free(archive_dir);
	if (!archive_dir_c)
		return NULL;

	full_file_path = concat_path(archive_dir_c, filename);
	free(archive_dir_c);
	if (!full_file_path) {
		return NULL;
	}

	return full_file_path;
}
