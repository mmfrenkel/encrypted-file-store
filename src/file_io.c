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

FileContent* init_file_content_pt(char *filename, BYTE *content, size_t n_bytes);

FileContent* init_file_content_ct(char *filename, BYTE *content, size_t n_bytes,
		size_t len_iv, size_t len_hmac_hash);

char* get_full_filepath_in_archive(char *base_path, char *archive,
		char *filename);

int write_content_to_file(char *file_path, BYTE *content, size_t n_bytes,
		char *write_mode);

int extract_file_content(char *file_path, BYTE **content);

/* ------------------------------------------------------ */


void free_file_content(FileContent *fc) {

	if(!fc) return;

	if (fc->filename) free(fc->filename);

	if (fc->plaintext) free(fc->plaintext);

	if (fc->ciphertext) free(fc->ciphertext);

	if (fc->iv) free(fc->iv);

	if (fc->hmac_hash) free(fc->hmac_hash);

	free(fc);
}

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
FileContent* open_plaintext_file(char *filename) {

	FileContent *file_content;
	BYTE *content = NULL;

	int n_bytes  = extract_file_content(filename, &content);

	// here we assume that the plaintext file is given as a full path, or is in the current dir
	if (n_bytes < 0) {
		printf("Could not open plaintext file content.\n");
		return NULL;
	}

	if (!(file_content = init_file_content_pt(filename, content, n_bytes))) {
		printf("Could not create FileContent struct to contain data.\n");
		return NULL;
	}
	return file_content;
}

/**
 *
 */
FileContent* open_encrypted_file(char *base_path, char *archive, char *filename,
		size_t len_iv, size_t len_hmac_hash) {

	// get full path of where file should be
	char *file_path;
	if (!(file_path = get_full_filepath_in_archive(base_path, archive, filename))) {
		printf("Issue encountered creating the full file path.\n");
		return NULL;
	}
	printf("Full file path for encrypted file: %s\n", file_path);

	BYTE *content = NULL;
	int n_bytes = extract_file_content(file_path, &content);
	if (n_bytes < 0) {
		printf("Could not extract file content from encrypted file.\n");
		return NULL;
	}

	FileContent *file_content = init_file_content_ct(filename, content, n_bytes,
			len_iv, len_hmac_hash);

	free(file_path);
	free(content); // we no longer need this unparsed content; it's now in file_content
	return file_content;
}

/**
 *
 */
int write_ciphertext_to_file(char *base_path, char *archive,
		FileContent *fcontent, size_t len_iv, size_t len_hmac_hash) {

	// we need to concatinate the IV + ciphertext + HMAC, in this order first
	size_t total_bytes = fcontent->n_ciphertext_bytes + len_iv + len_hmac_hash;
	BYTE content[total_bytes];

	memcpy(content, fcontent->iv, len_iv);

	memcpy(&content[len_iv], fcontent->ciphertext,
			fcontent->n_ciphertext_bytes);

	memcpy(&content[len_iv + fcontent->n_ciphertext_bytes], fcontent->hmac_hash,
			len_hmac_hash);

	// get the full file path for where the file should be saved
	char *file_path;
	if (!(file_path = get_full_filepath_in_archive(base_path, archive,
			fcontent->filename))) {
		printf("Issue encountered creating the full file path.\n");
		return -1;
	}

	// write the concatinated content to file at full file path
	int error;
	if ((error = write_content_to_file(file_path, content, total_bytes, "wb"))) {
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
	return write_content_to_file(fcontent->filename, fcontent->plaintext,
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
FileContent* init_file_content_pt(char *filename, BYTE *content, size_t n_bytes) {

	FileContent *file = (FileContent*) malloc(sizeof(FileContent));
	if (!file) {
		printf("Failed to allocate memory for new file.\n");
		return NULL;
	}

	// FileContent struct should get it's own memory copy of the filename
	char *filename_cpy = (char *) malloc(strlen(filename) * (sizeof(char) + 1));
	if (!filename_cpy) {
		printf("Failed to allocate memory for filename copy in file content.\n");
		free(file);
		return NULL;
	}
	memcpy(filename_cpy, filename, strlen(filename) + 1);

	// we know information at this point about the plaintext
	file->filename = filename_cpy;
	file->plaintext = content;
	file->n_plaintext_bytes = n_bytes;

	// no info about the encryption of this file yet; will be filled out as needed later
	file->ciphertext = NULL;
	file->n_ciphertext_bytes = 0;
	file->iv = NULL;
	file->hmac_hash = NULL;

	return file;
}


/**
 *
 */
FileContent* init_file_content_ct(char *filename, BYTE *content, size_t n_bytes,
		size_t len_iv, size_t len_hmac_hash) {

	FileContent *file = (FileContent*) malloc(sizeof(FileContent));
	if (!file) {
		printf("Failed to allocate memory for new file.\n");
		return NULL;
	}

	// we need to parse information out of the encrypted content (i.e., IV, ciphertext, HMAC)
	BYTE* iv = (BYTE *) malloc(sizeof(BYTE) * len_iv);
	if (!iv) {
		printf("Could not allocate memory for IV from encrypted file.\n");
		return NULL;
	}

	size_t ct_bytes = n_bytes - len_iv - len_hmac_hash;
	BYTE *ct = (BYTE *) malloc(sizeof(BYTE) * ct_bytes);
	if (!ct) {
		printf("Could not allocate memory for ciphertext.\n");
		free(iv);
		return NULL;
	}

	BYTE *hmac_hash = (BYTE *) malloc(sizeof(BYTE) * len_hmac_hash);
	if (!hmac_hash) {
		printf("Could not allocate memory for HMAC hash from encrypted file.\n");
		free(iv);
		free(ct);
		return NULL;
	}

	memcpy(iv, content, len_iv);
	memcpy(ct, &content[len_iv], ct_bytes);
	memcpy(hmac_hash,  &content[len_iv + ct_bytes], len_hmac_hash);

	// FileContent struct should get it's own memory copy of the filename
	char *filename_cpy = (char *) malloc(strlen(filename) * (sizeof(char) + 1));
	if (!filename_cpy) {
		printf("Failed to allocate memory for filename copy in file content.\n");
		free(file);
		return NULL;
	}
	memcpy(filename_cpy, filename, strlen(filename) + 1);

	// we know things about the ciphertext...
	file->filename = filename_cpy;
	file->ciphertext = ct;
	file->n_ciphertext_bytes = ct_bytes;
	file->iv = iv;
	file->hmac_hash = hmac_hash;

	// ... we don't know anything about the plaintext yet
	file->plaintext = NULL;
	file->n_plaintext_bytes = 0;

	return file;
}

/**
 * Extracts all content from a file at the provided file path and saves
 * it into memory pointed to by content. The method allocates the required
 * amount of memory to hold the entire file content.
 *
 * https://stackoverflow.com/questions/22059189/read-a-file-as-byte-array
 * https://www.tutorialspoint.com/c_standard_library/c_function_ftell.htm
 */
int extract_file_content(char *file_path, BYTE **content) {

	FILE *fp = fopen(file_path, "rb");          // open file in binary mode

	if (!fp) {
		printf("Could not find/open file %s. Please make sure to specify an "
				"absolute path or make sure the file is in the current "
				"directory.\n", file_path);
		return -1;
	}

	fseek(fp, 0, SEEK_END);                    // jump to the end of the file
	unsigned long int n_bytes = ftell(fp);     // return current file position
	rewind(fp);                                // go back to beginning of file

	// set memory for the file, including reading in content
	BYTE *file_buf = (BYTE*) malloc(n_bytes * sizeof(BYTE));
	if (!file_buf) {
		printf("Could not allocate memory for file buffer to read content.\n");
		return -1;
	}

	fread(file_buf, sizeof(BYTE), n_bytes, fp);
	fclose(fp);

	*content = file_buf;
	return n_bytes;
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
