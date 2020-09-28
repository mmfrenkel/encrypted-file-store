/*
 * file_io.c
 *
 * Contains functions necessary to perform I/O operations
 * required for files. Implements the ability to read and
 * write plaintext and ciphertext files into organized
 * FileContent structs that can be utilized in other areas
 * of the filestore program.
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

char* get_full_filepath_in_archive(char *base_path, char *archive,
		char *filename);

int write_content_to_file(char *file_path, BYTE *content, size_t n_bytes,
		char *write_mode);

int extract_file_content(char *file_path, BYTE **content);

/* ------------------------------------------------------ */

/**
 * Frees any memory associated with a specified
 * FileContent struct, including all of the members
 * of the struct that have memory allocated.
 *
 * @param pointer for a FileContent struct
 */
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
 * Determine if an archive directory already exists within the base
 * archive directory.
 *
 * @param archive_base_path, the base path for where ALL archives are
 * 							 stored within a user's file system
 * @param archive_name, the name of the archive
 * @return true, if the archive directory alreadt exists
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
 * Prints out all filenames in a specified archive.
 *
 * @param archive_base_path, the base path for where ALL archives are
 * 							 stored within a user's file system
 * @param archive_name, the name of the archive
 * @return 0 if listing was successful, -1 if an error occurred
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

	printf("Files currently encrypted within \"%s\":\n", archive_name);
	int count_files = 0;
	while ((de = readdir(dir)) != NULL) {

		// we don't need to see the . and .. content in dir
		if (strcmp(".", de->d_name) && strcmp("..", de->d_name)) {
			printf(" *  %s\n", de->d_name);
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

/**
 * Creates a new directory for a new archive within the archive "base"
 * folder, where all archives can be accessed.
 *
 * @param archive_base_path, the base path for where ALL archives are
 * 							 stored within a user's file system
 * @param archive_name, the name of the archive
 */
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
 * Opens a plaintext file, and extracts its contents into a
 * new FileContent. The FileContent created will have no information
 * about any ciphertext, as the ciphertext has yet to be created. Only
 * the size of the plaintext, the plaintext content, and the filename
 * are "filled in."
 *
 * Critically, this function assumes that all files that should be
 * encrypted are in the current directory that the user is in when they
 * run the program, or that the user has specified the entire path of
 * the file as the filename in the command line.
 *
 * @param filename, the name of the file, may or may not specify the
 * 	 				path to the file, depending on the location.
 * @return pointer to a newly allocated FileContent struct
 */
FileContent* open_plaintext_file(char *filename) {

	FileContent *file_content;
	BYTE *content = NULL;

	int n_bytes  = extract_file_content(filename, &content);

	// here we assume that the plaintext file is given as a full path, or is in the current dir
	if (n_bytes < 0) {
		return NULL;
	}
	else if (n_bytes == 0) {
		printf("Encryption is not supported for files (%s) with no contents.\n", filename);
		return NULL;
	}

	if (!(file_content = init_file_content_pt(filename, content, n_bytes))) {
		printf("Could not create FileContent struct to contain data.\n");
		return NULL;
	}
	return file_content;
}

/**
 * Opens and parses contents of an encrypted file into a new
 * FileContent struct. All encrypted files follow the same format:
 *
 * [IV] + [CIPHERTEXT] + [HMAC]
 *
 *  * The IV (initialization vector) represents the initial set of
 *    truly random characters that goes into AES encryption using cipher-block
 *    chaining (CBC). This is required to properly decrypt the encrypted
 *    file (see cryption.c).
 *
 *  * The ciphertext is the encrypted plaintext content from
 *    the original file.
 *
 *  * HMAC is used as the message authentication code to alert users if
 *    their file may be corrupted (see encryption.c).
 *
 * @param base_path, the base path for where ALL archives are
 * 					 stored within a user's file system
 * @param archive, the name of the archive
 * @param filename, the name of the original plaintext file to reopen
 * @param len_iv, the length of the IV. This will be the size of a AES block,
 * 				  if CBC is used
 * @param len_hmac_hash, the length of the hmac hash
 * @return new FileContent containing the parsed components of the encrypted file.
 */
FileContent* open_encrypted_file(char *base_path, char *archive, char *filename,
		size_t len_iv, size_t len_hmac_hash) {

	// get full path of where file should be
	char *file_path;
	if (!(file_path = get_full_filepath_in_archive(base_path, archive, filename))) {
		printf("Issue encountered creating the full file path.\n");
		return NULL;
	}

	BYTE *content = NULL;
	int n_bytes = extract_file_content(file_path, &content);
	if (n_bytes < 0) {
		return NULL;
	} else if (n_bytes == 0) {
		printf("The encrypted file %s has no contents; this is probably not what you were "
				"expecting. This file may have been tampered with.\n",
				filename);
		return NULL;
	}

	FileContent *fcontent = init_file_content_ct(filename, content, n_bytes,
			len_iv, len_hmac_hash);

	free(file_path);
	free(content); // we no longer need this unparsed content; it's now in file_content
	return fcontent;
}

/**
 * Writes information stored in FileContents to a file in the
 * encrypted archive directory. The final encrypted file contains three
 * pieces of information, in this order:
 *
 * [IV] + [CIPHERTEXT] + [HMAC]
 *
 *  * The IV (initialization vector) represents the initial set of
 *    truly random characters that goes into AES encryption using cipher-block
 *    chaining (CBC). This is required to properly decrypt the encrypted
 *    file (see cryption.c).
 *
 *  * The ciphertext is the encrypted plaintext content from
 *    the original file.
 *
 *  * HMAC is used as the message authentication code to alert users if
 *    their file may be corrupted (see encryption.c).
 *
 * @param base_path, the base path for where ALL archives are
 * 					 stored within a user's file system
 * @param archive, the name of the archive
 * @param fcontent, FileContent containing the parsed components of the
 * 					encrypted file.
 * @param len_iv, the length of the IV. This will be the size of a AES block,
 * 				  if CBC is used
 * @param len_hmac_hash, the length of the hmac hash
 * @return 0 if write is successful -1 if there is an error
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
 * Writes plaintext content stored in a FileContent struct
 * to a plaintext file in the current directory. In order to write
 * the file, the plaintext bytes and the size of the file must not
 * be NULL (other ciphertext information is not required).
 *
 * @param fcontent, FileContent containing the parsed components of the
 * 					plaintext file.
 */
int write_plaintext_to_file(FileContent *fcontent) {
	return write_content_to_file(fcontent->filename, fcontent->plaintext,
			fcontent->n_plaintext_bytes, "w");
}


/**
 * Deletes a file from an archive, permanently. The method
 * will construct the full path to the file from the various
 * components. Filename should just be the name of the file.
 *
 * @param base_path, the base path for where ALL archives are
 * 					 stored within a user's file system
 * @param archive, the name of the archive
 * @param filename, the name of the file to delete
 * @return 0 if deletion was successful, -1 if error
 */
int delete_file_from_archive(char *base_path, char *archive, char *filename) {

	// get full path of where file should be
	char *file_path;
	if (!(file_path = get_full_filepath_in_archive(base_path, archive, filename))) {
		printf("Issue encountered creating the full file path.\n");
		return -1;
	}

	int error = delete_file(file_path);
	free(file_path);
	return error;
}

/**
 * Permenantly deletes a file, specified by its file path.
 *
 * @param file_path, the path of a file to delete
 * @return 0 if deletion was successful, -1 if error
 */
int delete_file(char *file_path) {
	int del = remove(file_path);
	if (del) {
		printf("File did not delete properly. Please check on %s", file_path);
		return -1;
	}
	return 0;
}

/**
 *  Initializes/allocates memory for new FileContent struct
 *  containing information about file plaintext. It is assumed
 *  that nothing is known about the ciphertext or other content, so
 *  those fields are initialized to NULL (or 0, where applicable).
 *
 *  @param filename, the name of the file
 *  @param content, the plaintext content as an array of BYTES (unsigned chars)
 *  @param n_bytes, the number of plaintext bytes in the file
 *  return newly allocated FileContent struct, with plaintext information;
 *  	   NULL if an issue was encountered
 */
FileContent* init_file_content_pt(char *filename, BYTE *content, size_t n_bytes) {

	FileContent *file = (FileContent*) malloc(sizeof(FileContent));
	if (!file) {
		printf("Failed to allocate memory for new file.\n");
		return NULL;
	}

	// FileContent struct should get it's own memory copy of the filename
	char *filename_cpy = (char*) malloc(strlen(filename) * (sizeof(char) + 1));
	if (!filename_cpy) {
		printf("Failed to allocate memory for filename copy in "
				"file content.\n");
		free(file);
		return NULL;
	}
	memcpy(filename_cpy, filename, strlen(filename) + 1);

	// we know information at this point about the plaintext
	file->filename = filename_cpy;
	file->plaintext = content;
	file->n_plaintext_bytes = n_bytes;

	// no info about the encryption of this file yet; will be filled out later
	file->ciphertext = NULL;
	file->n_ciphertext_bytes = 0;
	file->iv = NULL;
	file->hmac_hash = NULL;

	return file;
}

/**
 *  Initializes/allocates memory for new FileContent struct
 *  containing information about file ciphertext. It is assumed
 *  that nothing is known about the plaintext or plaintext size, so
 *  those fields are initialized to NULL (or 0, where applicable).
 *
 *  The ciphertext content is initially the entire content retrieved
 *  from the file; this method parses out the individual components
 *  of that content: [IV] + [CIPHERTEXT] + [HMAC]. You can read more
 *  about these components in the write_ciphertext_to_file() function
 *  and in encryption.c.
 *
 *  @param filename, the name of the file
 *  @param content, the plaintext content as an array of BYTES (unsigned chars)
 *  @param n_bytes, the number of ciphertext bytes in the file
 *  @param len_iv, the length of the IV. This will be the size of a AES block,
 * 				   if CBC is used
 * 	@param len_hmac_hash, the length of the hmac hash
 *  return newly allocated FileContent struct, with plaintext information;
 *  	   NULL if an issue was encountered
 */
FileContent* init_file_content_ct(char *filename, BYTE *content, size_t n_bytes,
		size_t len_iv, size_t len_hmac_hash) {

	FileContent *file = (FileContent*) malloc(sizeof(FileContent));
	if (!file) {
		printf("Failed to allocate memory for new file.\n");
		return NULL;
	}

	// we need to parse information out of the encrypted content (i.e., IV, ciphertext, HMAC)
	BYTE *iv = (BYTE*) malloc(sizeof(BYTE) * len_iv);
	if (!iv) {
		printf("Could not allocate memory for IV from encrypted file.\n");
		return NULL;
	}

	size_t ct_bytes = n_bytes - len_iv - len_hmac_hash;
	BYTE *ct = (BYTE*) malloc(sizeof(BYTE) * ct_bytes);
	if (!ct) {
		printf("Could not allocate memory for ciphertext.\n");
		free(iv);
		return NULL;
	}

	BYTE *hmac_hash = (BYTE*) malloc(sizeof(BYTE) * len_hmac_hash);
	if (!hmac_hash) {
		printf(
				"Could not allocate memory for HMAC hash from encrypted file.\n");
		free(iv);
		free(ct);
		return NULL;
	}

	memcpy(iv, content, len_iv);
	memcpy(ct, &content[len_iv], ct_bytes);
	memcpy(hmac_hash, &content[len_iv + ct_bytes], len_hmac_hash);

	// FileContent struct should get it's own memory copy of the filename
	char *filename_cpy = (char*) malloc(strlen(filename) * (sizeof(char) + 1));
	if (!filename_cpy) {
		printf(
				"Failed to allocate memory for filename copy in file content.\n");
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
 * amount of memory to hold the entire file content and returns the number
 * of bytes retrieved from that file.
 *
 * The approach to opening and retrieving file content in this manner was
 * inspired by a posting by NateS on StackOverflow on September 24, 2020.
 * More information about this most can be found here:
 * https://stackoverflow.com/questions/22059189/read-a-file-as-byte-array
 *
 * @param file_path, the full path to the file to open
 * @parm content, a pointer to an array to hold the file's content
 * @return the number of BYTEs (unsigned char) retrieved from the file
 */
int extract_file_content(char *file_path, BYTE **content) {

	FILE *fp = fopen(file_path, "rb");          // open file in binary mode

	if (!fp) {
		printf("Could not open file at \"%s\". Please make sure you specified "
				"the filename correctly and retry.\n", file_path);
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
 * Writes a specified number of bytes of provided content to a
 * specified file.
 *
 * @param file_path, the full path to the file to write to
 * @param content, pointer to an array of BYTEs (unsigned char) holding
 * 		     	   content to write to the file
 * @param n_bytes, the number of BYTEs of content to write to the file
 * @param write_mode, the mode to open/write to the file with
 * @return 0 if write is successful, -1 if an error occurred
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
 * Gets the current home directory for the user; equivalent
 * to running in a shell:
 *   $> cd ~
 *   $> pwd
 *
 * This strategy for this method was inspired by a post
 * by R Samuel Klatchko on StackOverflow, accessed on September 24, 2020.
 * More information about this source and contribution can be found here:
 * https://stackoverflow.com/questions/2910377/get-home-directory-in-linux
 *
 * @return the full path of the current home directory
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
 * Helper function for creating an absolute archive path, from
 * a relative archive base path by concating information about
 * a user's home directory
 *
 * @param rel_arc_base_path, relative archive base path (relative to ~)
 * @return absolute system path to the archive directory
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
 * Helper function to create the absolute path to a file within
 * the encrypted filestore archive.
 *
 * @param base_path, the path for the base directory for all archives
 * 	                 that are a part of the encrypted file store,
 * 	                 relative to ~
 * @param archive, name of the archive
 * @param filename, name of the file (not a file path)
 * @return absolute system path to the file within the archive
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

/**
 * Helper function to concat two components of a file path
 * together. This is performed as a simple string concatination,
 * with memory allocated on the heap for the new string.
 *
 * @param str1, first component of string to be created
 * @param str2, second component of string to be created
 * @return new, concatinated string
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

