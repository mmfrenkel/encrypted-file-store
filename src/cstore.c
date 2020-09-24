/*
 * cstore.c
 *
 *  Created on: Sep 22, 2020
 *      Author: meganfrenkel
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cstore.h"
#include "user_io.h"
#include "file_io.h"
#include "encryption.h"

void alert_no_archive(char *archive);

int main(int argc, char *argv[]) {

	int error = 0;
	Request *request;

	if (!(request = parse_request(argc, argv))) {
		exit(1);
	}

	printf("User selected subcommand: %s for archive: %s\n",
			request->subcommand, request->archive);

	if (strncmp(LIST, request->subcommand, strlen(LIST)) == 0) {
		error = cstore_list(request);

	} else if (strncmp(ADD, request->subcommand, strlen(ADD)) == 0) {
		error = cstore_add(request);

	} else if (strncmp(EXTRACT, request->subcommand, strlen(EXTRACT)) == 0) {
		error = cstore_extract(request);

	} else if (strncmp(DELETE, request->subcommand, strlen(DELETE)) == 0) {
		error = cstore_delete(request);
	}

	return error;
}

/**
 *
 */
int cstore_list(Request *request) {

	// if archive does't exist, create it
	if (!archive_exists(ARCHIVE_DIR, request->archive)) {
		alert_no_archive(request->archive);
		return 0;
	}

	return list_archive_files(ARCHIVE_DIR, request->archive);
}

/**
 *
 */
int cstore_add(Request *request) {

	int error;
	BYTE *key;

	if (request->n_files == 0) {
		printf("No files were specified to be added to archive.\n");
		return 0;
	}

	// if archive does't exist, create it
	if (!archive_exists(ARCHIVE_DIR, request->archive)) {
		create_archive_folder(ARCHIVE_DIR, request->archive);
	}

	if (!(key = convert_password_to_cryptographic_key(request->password))) {
		printf("Couldn't convert password to cryptographic key");
		return -1;
	}

	// add list of files to archive
	for (int i = 0; i < request->n_files; i++) {

		FileContent *fc = get_plaintext_file(request->files[i]);

		if (!fc) {
			return -1;
		}

		if ((error = ecb_aes_encrypt(fc, key))) {
			printf("There was an error performing encryption.\n");
			return -1;
		}

		if ((error = write_ciphertext_to_file(ARCHIVE_DIR, request->archive, fc))) {
			printf("Couldn't write encrpyted content to file.\n");
			return -1;
		}

		// delete the original file
		if (delete_file(request->files[i])) {
			printf(
					"Encryption step succeeded, but could not remove original, unencrypted file.\n");
		}
		printf("Succesfully encrypted %s within archive %s\n", fc->filename,
				request->archive);
	}
	return 0;
}

/**
 *
 */
int cstore_extract(Request *request) {
	int error;
	BYTE *key;

	if (request->n_files == 0) {
		printf("No files were specified to be extracted from archive.\n");
		return 0;
	}

	// if archive does't exist, create it
	if (!archive_exists(ARCHIVE_DIR, request->archive)) {
		alert_no_archive(request->archive);
		return 0;
	}

	if (!(key = convert_password_to_cryptographic_key(request->password))) {
		printf("Couldn't convert password to cryptographic key");
		return -1;
	}

	// add list of files to archive
	for (int i = 0; i < request->n_files; i++) {

		FileContent *fc = get_encrypted_file(ARCHIVE_DIR, request->archive,
				request->files[i]);

		if ((error = ecb_aes_decrypt(fc, key))) {
			printf("There was an error performing decryption.\n");
		}

		if ((error = write_plaintext_to_file(fc))) {
			printf("Couldn't write plaintext to file.\n");
		}

		printf(
				"Succesfully decrypted %s from archive %s and saved to unencrpyted "
						"file.\n", fc->filename, request->archive);
	}
	return 0;

}

/**
 *
 */
int cstore_delete(Request *request) {
	BYTE *key;

	if (request->n_files == 0) {
		printf("No files were specified for deletion from archive.\n");
		return 0;
	}

	// if archive does't exist, create it
	if (!archive_exists(ARCHIVE_DIR, request->archive)) {
		alert_no_archive(request->archive);
		return 0;
	}

	if (!(key = convert_password_to_cryptographic_key(request->password))) {
		printf("Couldn't convert password to cryptographic key");
		return -1;
	}

	return 0;
}

void alert_no_archive(char *archive) {
	printf("The archive '%s' specified doesn't exist yet. Run "
			"'cstore add' to create a new archive and add files, "
			"or specify another archive.\n", archive);
}

