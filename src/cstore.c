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

/**
 * Main function of encrypted filestore.
 */
int main(int argc, char *argv[]) {

	int error = 0;
	Request *request;

	if (!(request = parse_request(argc, argv))) {
		exit(1);
	}

	if (strncmp(LIST, request->subcommand, strlen(LIST)) == 0) {
		error = cstore_list(request);

	} else if (strncmp(ADD, request->subcommand, strlen(ADD)) == 0) {
		error = cstore_add(request);

	} else if (strncmp(EXTRACT, request->subcommand, strlen(EXTRACT)) == 0) {
		error = cstore_extract(request);

	} else if (strncmp(DELETE, request->subcommand, strlen(DELETE)) == 0) {
		error = cstore_delete(request);
	}

	free_request(request);
	return error;
}

/**
 * Lists all files within a specified encrypted filestore archive.
 *
 * @param request, Request struct containing information about
 * 				   a user's submitted request. Request must have
 * 				   the name of the archive properly assigned.
 * @return 0 if success, -1 if error
 */
int cstore_list(Request *request) {

	// if archive does't exist, don't do anything, just continue
	if (!archive_exists(ARCHIVE_DIR, request->archive)) {
		alert_no_archive(request->archive);
		return 0;
	}
	return list_archive_files(ARCHIVE_DIR, request->archive);
}

/**
 * Adds all files specified in a user's request to a specified
 * archive within the encrypted filestore. The Request must have
 * the archive name, user password, number of files, and file
 * names specified. If any issues are encountered with submitted files,
 * other files are attempted before the program ends.
 *
 * @param request, Request struct containing information about
 * 				   a user's submitted request for encryption.
 * @return 0 if success, -1 if error
 */
int cstore_add(Request *request) {

	int error;
	BYTE *key;

	if (request->n_files == 0) {
		printf("No files were specified to be added to archive.\n");
		return 0;
	}

	if (!archive_exists(ARCHIVE_DIR, request->archive)) {
		printf("Archive %s does not yet exist, so creating it...\n",
				request->archive);
		create_archive_folder(ARCHIVE_DIR, request->archive);
	}

	if (!(key = convert_password_to_cryptographic_key(request->password,
			PW_CRYPT_ITER))) {
		printf("Couldn't convert password to cryptographic key");
		return -1;
	}

	for (int i = 0; i < request->n_files; i++) {

		FileContent *fc = open_plaintext_file(request->files[i]);

		if (!fc) {
			free_file_content(fc);
			continue;
		}

		if ((error = assign_iv(fc))) {
			free_file_content(fc);
			free_file_content(fc);
			continue;
		}

		if ((error = cbc_aes_encrypt(fc, key))) {
			printf("There was an error performing AES CBC encryption "
					"for %s\n", fc->filename);
			free_file_content(fc);
			continue;
		}

		if ((error = assign_hmac_256(fc, key))) {
			printf("There was an error determing HMAC %s\n", fc->filename);
			free_file_content(fc);
			continue;
		}

		if ((error = write_ciphertext_to_file(ARCHIVE_DIR, request->archive, fc,
		AES_BLOCK_SIZE, SHA256_BLOCK_SIZE))) {
			printf("Couldn't write encrpyted content to file "
					"for %s\n", fc->filename);
			free_file_content(fc);
			continue;
		}

		// delete the original file
		if (delete_file(request->files[i])) {
			printf("Encryption step succeeded, but could not remove original, "
					"unencrypted file for %s\n", fc->filename);
		}

		printf(" * Succesfully encrypted \"%s\" within archive \"%s.\"\n",
				fc->filename, request->archive);
		free_file_content(fc);
	}
	return 0;
}

/**
 * Extracts all files specified in a user's request from the
 * encrypted file store archive specified. The Request must have
 * the archive name, user password, number of files, and file
 * names specified. If any issues are encountered with submitted files,
 * other files are attempted before the program ends.
 *
 * In the process of extraction, files will be checked for corruption
 * based on their hash-based authentication code (read more about the HMAC
 * function used in this project within encryption.c). If a file has an
 * integrity concern, it is still extracted (it will be jibberish), but
 * the user is warned that their file is likely compromised. It's possible
 * that the HMAC authentication fails due to an incorrect password. In that
 * case, the user can simply try again.
 *
 * @param request, Request struct containing information about
 * 				   a user's submitted request for decryption.
 * @return 0 if success, -1 if error
 */
int cstore_extract(Request *request) {
	int error;
	int is_compromised;
	BYTE *key;

	if (request->n_files == 0) {
		printf("No files were specified to be extracted from archive.\n");
		return 0;
	}

	// if archive does't exist, don't do anything
	if (!archive_exists(ARCHIVE_DIR, request->archive)) {
		alert_no_archive(request->archive);
		return 0;
	}

	if (!(key = convert_password_to_cryptographic_key(request->password,
			PW_CRYPT_ITER))) {
		printf("Couldn't convert password to cryptographic key");
		return -1;
	}

	for (int i = 0; i < request->n_files; i++) {

		FileContent *fc = open_encrypted_file(ARCHIVE_DIR, request->archive,
				request->files[i], AES_BLOCK_SIZE, SHA256_BLOCK_SIZE);

		if (!fc) {
			free_file_content(fc);
			continue;
		}

		if ((error = cbc_aes_decrypt(fc, key))) {
			free_file_content(fc);
			continue;
		}

		if ((is_compromised = integrity_check(fc, key))) {
			printf(" INTEGRITY ALERT: Are you the owner of this archive? "
					"Are you certain you submitted the correct password? "
					"If so, the integrity of %s may have been compromised!\n",
					fc->filename);
		}

		if ((error = write_plaintext_to_file(fc))) {
			printf("There was an error writing plaintext file "
					"for %s\n", fc->filename);
			free_file_content(fc);
			continue;
		}

		printf(" * Decrypted \"%s\" from archive \"%s\"", fc->filename,
				request->archive);
		if (is_compromised)
			printf(", but remember, it has been compromised... :(\n");
		else
			printf(".\n");
		free_file_content(fc);
	}
	return 0;

}

/**
 * Deletes all files specified in a user's request from the
 * encrypted file store archive specified. The Request must have
 * the archive name, user password, number of files, and file
 * names specified. If any issues are encountered with submitted files,
 * other files are attempted before the program ends.

 * In order to make sure that unauthorized users do not delete the file,
 * the file is first opened and the hash-based authentication code
 * (HMAC) stored within the file is verified against a recalculated HMAC
 * from the opened ciphertext content. If the HMAC hashes match, the
 * authentication of the user can be confirmed and the file can be deleted.
 * If an unauthorized user submits an incorrect password, the HMAC
 * hashes will not match and the file will not be deleted. Note: if a
 * file is encrypted, it may make it look like the user isn't authenicated.
 * For this reason, the user is alerted that they're either unauthorized
 * to delete files or the file is compromised.
 *
 * @param request, Request struct containing information about
 * 				   a user's submitted request for deletion.
 * @return 0 if success, -1 if error
 */
int cstore_delete(Request *request) {
	BYTE *key;
	int error;
	int is_compromised;

	if (request->n_files == 0) {
		printf("No files were specified for deletion from archive.\n");
		return 0;
	}

	// if archive doesn't exist, don't do anything
	if (!archive_exists(ARCHIVE_DIR, request->archive)) {
		alert_no_archive(request->archive);
		return 0;
	}

	if (!(key = convert_password_to_cryptographic_key(request->password,
			PW_CRYPT_ITER))) {
		printf("Couldn't convert password to cryptographic key");
		return -1;
	}

	for (int i = 0; i < request->n_files; i++) {

		FileContent *fc = open_encrypted_file(ARCHIVE_DIR, request->archive,
				request->files[i], AES_BLOCK_SIZE, SHA256_BLOCK_SIZE);

		if (!fc) {
			free_file_content(fc);
			continue;
		}

		if ((is_compromised = integrity_check(fc, key))) {
			printf("INTEGRITY ALERT: Cannot delete %s. Either you are "
				   "authorized to delete this file or this file is corrupted."
				   "Either way, your identity cannot be confirmed.",
					fc->filename);
			free_file_content(fc);
			continue;
		}

		if ((error = delete_file_from_archive(ARCHIVE_DIR, request->archive,
				request->files[i]))) {
			printf("Cannot delete %s. There was an error on deletion.",
					fc->filename);
			free_file_content(fc);
			continue;
		}
		printf(" * Deleted \"%s\" from archive \"%s.\"\n", fc->filename,
				request->archive);
		free_file_content(fc);
	}
	return 0;
}

