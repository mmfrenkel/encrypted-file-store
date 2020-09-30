/*
 * cstore.c
 *
 * The main program that runs the encrypted file store.
 * Several of the essential functions of the file store are
 * defined in this file.
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
	BYTE *key;

	// -------------------- Get User's Request ---------------------//

	if (!(request = parse_request(argc, argv))) {
		exit(1);
	}

	// request to list files is not protected, we can simply run it
	if (strncmp(LIST, request->subcommand, strlen(LIST)) == 0) {
		error = cstore_list(request);
		free_request(request);
		exit(0);
	}

	// ------------------- Get Cryptographic Key --------------------//

	if (!(key = create_cryptographic_key(request->password, PW_CRYPT_ITER))) {
		exit(1);
	}

	// ------------ Check Archive Integrity/User Auth ---------------//

	if (!archive_exists(ARCHIVE_DIR, request->archive)) {

		printf("The archive doesn't exist.\n");

		if (strncmp(ADD, request->subcommand, strlen(ADD)) != 0) {
			printf("Trying to exit.\n");

			alert_no_archive(request->archive);
			free_request(request);
			return 0;
		}
		if ((error = create_archive_dir(ARCHIVE_DIR, request->archive))) {
			free_request(request);
			exit(1);
		}

	} else {
		if (!(archive_integrity_maintained(request->archive, key))) {
			free_request(request);
			exit(0);
		}
	}

	// ------------ Perform the Protected Action Requested ----------//

	if (strncmp(ADD, request->subcommand, strlen(ADD)) == 0) {
		error = cstore_add(request, key);

	} else if (strncmp(EXTRACT, request->subcommand, strlen(EXTRACT)) == 0) {
		error = cstore_extract(request, key);

	} else if (strncmp(DELETE, request->subcommand, strlen(DELETE)) == 0) {
		error = cstore_delete(request, key);
	}

	// --------------------------- Done! ----------------------------//

	free(key);
	free_request(request);
	return error;
}

/**
 * Checks that the integrity of the archive has been maintained
 * through three steps.
 *
 * (1) Making sure that the metadata file associated with the archive
 *     is in a structure we would expect (it's length is correct).
 * (2) Making sure that the user, giving their submitted password,
 *     has access to this archive.
 * (3) Making sure that the content of the archive as a whole,
 *     meaning the files within the archive, are in the same state
 *     as they were before.
 *
 * Both steps 2 and 3 are completed by checking HMAC codes in the metadata
 * file with recalculated HMAC codes for the archive name + key and
 * archive filenames + key combinations.
 *
 * @param archive, the name of the archive
 * @param key, crytographic key derived from the user's password
 * @returns 1 if the integrity of the archive is maintained, 0 if not, or
 * 			if the integrity of the archive could not be confirmed.
 */
int archive_integrity_maintained(char *archive, BYTE *key) {

	int auth_issue, integrity_issue, archive_ok;

	// open the metadata file and get all contents
	BYTE *metadata;
	int n_bytes = open_archive_metadata(ARCHIVE_DIR, archive, &metadata);

	// Check that content of metadata is what we expect, based on its size
	if (n_bytes != SHA256_BLOCK_SIZE * 2) {
		printf("\nINTEGRITY ALERT: The metadata file for the archive "
				"\"%s\" is not in the format expected or may be missing entirely. "
				"This archive is likely compromised!\n\n", archive);
		if (metadata)
			free(metadata);
		return 0;
	}

	// Attempt to authenticate user for archive
	if ((auth_issue = authenticate_user_for_archive(archive, key, metadata))) {
		if (auth_issue == -1) {
			printf("\nAn error occuring in verifying that you have access to "
					"this archive; can you please try again, double checking "
					"your password?\n\n");

		} else if (auth_issue == 1) {
			printf("\nINTEGRITY ALERT: Are you sure you submitted the correct "
					"password? You are not authorized to access this archive with "
					"the credentials you provided. Otherwise, this archive may "
					"have been tampered with while you were gone...\n\n");
		}
		free(metadata);
		return 0;
	}
	printf("Authenticated user for archive \"\%s\"!\n", archive);

	// Now double check that we have all of the files that we could expect
	char *filenames = concat_archive_filenames(ARCHIVE_DIR, archive);
	if (!filenames)
		return 1;

	if ((integrity_issue = verify_archive_contents(key, metadata, filenames))) {
		if (integrity_issue == -1) {
			printf("\nAn error occuring in verifying that the files in this "
					"archive haven't been tampered with. Try again.\n\n");

		} else if (integrity_issue == 1) {
			printf("\nINTEGRITY ALERT: It appears that one or more files in "
					"this archive may have been renamed or deleted, or a "
					"foreign file has been added! To confirm, please double check "
					"your password and try again.\n\n");
		}
		archive_ok = 0;
	} else {
		printf("Integrity of archive structure and filenames, checked!\n");
		archive_ok = 1;
	}

	free(metadata);
	free(filenames);
	return archive_ok;
}

/**
 * Checks that the integrity of the archive has been maintained
 * through three steps.
 *
 * @param archive, the name of the archive
 * @param key, crytographic key derived from the user's password
 * @returns 0 if the metadata file for the archive was updated
 * 			successfully, else -1
 */
int update_metadata(char *archive, BYTE *key) {

	// calculate key + archive name HMAC
	BYTE *hmac_user = compute_hmac_256(key, (unsigned char*) archive,
			strlen(archive));
	if (!hmac_user) {
		printf("Could not compute hmac for user/archive "
				"combination for metadata.\n");
		return -1;
	}

	// calculate key + filenames HMAC
	char *filenames = concat_archive_filenames(ARCHIVE_DIR, archive);
	if (!filenames) {
		free(hmac_user);
		return -1;
	}
	BYTE *hmac_files = compute_hmac_256(key, (unsigned char*) filenames,
			strlen(filenames));

	if (!hmac_files) {
		printf("Could not compute hmac for filename/archive "
				"combination for metadata.\n");
		free(hmac_user);
		free(filenames);
		return -1;
	}

	// copy both hashes into metadata
	size_t len = 2 * SHA256_BLOCK_SIZE;
	BYTE metadata[len];
	memcpy(metadata, hmac_user, SHA256_BLOCK_SIZE);
	memcpy(&metadata[SHA256_BLOCK_SIZE], hmac_files, SHA256_BLOCK_SIZE);

	// save metadata as a file
	int error = write_metadata_file(ARCHIVE_DIR, archive, metadata, len);

	// clean up
	free(filenames);
	free(hmac_user);
	free(hmac_files);
	return error;
}

/**
 * Lists all files within a specified encrypted filestore archive.
 * This is essentially a wrapper function for a function that lives
 * within the module handling files.
 *
 * @param request, Request struct containing information about
 * 				   a user's submitted request. Request must have
 * 				   the name of the archive properly assigned.
 * @return 0 if success, -1 if error
 */
int cstore_list(Request *request) {

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
int cstore_add(Request *request, BYTE *key) {
	int error;

	// if files are successfully encrypted, then can be safely deleted
	// this keeps track of which files can be deleted at the end.
	int to_delete[request->n_files];
	for (int i = 0; i < request->n_files; i++)
		to_delete[i] = 0;

	if (request->n_files == 0) {
		printf("No files were specified to be added to archive.\n");
		return 0;
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
					"for \"%s\"\n.", fc->filename);
			free_file_content(fc);
			continue;
		}

		if ((error = assign_ciphertext_hmac_256(fc, key))) {
			printf("There was an error determing HMAC \"%s\".\n", fc->filename);
			free_file_content(fc);
			continue;
		}

		if ((error = write_ciphertext_to_file(ARCHIVE_DIR, request->archive, fc,
				AES_BLOCK_SIZE, SHA256_BLOCK_SIZE))) {
			free_file_content(fc);
			continue;
		}

		printf("Succesfully encrypted \"%s\" within archive \"%s.\"\n",
				fc->filename, request->archive);

		free_file_content(fc);
		to_delete[i] = 1;
	}

	// update metadata content
	if ((error = update_metadata(request->archive, key))) {
		printf("Metadata update failed. You may not be able to access "
				"files in the archive without correct metadata, so "
				"your original plaintext file was not deleted.\n");
		return -1;
	}

	// delete the original files, but only the ones with no errors
	for (int i = 0; i < request->n_files; i++) {
		if (to_delete[i] == 1) {
			if (delete_file(request->files[i])) {
				printf("Warning: Encryption succeeded, but the original, "
						"unencrypted file \"%s\" could not be removed.\n",
						request->files[i]);
			}
		}
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
int cstore_extract(Request *request, BYTE *key) {
	int error;
	int is_compromised;

	if (request->n_files == 0) {
		printf("No files were specified to be extracted from archive.\n");
		return 0;
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
			printf("\nINTEGRITY ALERT: Are you the owner of this archive? "
					"Are you certain you submitted the correct password? "
					"If so, the integrity of %s may have been compromised!\n\n",
					fc->filename);
		}

		if ((error = write_plaintext_to_file(fc))) {
			printf("There was an error writing plaintext file "
					"for %s\n", fc->filename);
			free_file_content(fc);
			continue;
		}

		printf("Decrypted \"%s\" from archive \"%s\"", fc->filename,
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
 * this method should only be called after a user's identity has been
 * confirmed via the steps in the function archive_integrity_maintained(),
 * where the user's submitted password (in HMAC form) is checked
 * checked with what we would expect if the user was, in fact, the creator
 * of the archive.
 *
 * @param request, Request struct containing information about
 * 				   a user's submitted request for deletion.
 * @return 0 if success, -1 if error was encountered
 */
int cstore_delete(Request *request, BYTE *key) {
	int error;

	if (request->n_files == 0) {
		printf("No files were specified for deletion from archive.\n");
		return 0;
	}

	for (int i = 0; i < request->n_files; i++) {

		if ((error = delete_file_from_archive(ARCHIVE_DIR, request->archive,
				request->files[i]))) {
			printf("\nCould not delete \"%s\" from the archive \"%s\". Please make "
					"sure that the file exists in the archive and try again.\n\n",
					request->files[i], request->archive);
			continue;
		}
		printf("Deleted \"%s\" from archive \"%s.\"\n", request->files[i],
				request->archive);
	}

	// update metadata content
	if ((error = update_metadata(request->archive, key))) {
		printf("Metadata update failed. You may not be able to access "
				"files in the archive without correct metadata.\n");
		return -1;
	}
	return 0;
}

