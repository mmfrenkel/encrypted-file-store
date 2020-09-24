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


int main(int argc, char *argv[]) {

	int error;

	printf("Starting here.\n");
	Request *request = parse_request(argc, argv);
	if (!request) {
		exit(1);
	}

	printf("Subcommand: %s, Password: %s, Archive: %s\n",
			request->subcommand, request->password, request->archive);

	printf("Found %d files...\n", request->n_files);

	if (request->n_files > 0) {

		for (int i = 0; i < request->n_files; i++) {

				printf("File: %s\n", request->files[i]);

				FileContent *fc = get_plaintext_file(request->files[i]);

				BYTE *key = convert_password_to_cryptographic_key(request->password);

				if ((error = ecb_aes_encrypt(fc, key))) {
					printf("There was an error performing encryption.\n");
				}

				if ((error = write_ciphertext_to_file(ARCHIVE_DIR, request->archive, fc))) {
					printf("Couldn't write encrpyted content to file.\n");
				}

				// now read encrpyted data from file

				FileContent* efc = get_encrypted_file(ARCHIVE_DIR, request->archive, request->files[i]);

				if ((error = ecb_aes_decrypt(efc, key))) {
					printf("There was an error performing decryption.\n");
				}

				if ((error = write_plaintext_to_file(efc))) {
					printf("Couldn't write plaintext to file.\n");
				}

				printf("SUCCESS\n");
		}
	}

	//printf("ARCHIVE EXISTS: %s\n", archive_exists(ARCHIVE_DIR, request->archive) ? "true" : "false");

	//char* new_arch_path = create_archive_folder(ARCHIVE_DIR, "meg_test");
	//printf("%s\n", new_arch_path);

	// BYTE *key = convert_password_to_cryptographic_key(request->password);

	return 0;
}

