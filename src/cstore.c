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

				FileContent *fc = get_file(request->files[i]);
				printf("%s", fc->contents);

				create_padded_plaintext(fc->contents, fc->size);

				BYTE *key = convert_password_to_cryptographic_key(request->password);

				ecb_aes_encrypt(fc->contents, fc->size, key);

		}
	}

	//printf("ARCHIVE EXISTS: %s\n", archive_exists(ARCHIVE_DIR, request->archive) ? "true" : "false");

	//char* new_arch_path = create_archive_folder(ARCHIVE_DIR, "meg_test");
	//printf("%s\n", new_arch_path);

	// BYTE *key = convert_password_to_cryptographic_key(request->password);

	return 0;
}

