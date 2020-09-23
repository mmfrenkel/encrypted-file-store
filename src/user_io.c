/*
 * user_io.c
 *
 *  Created on: Sep 22, 2020
 *      Author: meganfrenkel
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#include "user_io.h"

char *VALID_COMMANDS[] = { "list", "add", "extract", "delete" };
char *COMMANDS_WO_PW[] = { "list" };
char *COMMANDS_W_FILES[] = {"add", "extract", "delete" };

/**
 *
 */
Request* init_request() {

	Request *request = (Request*) malloc(sizeof(Request));
	if (request == NULL) {
		printf("Failed to allocate memory for request\n");
		return NULL;
	}

	request->archive = NULL;
	request->password = NULL;
	request->subcommand = NULL;
	request->n_files = 0;

	char *files[MAX_N_FILES] = { NULL };
	request->files = files;
	return request;
}

/**
 *
 */
void free_request(Request *request) {

	if (request->archive) {
		free(request->archive);
	}

	if (request->password) {
		free(request->password);
	}

	if (request->files) {
		for (int i = 0; i < MAX_N_FILES; i++) {
			free(request->files[i]);
		}
		free(request->files);
	}
	free(request);
}

Request* parse_request(int argc, char *argv[]) {

	Request *request = init_request();
	char *subcommand;

	// Get user's subcommand
	if ((subcommand = extract_subcommand(argc, argv)) == NULL) {
		printf("Valid subcommand was not identified.\n");

		print_subcommand_options();
		free_request(request);
		return NULL;
	}
	request->subcommand = subcommand;

	// if necessary, parse password, either from command line submissions or new request
	if (password_required(subcommand)) {
		if (!(request->password = get_password(argc, argv))) {
			printf("Unable to obtain password from user.\n");

			free_request(request);
			return NULL;
		}
	}

	// get the archive name
	if (!(request->archive = extract_archive_name(argc, argv))) {
		printf("Insufficient arguments for subcommand %s; please "
				"make sure to provide an archive name.\n", subcommand);

		free_request(request);
		return NULL;
	}

	// get filenames
	if (filename_required(subcommand)) {
		if (!(request->files = extract_filenames(argc, argv))) {
			printf("Expected at least one filename for subcommand: "
					"%s", subcommand);

			free_request(request);
			return NULL;
		}
		request->n_files = count_files(request->files);
	}
	return request;
}

/**
 *
 */
bool password_required(char *subcommand) {
	for (int i = 0; i < N_COMMANDS_WO_PW; i++) {
		if (strcmp(subcommand, COMMANDS_WO_PW[i]) == 0)  {
			return false;
		}
	}
	return true;
}

/**
 *
 */
bool filename_required(char *subcommand) {
	for (int i = 0; i < N_COMMANDS_W_FILES; i++) {
		if (strcmp(subcommand, COMMANDS_W_FILES[i]) == 0)  {
			return true;
		}
	}
	return false;
}

/**
 *
 */
char* extract_subcommand(int argc, char *argv[]) {

	for (int i = 0; i < N_COMMANDS; i++) {
		if (strcmp(VALID_COMMANDS[i], argv[COMMAND_IDX]) == 0) {

			int len_str = strlen(argv[COMMAND_IDX]);

			// we found a value subcommand
			char *subcommand = (char *) malloc(sizeof(char) * len_str);
			strncpy(subcommand, argv[COMMAND_IDX], len_str);
			return subcommand;
		}
	}
	return NULL;
}

/**
 *
 */
bool user_submitted_pw(int argc, char *argv[]) {
	// must check that both the pw flag AND additional field provided to be
	// considered a submitted password
	if (argc > PW_FLAG_INDX + 1 && strcmp(argv[PW_FLAG_INDX], PW_FLAG) == 0) {
		return true;
	}
	return false;
}

/**
 *
 */
char* get_password(int argc, char *argv[]) {

	if (user_submitted_pw(argc, argv)) {
		// user attempted to pass password via command line
		return argv[PW_FLAG_INDX + 1];
	}

	// otherwise, we have to explicitly ask the user for a password
	char *password = (char*) malloc(sizeof(char) * PW_BUFFER);
	if (password == NULL) {
		printf("Failed to allocate memory for user-submitted password\n");
		return NULL;
	}

	password = getpass("Please provide your password: ");
	return password;
}

/**
 *
 */
char* extract_archive_name(int argc, char *argv[]) {

	// if the user submitted a password, then we can expect that the field
	// for archive name is at a different location than w/o password
	int archive_name_idx = user_submitted_pw(argc, argv) ? ARCH_INDX + 2 : ARCH_INDX;

	if (argc < archive_name_idx + 1) {
		// user didn't provide enough information
		return NULL;
	}
	return argv[archive_name_idx];
}

/**
 *
 */
char** extract_filenames(int argc, char *argv[]) {
	// if the user submitted a password, then we can expect that the field
	// for filename is at a different location than w/o password
	int filename_idx = user_submitted_pw(argc, argv) ? FILE_INDX + 2 : FILE_INDX;

	 // user didn't provide filenames
	if (argc < filename_idx + 1) {
		return NULL;
	}

	// user passed more files that is currently supported; they will be warned
	if (argc - filename_idx > MAX_N_FILES) {
		printf("WARNING: Only %d files are accepted in each round; you submitted %d files.",
				MAX_N_FILES, argc - filename_idx);
	}

	char **filenames = (char**) malloc(sizeof(char*) * MAX_N_FILES);
	int curr_idx = 0;
	for (int i = filename_idx; i < argc; i++) {
		if (curr_idx < MAX_N_FILES) {
			filenames[curr_idx] = argv[i];
			curr_idx++;
		}
	}
	return filenames;
}

/**
 *
 */
int count_files(char *filenames[]) {

	int i = 0;
	while (i < MAX_N_FILES && filenames[i]) {
		i++;
	}
	return i;
}

/**
 *
 */
void print_subcommand_options(){
	printf("Valid subcommand is required to continue.\n\n"
			"Please specify one of the following subcommands:\n"
			"* list <archive>: List all files in specified archive\n"
			"* add [-p password] <archive> <filename>: Add a file at <filename> to archive\n"
			"* extract [-p password] <archive> <filename>: Extract a file in a specified archive\n"
			"* delete [-p password] <archive> <filename>: Delete file in a specified archive\n\n");
}

