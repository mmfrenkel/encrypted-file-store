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
#include <termios.h>
#include <unistd.h>

#include "user_io.h"

char *VALID_COMMANDS[] = { LIST, ADD, EXTRACT, DELETE };
char *COMMANDS_WO_PW[] = { LIST };
char *COMMANDS_W_FILES[] = { ADD, EXTRACT, DELETE };


Request* init_request();

int count_files_submitted(int argc, char *argv[]);

bool password_required(char *subcommand);

bool filename_required(char *subcommand);

bool user_submitted_pw(int argc, char *argv[]);

char* get_password(int argc, char *argv[]);

char* extract_archive_name(int argc, char *argv[]);

char* extract_subcommand(int argc, char *argv[]);

char** extract_filenames(int argc, char *argv[], int num_files);

void get_hidden_pw(char *password);


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

	char **files = NULL;
	request->files = files;
	return request;
}

/**
 *
 */
void free_request(Request *request) {

	if (request->archive) free(request->archive);

	if (request->password)  free(request->password);

	if (request->files) {
		for (int i = 0; i < request->n_files; i++) {
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

		request->n_files = count_files_submitted(argc, argv);

		if (request->n_files < 0) {
			printf("Expected at least one filename for subcommand: "
					"%s. Or perhaps you forgot to include the archive name?\n", subcommand);
			free_request(request);
			return NULL;
		}

		if (!(request->files = extract_filenames(argc, argv, request->n_files))) {
			free_request(request);
			return NULL;
		}
	}
	return request;
}

/**
 *
 */
bool password_required(char *subcommand) {
	for (int i = 0; i < N_COMMANDS_WO_PW; i++) {
		if (strcmp(subcommand, COMMANDS_WO_PW[i]) == 0) {
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
		if (strcmp(subcommand, COMMANDS_W_FILES[i]) == 0) {
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
			char *subcommand = (char*) malloc(sizeof(char) * len_str + 1);
			memcpy(subcommand, argv[COMMAND_IDX], len_str + 1);
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

	// use user-submitted pw length; otherwise, buffer length
	bool use_user_pw = user_submitted_pw(argc, argv);
	int len_pw = use_user_pw ? strlen(argv[PW_FLAG_INDX + 1]) : PW_BUFFER_SIZE;

	// otherwise, we have to explicitly ask the user for a password
	char *password = (char*) malloc(sizeof(char) * (len_pw + 1));
	if (password == NULL) {
		printf("Failed to allocate memory for user-submitted password\n");
		return NULL;
	}

	if (use_user_pw) {
		memcpy(password, argv[PW_FLAG_INDX + 1], len_pw);
		memcpy(password + len_pw, "\0", 1);
	} else {
		// get the password from the user
		// password = getpass("Please provide your password: ");
		get_hidden_pw(password);
	}
	return password;
}

/**
 * This method is used to securely obtain a password from a user (the text they
 * submit for their password is obscured).
 *
 * Originally, getpass() was attempted to achieve this purpose. This function worked
 * well  while developing on MAC, but failed to work on the Linux VM (Seems that
 * the header file with getpass() could not be identified, even though
 * `man getpass` suggested that a header file did exist), so a new approach was
 * necessary.
 *
 * Code to obtain hidden password was obtained from Stack Overflow on September 27, 2020
 * from Henrique Nascimento Gouveia and Lucas. Their contributions can be found here:
 * https://stackoverflow.com/questions/1786532/c-command-line-password-input.
 */
void get_hidden_pw(char *password) {

	static struct termios old_terminal;
	static struct termios new_terminal;

	printf("Please provide your password (at most %d characters): ",
			PW_BUFFER_SIZE);

	// get settings of the actual terminal
	tcgetattr(STDIN_FILENO, &old_terminal);

	// do not echo the characters
	new_terminal = old_terminal;
	new_terminal.c_lflag &= ~(ECHO);

	// set this as the new terminal options
	tcsetattr(STDIN_FILENO, TCSANOW, &new_terminal);

	// get the password from the user
	int c;
	int i = 0;
    while ((c = getchar()) != '\n' && c != EOF && i < PW_BUFFER_SIZE){
        password[i++] = c;
    }
    password[i] = '\0';

    printf("\n");
    printf("This is the password: %s, length: %lu\n", password, strlen(password));

	// go back to the old settings
	tcsetattr(STDIN_FILENO, TCSANOW, &old_terminal);
}

/**
 *
 */
char* extract_archive_name(int argc, char *argv[]) {

	// if the user submitted a password, then we can expect that the field
	// for archive name is at a different location than w/o password
	int archive_name_idx =
			user_submitted_pw(argc, argv) ? ARCH_INDX + 2 : ARCH_INDX;

	if (argc < archive_name_idx + 1) {
		// user didn't provide enough information
		return NULL;
	}

	int len_archive_name = strlen(argv[archive_name_idx]);
	char *archive = (char*) malloc(sizeof(char) * (len_archive_name + 1));
	if (!archive) {
		printf("Failed to allocate memroy for archive");
		return NULL;
	}
	memcpy(archive, argv[archive_name_idx], len_archive_name);
	memcpy(archive + len_archive_name, "\0", 1);
	return archive;
}


int count_files_submitted(int argc, char *argv[]) {
	// if the user submitted a password, then we can expect that the field
	// for filename is at a different location than w/o password
	int filename_idx =
			user_submitted_pw(argc, argv) ? FILE_INDX + 2 : FILE_INDX;

	if (argc < filename_idx + 1) {
		return 0;   // user didn't provide filenames
	}

	// user passed more files that is currently supported; they will be warned
	if (argc - filename_idx > MAX_N_FILES) {
		printf("WARNING: Only %d files are accepted in each round; "
				"you submitted %d files.", MAX_N_FILES, argc - filename_idx);
	}

	// how many files were submitted; this can only accept up to the maximum number?
	int num_files = MAX_N_FILES > argc - filename_idx ?
			argc - filename_idx : MAX_N_FILES;

	return num_files;
}

/**
 *
 */
char** extract_filenames(int argc, char *argv[], int num_files) {
	// if the user submitted a password, then we can expect that the field
	// for filename is at a different location than w/o password
	int filename_idx =
			user_submitted_pw(argc, argv) ? FILE_INDX + 2 : FILE_INDX;

	char **filenames = (char**) malloc(sizeof(char*) * num_files);
	if (!filenames) {
		printf("Could not parse and store submitted filenames because of "
				"memory allocation failure.\n");
		return NULL;
	}

	// put each file into the file names array
	int curr_idx = 0;

	while (filename_idx < argc && curr_idx < num_files) {

		int len_filename = strlen(argv[filename_idx]);

		char *filename = (char*) malloc(sizeof(char) * (len_filename + 1));
		if (!filename) {
			printf("Failed to allocate memory for filename.\n");
			for (int j = 0; j < curr_idx; j++)
				free(filenames[j]);
			free(filenames);
			return NULL;
		}

		memcpy(filename, argv[filename_idx], len_filename);
		memcpy(&filename[len_filename], "\0", 1);
		filenames[curr_idx] = filename;

		curr_idx++;
		filename_idx++;
	}
	return filenames;
}

/**
 *
 */
int count_files(char *filenames[]) {

	int i = 0;
	while (i < MAX_N_FILES && filenames[i])
		i++;

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

