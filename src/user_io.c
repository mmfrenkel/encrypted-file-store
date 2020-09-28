/*
 * user_io.c
 *
 *  Responsible for all command line interaction with
 *  users, including parsing information provided into
 *  the form of a 'Request' that holds all the necessary
 *  information in a structured and clean form to
 *   provide further instruction to the rest of the program.
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

/* ----- methods that shouldn't be called externally ---- */

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

/* ------------------------------------------------------ */

/**
 * Initializes an empty Request struct.
 *
 * @return pointer to the newly allocated, empty Request
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
 * Frees the memory allocated to a Request struct.
 *
 * @param request, a pointer to the Request object to deallocate
 * @return void
 */
void free_request(Request *request) {

	if (request->archive)
		free(request->archive);

	if (request->password)
		free(request->password);

	if (request->files) {
		for (int i = 0; i < request->n_files; i++) {
			free(request->files[i]);
		}
		free(request->files);
	}
	free(request);
}

/**
 * Parses information from command line arguments into
 * a new Request struct that is returned as a pointer. Information
 * parsed includes:
 * 1. Subcommand (if not valid option, return NULL)
 * 2. Password (if required for subcommand)
 * 3. Archive Name
 * 4. Filenames (if required for subcommand).
 *
 * @param argc, the number of arguments submitted via command line
 * @param argv, list of points to string arguments
 * @return request
 */
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

	// get archive name
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
					"%s. Or perhaps you forgot to include the archive name?\n",
					subcommand);
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
 * Determines if a password is required for a given subcommand.
 *
 * @param subcommand, a string representing the selected subcommand
 * @return boolean, true if the subcommand requires a password
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
 * Determines if filenames are required for a given subcommand.
 *
 * @param subcommand, a string representing the selected subcommand
 * @return boolean, true if the subcommand requires filenames
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
 * "Extracts" the subcommand from command line arguments,
 * allocating memory for the string and returning a pointer
 * to the newly allocated memory. It is expected that the subcommand
 * will be the second argument provided by the user, for example:
 *
 * ./bin/cstore add ...
 * ./bin/cstore extract ...
 *
 * @param argc, the number of arguments submitted via command line
 * @param argv, list of points to string arguments
 * @return pointer for the memory holding the subcommand, NULL is
 * 		   returned if the subcommand isn't in the list of valid commands.
 */
char* extract_subcommand(int argc, char *argv[]) {

	for (int i = 0; i < N_COMMANDS; i++) {
		if (strcmp(VALID_COMMANDS[i], argv[COMMAND_IDX]) == 0) {

			int len_str = strlen(argv[COMMAND_IDX]);

			// we found a value subcommand
			char *subcommand = (char*) malloc(sizeof(char) * len_str + 1);
			if (!subcommand) {
				printf("Failed to allocated memory for subcommand.\n");
				return NULL;
			}

			memcpy(subcommand, argv[COMMAND_IDX], len_str + 1);
			return subcommand;
		}
	}
	return NULL;
}


/**
 * "Extracts" the password from the command line arguments, if a user
 * did in fact submit them via the command line, or asks the user
 * to submit their password via a hidden field. The maximum length of the
 * password is specified. It is expected that the password submitted
 * by the user will be present after a `-p` flag, stictly as the fourth
 * argument, as shown below.
 *
 * ./bin/cstore add -p password ...
 *
 * @param argc, the number of arguments submitted via command line
 * @param argv, list of points to string arguments
 * @return pointer for the memory holding the user-submitted password
 */
char* get_password(int argc, char *argv[]) {

	// use user-submitted pw length; otherwise, buffer length
	bool use_user_pw = user_submitted_pw(argc, argv);
	int len_pw = use_user_pw ? strlen(argv[PW_FLAG_INDX + 1]) : PW_BUFFER_SIZE;

	// otherwise, we have to explicitly ask the user for a password
	char *password = (char*) malloc(sizeof(char) * (len_pw + 1));
	if (!password) {
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
 * Determines if a user submitted a password via the command line,
 * i.e., via a '-p' flag.
 *
 * @param argc, the number of arguments submitted via command line
 * @param argv, list of points to string arguments
 * @returns true, if the user submitted a password
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
 * This method is used to securely obtain a password from a user (the text they
 * submit for their password is obscured), saving the contents into the memory
 * space specified by the parameter, password.
 *
 * Originally, getpass() was attempted to achieve this purpose. This function worked
 * well  while developing on MAC, but failed to work on the Linux VM (Seems that
 * the header file with getpass() could not be identified, even though
 * `man getpass` suggested that a header file did exist), so a new approach was
 * necessary.
 *
 * Code to obtain hidden password was heavily inspired by a posting on
 * Stack Overflow, found on September 27, 2020, that was created by
 * Henrique Nascimento Gouveia and Lucas. Their contributions can be found here:
 * https://stackoverflow.com/questions/1786532/c-command-line-password-input.
 *
 * @param password, the memory location that will hold the user-provided password.
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

	// go back to the old settings
	tcsetattr(STDIN_FILENO, TCSANOW, &old_terminal);
}

/**
 * "Extracts" the user-submitted archive name from the command line
 * arguments. it is expected that the archive name will be specified as
 * the third argument, if the password is not submitted, or the fifth
 * argument if it is. For example:
 *
 * ./bin/cstore add ARCHIVE_NAME ...
 *              OR
 * ./bin/cstore -p password ARCHIVE_NAME ...
 *
 * @param argc, the number of arguments submitted via command line
 * @param argv, list of points to string arguments
 * @return pointer for the memory holding the user-submitted archive name
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

/**
 * "Extracts" the user-submitted filenames from the command line
 * arguments. it is expected that the filenames name will be specified
 * after the archive name, as in:
 *
 * ./bin/cstore add archive FILENAME_ONE FILENAME_TWO ...
 *              OR
 * ./bin/cstore add -p password archive FILENAME_ONE FILENAME_TWO ...
 *
 * @param argc, the number of arguments submitted via command line
 * @param argv, list of points to string arguments
 * @param num_files, the number of filenames to discover
 * @return pointer to an array of filenames.
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
 * Counts the number of filenames submitted by the user,
 * based on the command line arguments.
 *
 * @param argc, the number of arguments submitted via command line
 * @param argv, list of points to string arguments
 * @return a count of the number of filenames submitted
 */
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
 * Prints out the available subcommands for users. This method
 * should be called when a user doesn't submit one of the selected
 * valid subcommands and needs further information to succeed in
 * using the filestore.
 */
void print_subcommand_options(){
	printf("Valid subcommand is required to continue.\n\n"
			"Please specify one of the following subcommands:\n"
			"* list <archive>: List all files in specified archive\n"
			"* add [-p password] <archive> <filename>: Add a file at <filename> to archive\n"
			"* extract [-p password] <archive> <filename>: Extract a file in a specified archive\n"
			"* delete [-p password] <archive> <filename>: Delete file in a specified archive\n\n");
}

void alert_no_archive(char *archive) {
	printf("The archive '%s' specified doesn't exist yet. Run "
			"'cstore add' to create a new archive and add files, "
			"or specify another archive.\n", archive);
}

