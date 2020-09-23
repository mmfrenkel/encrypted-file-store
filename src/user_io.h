/*
 * user_io.h
 *
 *  Created on: Sep 22, 2020
 *      Author: meganfrenkel
 */

#ifndef SRC_USER_IO_H_
#define SRC_USER_IO_H_

#include <stdbool.h>

#define PW_FLAG "-p"
#define PW_FLAG_INDX 2
#define ARCH_INDX 2
#define FILE_INDX 3
#define MAX_N_FILES 10
#define N_COMMANDS 5
#define COMMAND_IDX 1
#define PW_BUFFER 100

typedef struct request {
	char *subcommand;
	char *password;
	char *archive;
	char **files;
} Request;

Request* init_request();

void free_request(Request *request);

Request* parse_request(int argc, char *argv[]);

bool password_required(char *subcommand);

bool filename_required(char *subcommand);

char* extract_subcommand(int argc, char *argv[]);

bool user_submitted_pw(int argc, char *argv[]);

char* get_password(int argc, char *argv[]);

char* extract_archive_name(int argc, char *argv[]);

char** extract_filenames(int argc, char *argv[]);

void print_subcommand_options();

#endif /* SRC_USER_IO_H_ */
