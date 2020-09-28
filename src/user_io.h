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
#define N_COMMANDS 4
#define N_COMMANDS_WO_PW 1
#define N_COMMANDS_W_FILES 3
#define COMMAND_IDX 1
#define PW_BUFFER_SIZE 20

// valid commands
#define LIST "list"
#define ADD "add"
#define EXTRACT "extract"
#define DELETE "delete"

typedef struct request {
	char *subcommand;
	char *password;
	char *archive;
	char **files;
	int n_files;
} Request;


void free_request(Request *request);

Request* parse_request(int argc, char *argv[]);

void print_subcommand_options();

void alert_no_archive(char *archive);

#endif /* SRC_USER_IO_H_ */
