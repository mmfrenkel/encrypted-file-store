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


int main(int argc, char *argv[]) {

	printf("Starting here.\n");
	Request *request = parse_request(argc, argv);
	if (!request) {
		exit(1);
	}

	printf("Subcommand: %s, Password: %s, Archive: %s, Filename: \n",
			request->subcommand, request->password, request->archive);

	return 0;
}

