/*
 * file_io.c
 *
 *  Created on: Sep 23, 2020
 *      Author: meganfrenkel
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>

#include "file_io.h"


/**
 *
 */
char *get_home_dir() {

	struct passwd *pw = getpwuid(getuid());
	const char *dir = pw->pw_dir;

	char * home_dir = (char *) malloc(strlen(dir) + 1);
	if (!home_dir) {
		printf("Could not allocate memory for home directory.\n");
		return NULL;
	}

	memcpy(home_dir, dir, strlen(dir) + 1);
	return home_dir;
}

/**
 *
 */
char* get_absolute_path_archive(char *rel_arc_base_path) {

	char *base_dir;
	char *absolute_dir;

	// Used this approach because opendir() in archive_exists()
	// function seemingly couldn't find directory relative to ~.
	if (!(base_dir = get_home_dir()) ||
			!(absolute_dir = concat_path(base_dir, rel_arc_base_path))) {
		printf("Unable to access path to base archive.\n");
		exit(1);
	}

	free(base_dir);
	return absolute_dir;
}


/**
 *
 */
char* concat_path(char * str1, char *str2) {

	// get the full path of the archive
	int len1 = strlen(str1);
	int len2 = strlen(str2);
	char *new_str = (char*) malloc(sizeof(char) * (len1 + len2 + 1));

	if (!new_str) {
		printf("Could not allocate memory for concatenated string.\n");
		return NULL;
	}

	memcpy(new_str, str1, len1);
	memcpy(new_str + len1, str2, len2 + 1);
	return new_str;
}

/**
 * Find if an archive exists in the archive directory.
 */
bool archive_exists(char *rel_arc_base_path, char *archive_name) {

	struct dirent *de;
	bool found = false;
	char *absolute_arc_dir = get_absolute_path_archive(rel_arc_base_path);

	DIR *dir = opendir(absolute_arc_dir);
	if (!dir) {
		printf("Could not find the base archive location %s; run 'make base_archive' "
				"to create it before continuing\n", absolute_arc_dir);
		exit(1);
	}

	while ((de = readdir(dir)) != NULL) {
		printf("FOUND %s\n", de->d_name);
		if (strncmp(de->d_name, archive_name, strlen(archive_name)) == 0) {
			found = true;
			break;
		}
	}

	// clean-up
	closedir(dir);
	free(absolute_arc_dir);
	return found;
}

char* create_archive_folder(char *rel_arc_base_path, char *archive_name) {

	char *absolute_base_dir = get_absolute_path_archive(rel_arc_base_path);
	char *new_archive_dir = concat_path(absolute_base_dir, archive_name);

	int error;
	// 0700 to provide owner rights only
	if ((error = mkdir(new_archive_dir, 0700))){
		printf("Failed to create the new archive. Please try again.\n");
		exit(1);
	}

	free(absolute_base_dir);
	return new_archive_dir;
}

/**
 *
 */
FileContent* init_file_content(char *filename, BYTE *contents,
		unsigned long n_bytes) {

	FileContent *file = (FileContent*) malloc(sizeof(FileContent));
	if (!file) {
		printf("Failed to allocate memory for new file.\n");
		return NULL;
	}

	file->filename = filename;
	file->contents = contents;
	file->size = n_bytes;

	return file;
}

/**
 *
 */
FileContent* get_file(char *filename) {

	// extract contents of file
	char *name = (char*) malloc(sizeof(char) * strlen(filename));
	if (!name) {
		printf("Failed to allocate memory for name\n");
		return NULL;
	}
	strncpy(name, filename, strlen(filename));

	FileContent *file_content;
	if (!(file_content = extract_file_content(name))) {
		free(name);
		return NULL;
	}

	return file_content;
}

/**
 * https://stackoverflow.com/questions/22059189/read-a-file-as-byte-array
 * https://www.tutorialspoint.com/c_standard_library/c_function_ftell.htm
 */
FileContent* extract_file_content(char *filename) {

	FILE *fp = fopen(filename, "rb");          // open file in binary mode

	if (!fp) {
		printf("Could not find/open file %s. Please make sure it "
				"is the current directory", filename);
		return NULL;
	}

	fseek(fp, 0, SEEK_END);                    // jump to the end of the file
	unsigned long int n_bytes = ftell(fp);     // return current file position
	rewind(fp);                                // go back to beginning of file

	// set memory for the file, including reading in content
	BYTE *file_buf = (BYTE*) malloc(n_bytes * sizeof(BYTE));
	if (!file_buf) {
		printf("Could not allocate memory for file buffer to read content.\n");
	}

	fread(file_buf, sizeof(BYTE), n_bytes, fp);
	fclose(fp);

	// now put into a FileContent
	return init_file_content(filename, file_buf, n_bytes);
}
