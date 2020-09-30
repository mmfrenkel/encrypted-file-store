/*
 * cstore.h
 *
 *  Created on: Sep 22, 2020
 *      Author: meganfrenkel
 */

#ifndef SRC_CSTORE_H_
#define SRC_CSTORE_H_

#include "user_io.h"
#include "encryption.h"

// Any archives live in this directory, based on user's home dir
#define ARCHIVE_DIR "/encrypted_filestore_archive/"

int archive_integrity_maintained(char *archive, BYTE *key);

int update_metadata(char *archive, BYTE *key);

int cstore_list(Request *request);

int cstore_add(Request *request, BYTE *key);

int cstore_extract(Request *request, BYTE *key);

int cstore_delete(Request *request, BYTE *key);

#endif /* SRC_CSTORE_H_ */
