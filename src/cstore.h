/*
 * cstore.h
 *
 *  Created on: Sep 22, 2020
 *      Author: meganfrenkel
 */

#ifndef SRC_CSTORE_H_
#define SRC_CSTORE_H_

#include "user_io.h"

// Any archives live in this directory, based on user's home dir
#define ARCHIVE_DIR "/encrypted_filestore_archive/"

int cstore_list(Request *request);

int cstore_add(Request *request);

int cstore_extract(Request *request);

int cstore_delete(Request *request);

#endif /* SRC_CSTORE_H_ */
