# Makefile was originally inspired by Chnossos June 2, 2015 discovered at 
# https://stackoverflow.com/questions/30573481/path-include-and-src-directory-makefile 
# accessed on September 22, 2020.
#
# This Makefile was reconfigured from Makefile used on a personal project found here:
# https://github.com/mmfrenkel/lsm-tree-system

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin
ARCHIVE_DIR = ~/encrypted_filestore_archive

CFLAGS = -g -Wall -std=c11
LDFLAGS = -g 

EXE = $(BIN_DIR)/cstore
SRC = $(wildcard $(SRC_DIR)/*.c)
OBJ = $(SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

.PHONY: clean base_archive build

all: clean build base_archive

build: $(BIN_DIR) $(OBJ_DIR) $(EXE) 

$(EXE): $(OBJ) | $(BIN_DIR)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BIN_DIR) $(OBJ_DIR) $(LOG_DIR):
	mkdir -p $@

base_archive:
	mkdir -p $(ARCHIVE_DIR)

clean:
	rm -rf $(BIN_DIR) $(OBJ_DIR)
