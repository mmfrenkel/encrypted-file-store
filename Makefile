# Makefile was originally inspired by Chnossos June 2, 2015 discovered at 
# https://stackoverflow.com/questions/30573481/path-include-and-src-directory-makefile 
# accessed on September 22, 2020.
#
# This Makefile was reconfigured from Makefile used on a personal project found here:
# https://github.com/mmfrenkel/lsm-tree-system

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin
LIB_DIR = encryption-algorithms
TEST_DIR = tests
ARCHIVE_DIR = ~/encrypted_filestore_archive

CC = gcc
CFLAGS = -g -Wall -std=c11
LDFLAGS = -g 

# build main executable
EXE = $(BIN_DIR)/cstore
SRC = $(wildcard $(SRC_DIR)/*.c)
SRC_OBJ = $(SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
LIB = $(wildcard $(LIB_DIR)/*.c)
LIB_OBJ = $(LIB:$(LIB_DIR)/%.c=$(OBJ_DIR)/%.o)

# build test executable, steps taken to ensure that there are not two conflicting 'mains'
TEST_EXE = $(BIN_DIR)/test_cstore
TEST_SRC = $(wildcard $(TEST_DIR)/*.c)
TEST_OBJ = $(TEST_SRC:$(TEST_DIR)/%.c=$(OBJ_DIR)/%.o)
TEST_FILT_SRC = $(filter-out src/cstore.c, $(wildcard $(SRC_DIR)/*.c)) 
TEST_SRC_OBJ = $(TEST_FILT_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

.PHONY: clean base_archive build test install

all: clean build base_archive

build: $(BIN_DIR) $(OBJ_DIR) $(EXE) 

test: clean $(BIN_DIR) $(OBJ_DIR) $(TEST_EXE) 

install: clean build base_archive cp_to_path

$(EXE): $(SRC_OBJ) $(LIB_OBJ) | $(BIN_DIR)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
	
# ---- compile encryption algorithms files separately ---

$(OBJ_DIR)/%.o: $(LIB_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# -----------------for testing -------------------------

$(TEST_EXE): $(TEST_SRC_OBJ) $(TEST_OBJ) $(LIB_OBJ) | $(BIN_DIR)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@
	
$(OBJ_DIR)/%.o: $(TEST_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
	
# ------------------------------------------------------

$(BIN_DIR) $(OBJ_DIR) $(LOG_DIR):
	mkdir -p $@
	
cp_to_path:
	cp ./bin/cstore /usr/local/bin/cstore

base_archive:
	mkdir -p $(ARCHIVE_DIR)

clean:
	rm -rf $(EXE) $(OBJ_DIR)
