# Makefile was originally inspired by Chnossos June 2, 2015 discovered at 
# https://stackoverflow.com/questions/30573481/path-include-and-src-directory-makefile 
# accessed on September 22, 2020.
#
# This Makefile was reconfigured from Makefile used on a personal project found here:
# https://github.com/mmfrenkel/lsm-tree-system

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

CFLAGS = -g -Wall -std=c11
LDFLAGS = -g 

EXE = $(BIN_DIR)/cstore
SRC = $(wildcard $(SRC_DIR)/*.c)
OBJ = $(SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

.PHONY: clean all delete

all: clean $(BIN_DIR) $(OBJ_DIR) $(EXE)

$(EXE): $(OBJ) | $(BIN_DIR)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BIN_DIR) $(OBJ_DIR) $(LOG_DIR):
	mkdir -p $@

clean:
	rm -rf $(BIN_DIR) $(OBJ_DIR)
