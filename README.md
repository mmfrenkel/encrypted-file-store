# Encrypted File Store

This encrypted file store system allows users to submit files for encryption into a new archive (i.e., directory of encrypted files) on their computer using AES with cipher block chaining for encryption and HMAC using SHA-256 for integrity checking and authenication. Authorized users may encrypt, decrypt, delete, and list files in any archive as they wish, using any of the following commands.

## Use

This file store has four main commands: `add`, `extract`, `delete` and `list`, each of which will be explained below.

If a user wants to encrypt a new file (e.g., `apple.txt`) into an archive (e.g., `fruits`) they could issue:

```
$ ./bin/cstore add -p <password> fruits apple.txt
```
If the archive doesn't exist already, it will be created. Note also that the program accepts multiple files at a time, so you can encrypt multiple files with a single command:

```
$ ./bin/cstore add -p <password> fruits apple.txt bananas.txt
```
If users choose to not pass their password via the `-p` flag in plaintext, the program will prompt them for a password that will not be visible on the command line:

```
$ ./bin/cstore add fruits apple.txt bananas.txt
$ Please provide your password: 
```

Once a file is successfully added to an archive, it is easy to extract the file using the same password as it was initially encrypted with:

```
$ ./bin/cstore extract -p <password> fruits apple.txt bananas.txt
```
This will extract the file from the encrypted file store into the current directory, however it will not delete it from the encrypted file store. Upon extracting the file from the file store, the program will perform an integrity check to alert users if their file may have been corrupted or tampered with. It is important for users to get their password correct, or else the decryption of the file will not be successful (they will end up with a file that looks like jibberish!). 

In order to definitely delete the document from the archive:

```
$ ./bin/cstore delete -p <password> fruits apple.txt bananas.txt
```
Files are only deleted from an archive if users can be authenticated. If the user passes the wrong password, they will be unable to delete their file from the archive.


## Design

#### AES CBC Encryption

#### Integrity Check with Hash-Based Authentication Code (HMAC)

## Developer Notes

This project uses a Makefile to facilitate linking and compling this code. 

To build the main executable for this program run:

```
$ make all
```
This will clean and compile the code, creating a new executable `./bin/cstore` that should be used to run the file store. It will also create a new directory within your uses home directory called `encrypted_filestore_archive`. You can confirm that this base directory was created:

```
$ ~/encrypted_filestore_archive
```
There are two sets of tests for this program: (1) unit tests and (2) a bash script that runs a set of possible user commands. 

Unit tests can be compiled into a new executable and run via the following sequence of commands:

```
$ make test
$ ./bin/test_cstore
```
The bash script should be run after cleaning and compiling the main executable:

```
$ make all
$ ./bin/test_cstore.sh
```
The bash script tests are mostly to confirm that the program can handle various scenarios of user inputs with grace and without throwing any errors.

### Other

This project was built using MacOS Catalina, but tested on a Google Cloud Ubuntu 20.04.1 LTS Virtual Machine (VM). In order to make sure that the VM was ready to run this program, it was necessary to install the `build-essential` package in order to gain access to the `gcc` compiler and various C libraries.

```
$ sudo apt update
$ sudo apt install build-essential
```
