# Encrypted File Store

This encrypted file store system allows users to submit files for encryption and storage in an archive (i.e., directory of encrypted files) on their computer. This is accomplished using the Advanced Encryption Standard (AES) with cipher block chaining (CBC) for encryption and generating hash-based message authentication codes (HMAC) using SHA-256 for integrity checking and authenication. Authorized users may encrypt, decrypt, delete, and list files in any archive as they wish, using any of the following commands.

## Use

This file store has four main commands: `add`, `extract`, `delete` and `list`, each of which will be explained below. This program puts ALL archives within an `encrypted_filestore_archive` directory, which is created in the users home directory on building the project. All files are stored within this base directory and extracted back into the current directory. To see the encrypted filestore location:

```
$ cd ~/encrypted_filestore_archive
```
### I. Add

If a user wants to encrypt a new file (e.g., `apple.txt`) into an archive (e.g., `fruits`) they could issue the following command, providing their password within the command using the `-p` flag:

```
$ ./bin/cstore add -p <password> fruits apple.txt
```
If the archive doesn't exist already, it will be created. Any action that the user would like to take following the initial creation of the archive will require that they submit the same original password; otherwise, they will get an integrity alert that their password is incorrect. Additionally, you cannot add a file to an archive if there is already a file in the archive of the same name; this is to prevent users from accidentally overriding a file they forgot that they encrypted.

Note that the program accepts multiple files at a time, so you can encrypt multiple files with a single command:

```
$ ./bin/cstore add -p <password> fruits apple.txt bananas.txt kiwi.txt
```
If a user prefers to not pass their password via the `-p` flag in echoed plaintext, they can choose to not to directly submit it and the program will prompt them for a password that will not be visible on the command line:

```
$ ./bin/cstore add fruits apple.txt bananas.txt
$ Please provide your password: 
```
### II. Extract

Once a file is successfully added to an archive, it is easy to extract the file using the same password as it was initially encrypted with:

```
$ ./bin/cstore extract -p <password> fruits apple.txt bananas.txt
```
This will extract the file from the encrypted file store into the current directory, however it will not delete it from the encrypted file store. Upon extracting the file from the file store, the program will perform an integrity check to alert users if their file may have been corrupted or tampered with. It is important for users to get their password correct, or else the decryption of the file will not be successful (they will end up with a file that looks like jibberish!). 

### III. Delete

In order to  delete the document from the archive:

```
$ ./bin/cstore delete -p <password> fruits apple.txt bananas.txt
```
Files are only deleted from an archive if users can be authenticated. If the user passes the wrong password, they will be unable to delete their file from the archive. 

### IV. List

To list all encrypted files currently in the archive:

```
$ ./bin/cstore list fruits
```
Note that a password is not required for this functionality.


## Design

In order to perform the central encryption/decryption functions of an encrypted file archive, this project utiltizes the several encryption functions. The original source code for these functions was created by Brad Conte and found at https://github.com/B-Con/crypto-algorithms. For this project, the code lives in a separate directory (`/encryption-algorithsm`) from the `src` code written as part of this project.

This encrypted filestore utilizes integrity checking at the archive level and the file level. Read more below.

### I. Generation of Cryptographic Key

The cryptographic key used in the AES encryption and HMAC hashing steps described below is derived from the user-provided password. Upon submission, the user's password is iteratively hashed 10,000 times using SHA-256. 

### I. AES CBC Encryption

In order to encrypt and decrypt files, this project makes use of the Advanced Encryption Standard (AES). AES is a block cipher, taking 16 bytes (128 bits) at a time to produce 16 bytes of ciphertext. Here, cipher block chaining (CBC) mode was used to encrypt the entire plaintext content of a file, block by block, with each plaintext block exclusive-ORed with the previous ciphertext block before encryption. This approach is advantageous because it allows two identifical plaintext blocks to be encrypted differently and thus avoids the dreaded Linux Penguin effect of modes like the electronic code book (ECB) mode. 

The CBC approach requires an initialization vector (IV), an extra block of truly random text, to XOR with the first block of plaintext to produce the first ciphertext block. In this project, a unique IV is generated for each submitted file using `/dev/urandom`. Because the same IV is required for decryption, the unique IV for each file is prepended to the ciphertext and stored in the encrypted file (i.e., IV || ciphertext).

### II. Integrity Check with Hash-Based Authentication Code (HMAC)

Hash-based authentication codes (HMAC) are used several times as part of this project as a means of authentication and integrity checking. Here, HMAC hashes are determined for using the cryptographic key derived from a user's password (`k`) and text (`ct`). For this project, the algorithm for calculating the HMAC includes three distinct steps:

(1) Derive two keys from the provided key, `k`. These are created by XORing `k` with "magic numbers," `0x5c` (`opad`) and `0x36` (`ipad`) to produce an `opad_key` and `ipad_key`.
(2) Find the SHA-256 hash of a concatination (`||`) of the first derived key (`opad_key`) and the ciphertext, `ct`.
(3) Find the SHA-256 hash of a concatination of the first hash from step (2) and the second derived key (`ipad_key`).
 
HMAC expressed in an equation: `HMAC(ct, k) = H(opad XOR k || (H(ipad XOR k || ct))`

HMAC are utilized in three distinct ways:

a. Verifying a user's identity

When a new archive is created, an HMAC is generated from the archive's name using the password-derived cryptographic key, using the algorithm above. This HMAC is sent to the `.metadata` file for the archive, such that it can be re-read from the `.metadata` file each time a user attempts to add, extract or delete files from that archive in the future. This means that only users that have the password that was used in the creation of the archive can make edits to the archive (they may still list the file). Users with the wrong password will get an integrity alert, asking for a different password.

b. Verifying the structure of an archive (i.e., filenames)

In the course of an archive's lifetime, it is possible that an adversary renames or deletes a file in the archive, or even adds a foreign file to the archive. In order to be able to alert archive users of such corruption, each time a file is added or deleted from an archive, a HMAC is generated from concatination of the names of all the encrypted files in the archive. This HMAC is added to the archive's `.metadata` file. The means that each time a user attempts to interact with an archive, this filename-based HMAC can be regenerated and compared to the HMAC stored in the `.metadata` file. If the two HMACs do not match, users are alerted that the archive is corrupted.

c. Verifying the content of an individual encrypted file

In order to make sure that the content of an individual encrypted file is not corrupted or tampered with, an HMAC generated using the cryptographic key and ciphertext for each file. Each HMAC is appended to the ciphertext and stored in the encrypted file (ct || HMAC). This means that when a person attempts to extract their encrypted file from the archive, an integrity check can be made by comparing the initial HMAC assigned to an encrypted file (which is read in from the file on decryption) with the HMAC that is recomputed from ciphertext read in from the file store and password-derived cryptographic key. The integrity check fails if the two HMAC hashes do not match. This can be achieved if either (a) a user submits the wrong password or (b) a file has been corrupted in storage. Users are warned of possible integrity violations as part of the program. Additionally, given that the HMAC is reliant on a user's submitted password, this HMAC is used similarly for determining whether a user is allowed to delete a file from the file store. 

### III. The "TLDR"

On the archive-level: When an archive is created, a `.metadata` file is created to store two HMAC hashes, one to verify a user's identity and another to validate the structure (i.e., filenames) within the archive. These are used to provide integrity alerts to users if filenames are changed/deleted/added and prevent unauthorized users from making actions on an archive.

On the file-level: Each plaintext file receives it's own IV for AES encryption using CBC mode and it's own HMAC hash derived from it's corresponding ciphertext. In order to make decryption and integrity checking possible, each encrypted file in the file store is really a concatination of IV + ciphertext + HMAC, such that the initial IV and HMAC are recoverable for decryption.

## Developer Notes

### I. Building, Testing, Installing Project

This project uses a single Makefile as a build automation tool. 

#### a. Main Program 

To build the main executable for this program run:

```
$ make all
```
This will clean and compile the code, creating a new executable `./bin/cstore` that should be used to run the file store. It will also create a new directory within your home directory called `encrypted_filestore_archive` that serves as the base directory that all archives. You can confirm that this base directory was created:

```
$ ~/encrypted_filestore_archive
```
If you'd like to actually install the project (i.e., not just build the executable but also move it to your path) then run:

```
$ sudo make install
```
This nicely allows a user to issue `cstore` instead of `./bin/cstore` to run the program. Note, however, that this command assumes that `/usr/local/bin` is on your system `PATH` and that binaries can be moved to it; hence, this command is only recommended if running this program on a Linux OS. Additionally, the downside is that you'll need to continue using `sudo` for any Makefile command (i.e., `sudo make all`), otherwise you'll get a permissions error. If you install and later decide that it isn't for you:

```
$ sudo make uninstall
```
#### b. Testing Program 

There are two sets of tests for this program: (1) unit tests and (2) a bash script that runs various iterations of possible user commands. While the unit tests ensure that the encryption steps are functioning properly, the bash script tests are mostly to confirm that the program can handle various scenarios of user inputs with grace and without throwing any errors.

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

### II. Libaries Used

This project utilizes several standard C libraries. Here are some quick notes on their use and some reasons why they were included:
* `stdlib.h` -- Allows memory allocation/deallocation.
* `string.h` -- Allows for string comparisons, determining string length (helpful for parsing command line arguments and sending request to the correct functions).
* `stdio.h` -- Helpful for interactions with user, via the command line for example, and/or printing out/logging information.
* `termios.h` -- Allows a user to submit their password on the command line without echo (i.e., the password typed is not visible). Although getpass() was attempted, header files couldn't be found properly on Linux box. Termios allows for an alternative approach.
* `unistd.h` -- Required, in combination with `terminos.h`, to allow for hidden password submission.
* `stdbool.h` -- Makes code more readable by allowing the use of `true` and `false` instead of 1 and 0.

### III. Other

This project was built using MacOS Catalina, but tested on a Google Cloud Ubuntu 20.04.1 LTS Virtual Machine (VM). In order to make sure that the VM was ready to run this program, it was necessary to install the `build-essential` package in order to gain access to the `gcc` compiler and various C libraries.

```
$ sudo apt update
$ sudo apt install build-essential
```

Additionally, `gdb` and `valgrind` were installed and used for debugging and to check for memory leaks, respectively:
```
$ sudo apt install gdb
$ sudo apt install valgrind
```

## Credits

This project was created as part of the Security I (COMS W4181) course at Columbia University in Fall 2020 with Dr. Steven Bellovin. This project makes use of basic cryptographic algorithms written by Brad Conte and found on github here: https://github.com/B-Con/crypto-algorithms. Selected code from this repository was moved to `/encryption-algorithms`.
