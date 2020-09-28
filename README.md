# Encrypted File Store

This encrypted file store system allows users to submit files for encryption into a new archive (i.e., directory of encrypted files) on their computer using AES with cipher block chaining for encryption and HMAC using SHA-256 for integrity checking and authenication. Authorized users may encrypt, decrypt, delete, and list files in any archive as they wish, using any of the following commands.

## Use

This file store has four main commands: `add`, `extract`, `delete` and `list`, each of which will be explained below. By default, this program puts ALL archives within an `encrypted_filestore_archive` directory which is created in the users home directory. All files are stored within this basea directory and extracted into the current directory. To see the encrypted filestore location:

```
$ cd ~/encrypted_filestore_archive
```

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

In order to perform the central encryption/decryption functions of an encrypted file archive, this project utiltizes the several encryption functions. The original source code for these functions was created by Brad Conte and found at https://github.com/B-Con/crypto-algorithms. For this project, the code lives in a separate directory (`/encryption-algorithsm`) from the `src` code written as part of this project.

#### AES CBC Encryption

In order to encrypt and decrypt files, this project makes use of the Advanced Encryption Standard (AES). AES is a block cipher, taking 16 bytes (128 bits) at a time to produce 16 bytes of ciphertext. Here, cipher block chaining (CBC) mode was used to encrypt the whole plaintext, with each plaintext block exclusive-ORed with the previous ciphertext block before encryption. This approach is advantageous because it makes two identifical plaintext blocks will be encrypted differently and thus avoids the dreaded Linux Penguin effect of modes like the electronic code book (ECB) mode. The CBC approach requires an initialization vector (IV), an extra block of truly random text, for the first encryption block. In this project, a unique IV is generated for each submitted file using `/dev/urandom`. Because the same IV is required for decryption, the unique IV for each file is prepended to the ciphertext and stored in the encrypted file (IV + ciphertext).

The key used in the AES encryption is derived from the user-provided password. The password is iteratively hashed 10,000 times using SHA-256. This hashed password is used in AES as well as HMAC integrity checking (keep reading).

#### Integrity Check with Hash-Based Authentication Code (HMAC)

To provide users with confidence that their file content has been tampered with or corrupted, it was necessary to provide a means of authentication and integtrity checking. This is accomplished using a hash-based authenticate code, or HMAC. Here, an HMAC hash was determined for each file using the cryptographic key derived from a user's password (`k`) and the ciphertext (`ct`). For this project, the algorithm for calculating the HMAC includes these three distinct steps:

(1) Calculate two keys derived from the provided key. These are created using two "magic numbers," `0x5c` (`opad`) and `0x36` (`ipad`), and XOR-ing them with the key, `k`, to opad_key and ipad_key.
(2) Find SHA-256 hash of a concatination (`||`) of the first derived key (opad_key) and the ciphertext, `ct`.
(3) Find SHA-256 hash of a concatination of the first hash and the second derived key (ipad_key).
 
Expressed in an equation: `HMAC(ct, k) = H(opad XOR k || (H(ipad XOR k || ct))`

This HMAC code is appended to the ciphertext and stored in the encrypted file. This enables an integrity check to be achieved by comparing the initial HMAC hash assigned to an encrypted file (which is read in from the file on decryption) with the HMAC code that is recomputed from ciphertext read in from the file store and password-derived cryptographic key. The integrity check fails if the two HMAC hashes do not match. This can be achieved if either (a) a user submits the wrong password or (b) a file has been corrupted in storage. Users are warned of possible integrity violations as part of the program. Additionally, given that the HMAC is reliant on a user's submitted password, this HMAC code is used similarly for determining whether a user is allowed to delete a file from the file store. 

#### TLDR
As part of encryption, each plaintext file receives it's own IV for CBC mode AES encryption and based on the ciphertext generated, it's own HMAC SHA-256 hash. In order to make decryption and integrity checking possible, each encrypted file in the file store is really a concatination of IV + ciphertext + HMAC, such that the decryption step can recover the initial IV and HMAC.


## Developer Notes

This project uses a single Makefile as a build automation tool. 

To build the main executable for this program run:

```
$ make all
```
This will clean and compile the code, creating a new executable `./bin/cstore` that should be used to run the file store. It will also create a new directory within your home directory called `encrypted_filestore_archive` that serves as the base directory that all archives live within. You can confirm that this base directory was created:

```
$ ~/encrypted_filestore_archive
```
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

This project utilizes several standard C libraries. Here are some quick notes on their use and some reasons why they were included:
* `stdlib.h` -- Allows memory allocation/deallocation.
* `string.h` -- Allows for string comparisons, determining string length (helpful for parsing command line arguments and sending request to the correct functions).
* `stdio.h` -- Helpful for interactions with user, via the command line for example, and/or printing out/logging information.
* `termios.h` -- Allows a user to submit their password on the command line without echo (i.e., the password typed is not visible). Although getpass() was attempted, header files couldn't be found properly on Linux box. Termios allows for an alternative approach.
* `unistd.h` -- Required, in combination with `terminos.h`, to allow for hidden password submission.
* `stdbool.h` -- Makes code more readable by allowing the use of `true` and `false` instead of 1 and 0.

### Other

This project was built using MacOS Catalina, but tested on a Google Cloud Ubuntu 20.04.1 LTS Virtual Machine (VM). In order to make sure that the VM was ready to run this program, it was necessary to install the `build-essential` package in order to gain access to the `gcc` compiler and various C libraries.

```
$ sudo apt update
$ sudo apt install build-essential
```

Additionally, `gdb` and `valgrind` where installed via:
```
$ sudo apt install gdb
$ sudo apt install valgrind
```

### Credits

This project was created as part of the Security I (COMS W4181) course at Columbia University in Fall 2020. This project makes use of basic cryptographic algorithms written by Brad Conte and found on github here: https://github.com/B-Con/crypto-algorithms. 
