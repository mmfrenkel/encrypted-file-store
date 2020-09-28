#!/bin/bash

echo "STARTING TEST RUNS OF CSTORE; All attempts should complete gracefully :)"

# TEST 1
echo -e "\n1. Attempting to encrypt single file to archive with command line password."
echo -e " --------------------------------------------------------------------------------\n"
echo "NYC is beautiful in the Fall!" > fall_in_nyc.txt
./bin/cstore add -p pass seasons fall_in_nyc.txt

# TEST 2
echo -e "\n2. Attempting to encrypting multiple files to archive with command line password."
echo -e " --------------------------------------------------------------------------------\n"
echo "I have never been to California, I hear all seasons are nice!" > all_seasons_california.txt
echo "Maine is beauitful in the summer; WAY too cold in winter though." > ./summer_in_maine.txt
./bin/cstore add -p pass seasons all_seasons_california.txt summer_in_maine.txt

# TEST 3
echo -e "\n3. Attempting to encrypt a file that doesn't exist; this should be made clear."
echo -e " --------------------------------------------------------------------------------\n"
./bin/cstore add -p pass seasons this_file_doesnt_exist.txt

# TEST 4
echo -e "\n4. Attempting to encrypt two files; only one exists and the other already \nexists within the archive, so neither encryption should succeed!"
echo -e " --------------------------------------------------------------------------------\n"
echo "NYC is beautiful in the Fall!" > fall_in_nyc.txt
./bin/cstore add -p pass seasons this_file_doesnt_exist.txt fall_in_nyc.txt

# TEST 5
echo -e "\n5. Attempting to see all listed files. \nThere should be AT LEAST fall_in_winter.txt and summer_in_maine.txt."
echo -e " --------------------------------------------------------------------------------\n"
./cstore list seasons

# TEST 6
echo -e "\n6. Attempting to decrypt file with the correct password. \nIt should say: 'NYC is beautiful in the Fall!'"
echo -e " --------------------------------------------------------------------------------\n"
./bin/cstore extract -p pass seasons fall_in_nyc.txt
cat fall_in_nyc.txt

# TEST 7
echo -e "\n7. Attempting to decrypt file, with the wrong password. \nIt should give an integrity/password alert."
echo -e " --------------------------------------------------------------------------------\n"
./bin/cstore extract -p oops seasons fall_in_nyc.txt


# TEST 8
echo -e "\n8. Attempting to delete file, with the wrong password. \nIt should give an integrity/password alert."
echo -e " --------------------------------------------------------------------------------\n"
./bin/cstore delete -p oops seasons fall_in_nyc.txt

# TEST 9
echo -e "\n9. Attempting to delete file, with the correct password. \nIt should succeed."
echo -e " --------------------------------------------------------------------------------\n"
./bin/cstore delete -p pass seasons fall_in_nyc.txt

# TEST 10
echo -e "\n10. Attempting to delete file, which exists, but with a typo. \nIt should alert there is no file."
echo -e " --------------------------------------------------------------------------------\n"
./bin/cstore delete -p pass seasons fall_in_nycx.txt

# TEST 11
echo -e "\n11. Attempting to add file, but user forgot to submit an archive name."
echo -e " --------------------------------------------------------------------------------\n"
echo "NYC is beautiful in the Fall!" > fall_in_nyc.txt
./bin/cstore add -p pass fall_in_nyc.txt

# TEST 12
echo -e "\n12. Attempting to list files in an archive that doesn't exist."
echo -e " --------------------------------------------------------------------------------\n"
./bin/cstore list archive_that_does_not_exist

# TEST 13
echo -e "\n13. Attempting to extract files from an archive that doesn't exist."
echo -e " --------------------------------------------------------------------------------\n"
./bin/cstore extract -p pass archive_that_does_not_exist fall_in_nyc.txt

# TEST 14
echo -e "\n14. Attempting to delete files from an archive that doesn't exist."
echo -e " --------------------------------------------------------------------------------\n"
./bin/cstore delete -p pass archive_that_does_not_exist fall_in_nyc.txt

# CLEAN UP
rm fall_in_nyc.txt
rm -rf ~/encrypted_filestore_archive/seasons
