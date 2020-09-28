#!/bin/bash

echo "STARTING TEST RUNS OF CSTORE; All attempts should complete gracefully :)"
echo ""

# TEST 1
echo -e "1. Attempting to encrypt single file to archive with command line password.\n"
echo "NYC is beautiful in the Fall!" > fall_in_nyc.txt
./bin/cstore add -p pass seasons fall_in_nyc.txt
echo ""

# TEST 2
echo -e "2. Attempting to encrypting multiple files to archive with command line password.\n"
echo "NYC is beautiful in the Fall!" > fall_in_nyc.txt
echo "Maine is beauitful in the summer; WAY too cold in winter though." > ./summer_in_maine.txt
./bin/cstore add -p pass seasons fall_in_nyc.txt summer_in_maine.txt
echo ""

# TEST 3
echo -e "3. Attempting to encrypt a file that doesn't exist; this should be made clear. \n"
./bin/cstore add -p pass seasons this_file_doesnt_exist.txt
echo ""

# TEST 4
echo -e "4. Attempting to encrypt two files; only one exists, so only one should succeed.\n"
echo "NYC is beautiful in the Fall!" > fall_in_nyc.txt
./bin/cstore add -p pass seasons this_file_doesnt_exist.txt fall_in_nyc.txt
echo ""

# TEST 5
echo -e "5. Attempting to see all listed files; there should be AT LEAST fall_in_winter.txt and summer_in_maine.txt.\n"
./cstore list seasons
echo ""

# TEST 6
echo -e "6. Attempting to decrypt file with the correct password. It should say: 'NYC is beautiful in the Fall!'\n"
echo "pass" | ./bin/cstore extract -p pass seasons fall_in_nyc.txt
echo ""
cat fall_in_nyc.txt
echo ""

# TEST 7
echo -e "7. Attempting to decrypt file, with the wrong password. It should give an integrity/password alert.\n"
echo "pass" | ./bin/cstore extract -p oops seasons fall_in_nyc.txt
echo ""

# TEST 8
echo -e "8. Attempting to delete file, with the wrong password. It should give an integrity/password alert.\n"
echo "pass" | ./bin/cstore delete -p oops seasons fall_in_nyc.txt
echo ""

# TEST 9
echo -e "9. Attempting to delete file, with the correct password. It should succeed.\n"
echo "pass" | ./bin/cstore delete -p pass seasons fall_in_nyc.txt
echo ""

# TEST 10
echo -e "10. Attempting to delete file, which exists, but with a typo. It should alert there is no file.\n"
echo "pass" | ./bin/cstore delete -p pass seasons fall_in_nycx.txt
echo ""

# TEST 11
echo -e "11. Attempting to add file, but user forgot to submit an archive name.\n"
echo "NYC is beautiful in the Fall!" > fall_in_nyc.txt
./bin/cstore add -p pass fall_in_nyc.txt
echo ""

# TEST 12
echo -e "12. Attempting to list files in an archive that doesn't exist.\n"
./bin/cstore list archive_that_does_not_exist
echo ""

# TEST 13
echo -e "13. Attempting to extract files from an archive that doesn't exist.\n"
./bin/cstore extract -p pass archive_that_does_not_exist fall_in_nyc.txt
echo ""

# TEST 14
echo -e "14. Attempting to delete files from an archive that doesn't exist.\n"
./bin/cstore delete -p pass archive_that_does_not_exist fall_in_nyc.txt
echo ""

# CLEAN UP
rm fall_in_nyc.txt
