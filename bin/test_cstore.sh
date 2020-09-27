#!/bin/bash

echo "STARTING TEST RUNS OF CSTORE; All attempts should complete gracefully :)"
echo ""

# TEST 1
echo -e "1. Attempting to encrypt single file to archive with command line password.\n"
echo "NYC is beautiful in the Fall!" > fall_in_nyc.txt
./cstore add -p pass seasons fall_in_nyc.txt
echo ""

# TEST 2
echo -e "2. Attempting to encrypting multiple files to archive with command line password.\n"
echo "NYC is beautiful in the Fall!" > fall_in_nyc.txt
echo "Maine is beauitful in the summer; WAY too cold in winter though." > ./summer_in_maine.txt
./cstore add -p pass seasons fall_in_nyc.txt summer_in_maine.txt
echo ""

# TEST 3
echo -e "3. Attempting to encrypt a file that doesn't exist; this should be made clear. \n"
./cstore add -p pass seasons this_file_doesnt_exist.txt
echo ""

# TEST 4
echo -e "4. Attempting to encrypt two files; only one exists, so only one should succeed.\n"
echo "NYC is beautiful in the Fall!" > fall_in_nyc.txt
./cstore add -p pass seasons this_file_doesnt_exist.txt fall_in_nyc.txt
echo ""

# TEST 5
echo -e "5. Attempting to see all listed files; there should be AT LEAST fall_in_winter.txt and summer_in_maine.txt.\n"
./cstore list seasons
echo ""

# TEST 6
echo -e "6. Attempting to decrypt file with the correct password. It should say: 'NYC is beautiful in the Fall!'\n"
echo "pass" | ./cstore extract -p pass seasons fall_in_nyc.txt
echo ""
cat fall_in_nyc.txt
echo ""

# TEST 7
echo -e "7. Attempting to decrypt file, with the wrong password. It should give an integrity/password alert.\n"
echo "pass" | ./cstore extract -p oops seasons fall_in_nyc.txt
echo ""

# TEST 8
echo -e "8. Attempting to delete file, with the wrong password. It should give an integrity/password alert.\n"
echo "pass" | ./cstore delete -p oops seasons fall_in_nyc.txt
echo ""

# TEST 9
echo -e "9. Attempting to delete file, with the correct password. It should succeed.\n"
echo "pass" | ./cstore delete -p pass seasons fall_in_nyc.txt
echo ""

# TEST 10
echo -e "10. Attempting to delete file, which exists, but with a typo. It should alert there is no file.\n"
echo "pass" | ./cstore delete -p pass seasons fall_in_nycx.txt
echo ""

# CLEAN UP
rm fall_in_nyc.txt
