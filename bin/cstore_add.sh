#!/bin/bash

echo "NYC is beautiful in the Fall!" > fall_in_nyc.txt
echo "I have never been to California, I hear all seasons are nice!" > all_seasons_california.txt
echo "Maine is beauitful in the summer; WAY too cold in winter though." > summer_in_maine.txt

./bin/cstore add -p pass seasons fall_in_nyc.txt all_seasons_california.txt summer_in_maine.txt
