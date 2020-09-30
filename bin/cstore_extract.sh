#!/bin/bash

./bin/cstore extract -p pass seasons fall_in_nyc.txt

echo -e "Extracted file contains:"
cat fall_in_nyc.txt
