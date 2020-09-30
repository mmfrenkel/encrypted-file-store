#!/bin/bash

./bin/cstore delete -p pass seasons fall_in_nyc.txt

echo -e "('fall_in_nyc.txt' should be missing from the list below)\n"
./bin/cstore list seasons
