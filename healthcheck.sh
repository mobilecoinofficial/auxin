#!/bin/bash
set -o errexit -o pipefail -o xtrace
tested=${1:-+12513552703}
number=$(ls state/data | head -1)
auxin/auxin_cli -u $number send -m '/printerfact' $tested
auxin/auxin_cli -u $number receive | tee output
grep -i printer output
