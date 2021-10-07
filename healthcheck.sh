#!/bin/bash
set -o errexit -o pipefail -o xtrace
tested=${1:-+12513552703}
number=$(ls state/data | head -1)
target/debug/auxin-cli -u $number send -m '/ping' $tested
target/debug/auxin-cli -u $number receive | tee output
grep -s "pong" output
