#!/bin/bash
set -exu
# default to echobot
echobot=${1:-+12406171615}
number=$(ls state/data | head -1)
auxin=target/debug/auxin-cli
#auxin=signal-cli
auxin_state="$PWD/state"
curl -s https://drand.cloudflare.com/public/latest -o latest_entropy.json
entropy=$(jq -cr '[.randomness, .round|tostring]|join(" ")' < latest_entropy.json)
time $auxin --config $auxin_state -u $number send -m "/ping $entropy" $echobot
time $auxin --config $auxin_state -u $number receive | tee output
# if this exits 0, entropy is in the output file
grep -s "$entropy" output
