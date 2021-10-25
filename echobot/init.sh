#!/bin/bash
set -exu
echobot=${1:-12406171615}
# this is a persistent directory on fly iad
# see fly.toml for reference
auxin_state="/auxin_state"
state_path=$auxin_state/data/+$echobot
# only called once
if [ ! -f "$state_path" ]
    then mkdir $auxin_state || true
    curl "https://mcltajcadcrkywecsigc.supabase.co/rest/v1/signal_accounts?select=datastore&id=eq.%2B$echobot" \
   -H "apikey: $SUPABASE_API_KEY" \
   -H "Authorization: Bearer $SUPABASE_API_KEY" \
   -H "Accept: application/octet-stream" | tar -C $auxin_state -x
fi
# normal codepath
/app/auxin_cli --config $auxin_state --user +$echobot echoserver | jq -c
