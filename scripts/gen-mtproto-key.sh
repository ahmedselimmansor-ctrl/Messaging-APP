#!/usr/bin/env bash
#
# Generates an MTProto server key for local development.
#
# Production keys come from Secret Manager via bootstrap-secrets.sh; this is
# for running the stack on a laptop, where there is no Secret Manager.

set -euo pipefail

OUT="${1:-./local/mtproto-server-key.pem}"
mkdir -p "$(dirname "${OUT}")"

if [ -f "${OUT}" ]; then
  echo "${OUT} already exists; refusing to overwrite" >&2
  exit 1
fi

openssl genrsa -out "${OUT}" 2048 2>/dev/null
chmod 600 "${OUT}"

echo "private key: ${OUT}"
echo
echo "public key (clients pin this):"
openssl rsa -in "${OUT}" -pubout 2>/dev/null
