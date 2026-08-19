#!/usr/bin/env bash
#
# Seeds the Secret Manager secrets Terraform created empty.
#
# Terraform deliberately never holds a secret value: state is a file that gets
# copied, diffed and occasionally pasted into a chat window. This script
# generates the key material locally, pushes it, and never writes it to disk
# outside a temporary directory it removes on exit.
#
# Usage: ./scripts/bootstrap-secrets.sh PROJECT_ID ENV

set -euo pipefail

PROJECT_ID="${1:?usage: $0 PROJECT_ID ENV}"
ENV="${2:?environment is required (dev|staging|prod)}"
PREFIX="messaging-${ENV}"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
chmod 700 "${WORK}"

have_version() {
  gcloud secrets versions list "$1" --project="${PROJECT_ID}" \
    --filter="state=ENABLED" --format='value(name)' 2>/dev/null | grep -q .
}

add_version() {
  local secret="$1" file="$2"
  gcloud secrets versions add "${secret}" \
    --project="${PROJECT_ID}" --data-file="${file}" >/dev/null
  echo "  seeded ${secret}"
}

echo "seeding secrets for ${PREFIX}"

# ---------------------------------------------------------------------------
# JWT signing key — ES256 (P-256), PKCS#8 PEM
# ---------------------------------------------------------------------------
#
# ES256 rather than RS256: every request to every service verifies one of
# these, and a P-256 signature is 64 bytes against RSA-2048's 256.
if have_version "${PREFIX}-jwt-signing-key"; then
  echo "  ${PREFIX}-jwt-signing-key already has a version; skipping"
else
  openssl ecparam -name prime256v1 -genkey -noout -out "${WORK}/jwt-ec.pem" 2>/dev/null
  openssl pkcs8 -topk8 -nocrypt -in "${WORK}/jwt-ec.pem" -out "${WORK}/jwt.pem"
  add_version "${PREFIX}-jwt-signing-key" "${WORK}/jwt.pem"

  # The key id is what makes rotation possible without invalidating live
  # tokens: verifiers accept every key in the JWKS and select by kid.
  KID="$(date -u +%Y%m%d)-$(openssl rand -hex 4)"
  printf '%s' "${KID}" > "${WORK}/kid"
  echo "  key id: ${KID}"
  echo "  (set JWT_SIGNING_KEY_ID=${KID} in the overlay)"
fi

# ---------------------------------------------------------------------------
# MTProto server key — RSA-2048
# ---------------------------------------------------------------------------
#
# RSA because the handshake wraps new_nonce with it, exactly as MTProto
# specifies. Clients pin the public half, so rotating this is a coordinated
# client release, not a routine operation.
if have_version "${PREFIX}-mtproto-server-key"; then
  echo "  ${PREFIX}-mtproto-server-key already has a version; skipping"
else
  openssl genrsa -out "${WORK}/mtproto.pem" 2048 2>/dev/null
  add_version "${PREFIX}-mtproto-server-key" "${WORK}/mtproto.pem"

  openssl rsa -in "${WORK}/mtproto.pem" -pubout -out "${WORK}/mtproto.pub" 2>/dev/null
  echo
  echo "  --- MTProto server public key ---"
  echo "  Ship this with the clients. They must pin it: without pinning, an"
  echo "  attacker who can intercept the connection substitutes their own key,"
  echo "  learns new_nonce and reads the entire Diffie-Hellman exchange."
  echo
  cat "${WORK}/mtproto.pub"
  echo
fi

# ---------------------------------------------------------------------------
# SMS webhook credential
# ---------------------------------------------------------------------------
if have_version "${PREFIX}-sms-webhook-auth"; then
  echo "  ${PREFIX}-sms-webhook-auth already has a version; skipping"
else
  if [ "${ENV}" = "prod" ]; then
    echo "  ${PREFIX}-sms-webhook-auth needs the real aggregator credential:"
    echo "    printf 'Bearer XXX' | gcloud secrets versions add ${PREFIX}-sms-webhook-auth \\"
    echo "      --project=${PROJECT_ID} --data-file=-"
  else
    printf 'Bearer placeholder-%s' "$(openssl rand -hex 16)" > "${WORK}/sms"
    add_version "${PREFIX}-sms-webhook-auth" "${WORK}/sms"
  fi
fi

# ---------------------------------------------------------------------------
# Cassandra credentials, one per service
# ---------------------------------------------------------------------------
#
# Passwords only, no JSON envelope. The Secret Manager CSI driver projects a
# secret's bytes as a file verbatim, so a JSON blob would arrive as a single
# opaque string that the services would then have to parse. Usernames are role
# names, not credentials, and live in the manifests.
#
# The roles these belong to are created by the schema Job from
# db/cassandra/roles.cql, which reads exactly these secrets.
for role in chat persister media readonly superuser; do
  name="${PREFIX}-cassandra-${role}-credentials"
  if have_version "${name}"; then
    echo "  ${name} already has a version; skipping"
    continue
  fi
  # tr strips the characters that make a password awkward to pass through
  # cqlsh, sed and shell quoting. 32 bytes of base64 minus those is still well
  # over 128 bits of entropy.
  openssl rand -base64 48 | tr -d '\n=+/' | cut -c1-40 > "${WORK}/cassandra-${role}"
  add_version "${name}" "${WORK}/cassandra-${role}"
done
echo "  apply db/cassandra/roles.cql to create the matching Cassandra roles"
echo "  (the cassandra-schema Job does this automatically on deploy)"

# ---------------------------------------------------------------------------
# Elasticsearch credentials
# ---------------------------------------------------------------------------
if have_version "${PREFIX}-elasticsearch-credentials"; then
  echo "  ${PREFIX}-elasticsearch-credentials already has a version; skipping"
else
  openssl rand -base64 48 | tr -d '\n=+/' | cut -c1-40 > "${WORK}/es"
  add_version "${PREFIX}-elasticsearch-credentials" "${WORK}/es"
  echo "  create two Elasticsearch users with this password:"
  echo "    indexer  — write to the messages index"
  echo "    search   — read only"
fi

# ---------------------------------------------------------------------------
# TURN shared secret
# ---------------------------------------------------------------------------
#
# One value used by two components: the call service mints REST-API
# credentials by HMAC-ing an expiry with it, coturn verifies them with the
# same secret. Rotating it invalidates outstanding credentials, which is
# harmless — they last hours and clients fetch new ones per call.
if have_version "${PREFIX}-turn-credentials"; then
  echo "  ${PREFIX}-turn-credentials already has a version; skipping"
else
  openssl rand -base64 48 | tr -d '\n=+/' | cut -c1-40 > "${WORK}/turn"
  add_version "${PREFIX}-turn-credentials" "${WORK}/turn"
fi

echo
echo "done. Verify with:"
echo "  gcloud secrets list --project=${PROJECT_ID} --filter='name~${PREFIX}'"
