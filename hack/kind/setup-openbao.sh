#!/usr/bin/env bash

# Copyright 2026 The Agent Substrate Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Deploys the development OpenBao in hack/kind/openbao.yaml and configures it to
# accept substrate actor JWTs:
#
#   - JWT auth at auth/jwt, trusting the issuer ate-idp-server publishes
#     (OIDC discovery at ACTOR_JWT_ISSUER, https://idp.ate-system.svc by
#     default), verified with the servicedns trust bundle.
#   - Role substrate-actor: binds audience "openbao", names each OpenBao entity
#     by the JWT subject (actor/<atespace>/<name>), and copies the actor's
#     atespace, name and UID into the entity alias metadata.
#   - Policy substrate-actor: an actor may read the KV version 2 secrets under
#     secret/atespaces/<its atespace>/.
#
# openbao.yaml also declares a file audit device on stdout, so
# `kubectl -n openbao logs deploy/openbao` shows which actor read what.
#
# Dev mode keeps everything in memory, so rerun this after OpenBao restarts.
# The script is idempotent.
#
# Usage: hack/kind/setup-openbao.sh
#   KUBECTL_CONTEXT  kubectl context (default: the current context)
#   ACTOR_JWT_ISSUER the issuer substrate was installed with
#                    (default: https://idp.ate-system.svc)

set -o errexit -o nounset -o pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CTX_ARGS=()
if [[ -n "${KUBECTL_CONTEXT:-}" ]]; then
  CTX_ARGS=(--context "${KUBECTL_CONTEXT}")
fi
ISSUER="${ACTOR_JWT_ISSUER:-https://idp.ate-system.svc}"

k() { kubectl "${CTX_ARGS[@]}" "$@"; }
# bao runs the OpenBao CLI in the pod against the loopback dev listener.
bao() {
  k -n openbao exec -i deploy/openbao -- env BAO_ADDR=http://127.0.0.1:8201 BAO_TOKEN=root bao "$@"
}

echo "== deploying OpenBao"
k apply -f "${ROOT}/hack/kind/openbao.yaml"
k -n openbao rollout status deploy/openbao --timeout=180s

echo "== JWT auth trusting ${ISSUER}"
AUTH_MOUNTS="$(bao auth list -format=json)"
if ! grep -q '"jwt/"' <<<"${AUTH_MOUNTS}"; then
  bao auth enable jwt
fi
# The pod projects the servicedns trust bundle that ate-idp-server's serving
# certificate chains to.
DISCOVERY_CA="$(k -n openbao exec deploy/openbao -- cat /run/servicedns.podcert.ate.dev/trust-bundle.pem)"
bao write auth/jwt/config \
  oidc_discovery_url="${ISSUER}" \
  bound_issuer="${ISSUER}" \
  oidc_discovery_ca_pem="${DISCOVERY_CA}"

echo "== role substrate-actor"
# The claim mappings are JSON pointers into the nested actor.ate.dev claim.
bao write auth/jwt/role/substrate-actor \
  role_type=jwt \
  user_claim=sub \
  bound_audiences=openbao \
  claim_mappings=/actor.ate.dev/atespace=atespace \
  claim_mappings=/actor.ate.dev/actorName=actor \
  claim_mappings=/actor.ate.dev/actorUID=actor_uid \
  token_policies=substrate-actor \
  token_ttl=5m \
  token_max_ttl=5m

echo "== policy substrate-actor"
ACCESSOR="$(bao read -field=accessor sys/auth/jwt)"
bao policy write substrate-actor - <<EOF
# An actor may read the KV v2 secrets of its own atespace, and nothing else.
path "secret/data/atespaces/{{identity.entity.aliases.${ACCESSOR}.metadata.atespace}}/*" {
  capabilities = ["read"]
}
EOF

echo "OpenBao is ready. Store a secret for atespace <A> with:"
echo "  kubectl -n openbao exec deploy/openbao -- env BAO_ADDR=http://127.0.0.1:8201 BAO_TOKEN=root \\"
echo "    bao kv put secret/atespaces/<A>/example-api token=<value>"
echo "and name it in an egress policy as:"
echo "  ate-secret://openbao/kv/secret/atespaces/<A>/example-api/token"
