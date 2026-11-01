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

# End-to-end test of the OpenBao credential provider on a kind cluster running
# substrate. It proves, on the wire, that:
#
#   1. an actor's placeholder header is replaced with the secret OpenBao holds
#      for the actor's own atespace;
#   2. an actor in another atespace naming that secret is refused (403);
#   3. a secret that does not exist is refused the same way (403);
#   4. OpenBao's audit log names the actor that read the secret;
#   5. with OpenBao down, a request needing a credential fails closed with a
#      retryable 503.
#
# Prerequisites: substrate installed on kind from a checkout at the version in
# go.mod, with this provider and identity wired in (see README.md):
#
#   ATE_CREDENTIAL_PROVIDER='[{"name":"k8s.io"},{"name":"openbao","address":"openbao-credential-provider.credprovider-openbao.svc:50051"}]'
#   ATE_EGRESS_GATEWAY_EXTRA_SPIFFE_IDS=spiffe://cluster.local/ns/credprovider-openbao/sa/openbao-credential-provider
#
# and KO_DOCKER_REPO pointing at a registry the cluster pulls from
# (localhost:5001 for substrate's kind setup). kubectl, kubectl-ate, ko-able Go,
# curl and jq must be on PATH.
#
# Usage:
#   hack/e2e-kind.sh             run the test (leaves its resources in place)
#   hack/e2e-kind.sh --cleanup   delete everything the test created, including
#                                the development OpenBao and the provider
#
#   KUBECTL_CONTEXT  kubectl context (default: the current context)
#   KUBECTL_ATE      kubectl-ate binary matching the cluster (default: kubectl-ate)
#   WORKER_IMAGE    worker image for the test pool (default: the image of an
#                    existing WorkerPool in the cluster)

set -o errexit -o nounset -o pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

CTX="${KUBECTL_CONTEXT:-$(kubectl config current-context)}"
K=(kubectl --context "${CTX}")
KATE=("${KUBECTL_ATE:-kubectl-ate}" --context "${CTX}")
NS=credprovider-openbao-e2e
TARGET="http://whoami.${NS}.svc.cluster.local/"
TARGET_HOST="whoami.${NS}.svc.cluster.local"
PROVIDER_ID=spiffe://cluster.local/ns/credprovider-openbao/sa/openbao-credential-provider
DRIVER_ID=spiffe://cluster.local/ns/${NS}/sa/e2e-driver
ROUTER_URL=https://atenet-router.ate-system.svc/
PLACEHOLDER="Bearer actor-placeholder"

log()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
pass() { printf '\033[1;32mPASS\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31mFAIL\033[0m %s\n' "$*"; FAILED=1; }
FAILED=0

bao() {
  "${K[@]}" -n openbao exec -i deploy/openbao -- env BAO_ADDR=http://127.0.0.1:8201 BAO_TOKEN=root bao "$@"
}

# actors are atespace/name pairs this test creates.
ACTORS=(team-a/alpha team-b/bravo team-a/charlie team-a/delta)

cleanup() {
  log "cleanup"
  for ref in "${ACTORS[@]}"; do
    "${KATE[@]}" delete actor "${ref#*/}" -a "${ref%/*}" >/dev/null 2>&1 || true
  done
  for as in team-a team-b; do
    "${KATE[@]}" delete actor-template probe -a "${as}" >/dev/null 2>&1 || true
    "${KATE[@]}" delete atespace "${as}" >/dev/null 2>&1 || true
  done
  "${K[@]}" delete namespace "${NS}" credprovider-openbao openbao --ignore-not-found
}

if [[ "${1:-}" == "--cleanup" ]]; then
  cleanup
  exit 0
fi

##############################################################################
log "preflight: substrate is wired for this provider"
##############################################################################
# Command output is captured before grepping: under pipefail, `kubectl ... |
# grep -q` can fail on a match when grep exits early and kubectl takes SIGPIPE.
API_SERVER="$("${K[@]}" -n ate-system get deploy ate-api-server -o json)"
SYSTEM_CONFIG="$("${K[@]}" -n ate-system get deploy,configmap -o yaml)"
if ! grep -q "${PROVIDER_ID}" <<<"${API_SERVER}"; then
  echo "ate-api-server does not grant ${PROVIDER_ID} the egress_gateway role." >&2
  echo "Reinstall substrate with ATE_EGRESS_GATEWAY_EXTRA_SPIFFE_IDS=${PROVIDER_ID}" >&2
  exit 1
fi
if ! grep -q 'openbao-credential-provider.credprovider-openbao.svc' <<<"${SYSTEM_CONFIG}"; then
  echo "The egress gateway is not configured with the openbao provider." >&2
  echo "Reinstall substrate with ATE_CREDENTIAL_PROVIDER including" >&2
  echo '  {"name":"openbao","address":"openbao-credential-provider.credprovider-openbao.svc:50051"}' >&2
  exit 1
fi
if ! grep -q "${DRIVER_ID}" <<<"${SYSTEM_CONFIG}"; then
  echo "The router does not admit the test driver; add ${DRIVER_ID}" >&2
  echo "to substrate's ingress allowed SPIFFE IDs." >&2
  exit 1
fi
: "${KO_DOCKER_REPO:?set KO_DOCKER_REPO to a registry the cluster pulls from, e.g. localhost:5001}"
WORKER_IMAGE="${WORKER_IMAGE:-$("${K[@]}" get workerpools -A -o jsonpath='{.items[0].spec.workerImage}' 2>/dev/null || true)}"
if [[ -z "${WORKER_IMAGE}" ]]; then
  echo "No WorkerPool to copy a worker image from; set WORKER_IMAGE." >&2
  exit 1
fi
pass "ate-api-server grants the provider egress_gateway; the gateway names the provider"
echo "worker image: ${WORKER_IMAGE}"

##############################################################################
log "OpenBao and the provider"
##############################################################################
KUBECTL_CONTEXT="${CTX}" hack/kind/setup-openbao.sh
"${K[@]}" kustomize config | go run github.com/google/ko@v0.19.1 resolve --base-import-paths -f - | "${K[@]}" apply -f - >/dev/null
"${K[@]}" -n credprovider-openbao rollout status deploy/openbao-credential-provider --timeout=180s
bao kv put secret/atespaces/team-a/example-api token=team-a-secret >/dev/null
bao kv put secret/atespaces/team-b/example-api token=team-b-secret >/dev/null
pass "OpenBao configured and seeded; provider rolled out"

##############################################################################
log "echo target, worker pool and probe actors"
##############################################################################
sed "s#WORKER_IMAGE#${WORKER_IMAGE}#" test/e2e/manifests.yaml | "${K[@]}" apply -f - >/dev/null
"${K[@]}" -n "${NS}" rollout status deploy/whoami --timeout=120s
"${K[@]}" -n "${NS}" rollout status deploy/e2e-driver --timeout=120s
PROBE_IMAGE="$(go run github.com/google/ko@v0.19.1 build --base-import-paths ./test/e2e/probe 2>/dev/null | tail -1)"
echo "probe image: ${PROBE_IMAGE}"
for as in team-a team-b; do
  "${KATE[@]}" create atespace "${as}" >/dev/null 2>&1 || true
  if ! "${KATE[@]}" get actor-template probe -a "${as}" >/dev/null 2>&1; then
    sed -e "s#ATESPACE#${as}#" -e "s#PROBE_IMAGE#${PROBE_IMAGE}#" test/e2e/actor-template.yaml \
      | "${KATE[@]}" create actor-template -f - >/dev/null
  fi
done

# policy <atespace/actor> <credential URI> gives the actor an http rule for the
# echo target that injects the URI's secret as its Authorization header.
policy() {
  local ref=$1 uri=$2
  "${KATE[@]}" create actor "${ref#*/}" -a "${ref%/*}" --template probe >/dev/null 2>&1 || true
  "${KATE[@]}" delete egress-policy "${ref#*/}" -a "${ref%/*}" >/dev/null 2>&1 || true
  sed -e "s#TARGET_HOST#${TARGET_HOST}#" -e "s#CREDENTIAL_URI#${uri}#" test/e2e/egress-policy.yaml \
    | "${KATE[@]}" create egress-policy "${ref#*/}" -a "${ref%/*}" -f - >/dev/null
}
policy team-a/alpha   ate-secret://openbao/kv/secret/atespaces/team-a/example-api/token
policy team-b/bravo   ate-secret://openbao/kv/secret/atespaces/team-a/example-api/token
policy team-a/charlie ate-secret://openbao/kv/secret/atespaces/team-a/no-such-secret/token
policy team-a/delta   ate-secret://openbao/kv/secret/atespaces/team-a/example-api/token
pass "actors and egress policies created"

# probe <atespace/actor> asks the actor, through the router, to fetch the echo
# target with the placeholder header; prints the actor's JSON answer; and
# suspends the actor so the next one gets a worker. The router resumes a
# suspended actor on request.
probe() {
  local ref=$1 out=""
  for _ in $(seq 1 20); do
    out=$("${K[@]}" -n "${NS}" exec deploy/e2e-driver -- curl -sS --max-time 60 \
      --cert /run/router-client/credential-bundle.pem \
      --cacert /run/router-client/trust-bundle.pem \
      -H "ate-target-actor: ${ref}" -H 'Content-Type: application/json' \
      -d "{\"url\":\"${TARGET}\",\"headers\":{\"Authorization\":\"${PLACEHOLDER}\"}}" \
      "${ROUTER_URL}" 2>&1 || true)
    [[ "${out}" == \{* ]] && break
    echo "  (${ref} not answering yet: ${out:0:160})" >&2
    sleep 3
  done
  "${KATE[@]}" suspend actor "${ref#*/}" -a "${ref%/*}" >/dev/null 2>&1 || true
  echo "${out}"
}

##############################################################################
log "1. team-a/alpha receives team-a's secret"
##############################################################################
OUT=$(probe team-a/alpha)
BODY=$(jq -r '.body // ""' <<<"${OUT}")
if [[ "$(jq -r '.statusCode' <<<"${OUT}")" == 200 ]] && grep -q 'Authorization: Bearer team-a-secret' <<<"${BODY}"; then
  pass "the echo target received Authorization: Bearer team-a-secret"
else
  fail "alpha: ${OUT}"
fi
if grep -q 'actor-placeholder' <<<"${BODY}"; then
  fail "the placeholder reached the target"
fi

##############################################################################
log "2. team-b/bravo naming team-a's secret is refused"
##############################################################################
OUT=$(probe team-b/bravo)
if [[ "$(jq -r '.statusCode' <<<"${OUT}")" == 403 ]] && ! grep -q 'team-a-secret' <<<"${OUT}"; then
  pass "403 for another atespace's secret"
else
  fail "bravo: ${OUT}"
fi

##############################################################################
log "3. a missing secret is refused the same way"
##############################################################################
OUT=$(probe team-a/charlie)
if [[ "$(jq -r '.statusCode' <<<"${OUT}")" == 403 ]]; then
  pass "403 for a secret that does not exist"
else
  fail "charlie: ${OUT}"
fi

##############################################################################
log "4. OpenBao's audit log names the actor"
##############################################################################
AUDIT="$("${K[@]}" -n openbao logs deploy/openbao --tail=-1)"
if grep -q 'jwt-actor/team-a/alpha' <<<"${AUDIT}"; then
  pass "audit log entries name actor/team-a/alpha"
else
  fail "no audit entry names actor/team-a/alpha"
fi

##############################################################################
log "5. OpenBao down: fail closed with 503"
##############################################################################
"${K[@]}" -n openbao scale deploy/openbao --replicas=0 >/dev/null
"${K[@]}" -n openbao wait --for=delete pod -l app=openbao --timeout=120s >/dev/null 2>&1 || true
# delta has never logged in, so nothing cached can answer for it.
OUT=$(probe team-a/delta)
if [[ "$(jq -r '.statusCode' <<<"${OUT}")" == 503 ]]; then
  pass "503 while OpenBao is unreachable"
else
  fail "delta: ${OUT}"
fi
log "restoring OpenBao (dev mode restarts empty)"
"${K[@]}" -n openbao scale deploy/openbao --replicas=1 >/dev/null
KUBECTL_CONTEXT="${CTX}" hack/kind/setup-openbao.sh >/dev/null
bao kv put secret/atespaces/team-a/example-api token=team-a-secret >/dev/null
bao kv put secret/atespaces/team-b/example-api token=team-b-secret >/dev/null

if [[ "${FAILED}" -ne 0 ]]; then
  log "FAILED"
  exit 1
fi
log "PASS (hack/e2e-kind.sh --cleanup removes the test resources)"
