# credprovider-openbao

An [Agent Substrate](https://github.com/agent-substrate/substrate) egress credential provider backed by [OpenBao](https://openbao.org). The egress gateway calls it to resolve `ate-secret://openbao/...` URIs in an Actor's `EgressPolicy` and injects the result into the Actor's outbound request, so the secret never enters the sandbox.

The provider logs in to OpenBao in one of two ways, set by `--openbao-auth`:

| | `kubernetes` (default) | `actor-jwt` |
| --- | --- | --- |
| OpenBao login | Once, as the provider's ServiceAccount, through the Kubernetes auth method | As each Actor, with a substrate Actor JWT the provider mints, through the JWT auth method |
| Who decides what an Actor may read | The provider: secrets under `atespaces/<its atespace>/` | OpenBao's policy, templated on the Actor's atespace |
| What OpenBao's audit log names | The provider, plus the Actor in an `X-Substrate-Actor` request header | The Actor's own entity, `actor/<atespace>/<name>` |
| What substrate must grant | A place in the gateway's provider list | That, and the `egress_gateway` role for the provider's identity, to mint |

Both modes run from one image. `config/` deploys `kubernetes` mode as provider `openbao`; `config/actor-jwt/` deploys `actor-jwt` mode as provider `openbao-actor` in its own namespace, so the two can run side by side against one OpenBao.

## How a fetch works

1. The egress gateway selects an Actor's `http` or `https` rule that injects a header from a credential URI, and calls `FetchSecret(uri, actor_spiffe_id)` over mTLS. The provider admits only the gateway's identity (`--injector-identity`).
2. In `kubernetes` mode, the provider refuses a secret outside `<mount>/atespaces/<the actor's atespace>/` without contacting OpenBao.
3. If it holds no reusable OpenBao token, the provider logs in:
   - `kubernetes`: it presents its projected ServiceAccount token, bound to audience `openbao`, to `auth/kubernetes`. OpenBao checks it with a TokenReview. One token serves every Actor.
   - `actor-jwt`: it calls ateapi `Control.MintActorJwt` for the Actor with audience `openbao`, then presents the JWT to `auth/jwt`. OpenBao verifies it against `ate-idp-server`'s OIDC discovery document and maps the Actor's atespace, name and UID into the entity alias metadata. Each Actor gets its own token.

   Concurrent requests that need the same token share one login.
4. The provider reads `<mount>/data/<path>` with that token, sends the Actor as `X-Substrate-Actor: actor/<atespace>/<name>`, and returns the named field. It reuses a token until a third of its TTL is left, and logs in again once if a cached token is refused.

## Trust model

- **Both modes trust the gateway.** The provider believes the gateway's claim about which Actor is asking, as every substrate credential provider does. OpenBao never sees proof from the Actor itself.
- **`kubernetes` mode:** the provider's OpenBao policy reads every atespace's secrets, and the provider enforces the per-atespace boundary. A compromised provider can read everything under `secret/atespaces/`, and nothing in substrate. The `X-Substrate-Actor` header is the provider's assertion, logged as given.
- **`actor-jwt` mode:** OpenBao's policy enforces the boundary and its audit log attributes each read to an Actor entity. To mint, the provider needs substrate's `egress_gateway` role, which also lets it mint a JWT for **any** Actor toward any audience, mint Actor certificates, and read every egress policy. Protect it like the gateway.
- **Policy author vs. Actor:** an atespace editor writes the egress policy and chooses the URI. In both modes, a URI naming another atespace's secret is refused.
- **Refusals look alike:** a refused path, a missing secret, a missing field, an unknown Actor and a refused Actor login all return the same `PermissionDenied` message, so an Actor cannot probe what exists.
- **Recreated Actors (`actor-jwt`):** the gateway does not forward the Actor UID, and the provider caches tokens by atespace and name. A deleted and recreated Actor with the same name maps to the same OpenBao entity, and may reuse its predecessor's cached token for up to two thirds of the token TTL.
- **Secrecy is not end-to-end:** as with any injected credential, a destination can echo the header back to the Actor. Inject only toward trusted destinations.

## Credential URIs

```
ate-secret://<provider>/kv/<mount>/<path>.../<field>
```

The string value of `<field>` in the latest version of the KV version 2 secret at `<path>` in the engine mounted at `<mount>`. For example, `ate-secret://openbao/kv/secret/atespaces/team-a/example-api/token` reads field `token` of `secret/atespaces/team-a/example-api`.

Segments are 1–255 of `A–Z a–z 0–9 _ - .`; dot segments, percent-encoding, queries and fragments are rejected. The host must equal `--provider-name`. In `kubernetes` mode the path must start with `atespaces/<the actor's atespace>/`.

## Install

### 1. OpenBao

`hack/kind/setup-openbao.sh` applies the following to a development OpenBao, for both modes.

For `kubernetes` mode, Kubernetes auth with a role bound to the provider's ServiceAccount, a policy reading every atespace's secrets, and the audit header:

```sh
bao auth enable kubernetes
bao write auth/kubernetes/config kubernetes_host=https://kubernetes.default.svc
bao write auth/kubernetes/role/substrate-credential-provider \
  bound_service_account_names=openbao-credential-provider \
  bound_service_account_namespaces=credprovider-openbao \
  audience=openbao token_policies=substrate-credential-provider token_ttl=5m token_max_ttl=5m
bao policy write substrate-credential-provider - <<'EOF'
path "secret/data/atespaces/*" { capabilities = ["read"] }
EOF
bao write sys/config/auditing/request-headers/x-substrate-actor hmac=false
```

OpenBao's own ServiceAccount needs `system:auth-delegator` to make TokenReviews. An OpenBao outside the cluster needs `kubernetes_host`, `kubernetes_ca_cert` and a `token_reviewer_jwt` instead.

For `actor-jwt` mode, JWT auth trusting substrate's Actor JWT issuer, and a policy templated on the Actor's atespace:

```sh
bao auth enable jwt
bao write auth/jwt/config \
  oidc_discovery_url=https://idp.ate-system.svc \
  bound_issuer=https://idp.ate-system.svc \
  oidc_discovery_ca_pem=@servicedns-trust-bundle.pem
bao write auth/jwt/role/substrate-actor \
  role_type=jwt user_claim=sub bound_audiences=openbao \
  claim_mappings=/actor.ate.dev/atespace=atespace \
  claim_mappings=/actor.ate.dev/actorName=actor \
  claim_mappings=/actor.ate.dev/actorUID=actor_uid \
  token_policies=substrate-actor token_ttl=5m token_max_ttl=5m
```

```hcl
# substrate-actor: an Actor reads only its own atespace's secrets.
path "secret/data/atespaces/{{identity.entity.aliases.<jwt accessor>.metadata.atespace}}/*" {
  capabilities = ["read"]
}
```

- The issuer is substrate's `ACTOR_JWT_ISSUER` (`https://idp.<namespace>.svc` by default). `ate-idp-server`'s certificate comes from the servicedns signer, so `oidc_discovery_ca_pem` is that signer's trust bundle (the `servicedns.podcert.ate.dev/identity` ClusterTrustBundle labeled `podcert.ate.dev/canarying: live`). Update it if that CA rotates.
- An OpenBao that cannot reach `ate-idp-server` can use `jwt_validation_pubkeys` instead, from the `jwks` key of the `actor-id-jwt-pool` Secret. Key rotation is then manual.
- Find the accessor with `bao read -field=accessor sys/auth/jwt`.

### 2. Substrate

Install substrate with the provider in the gateway's provider list:

```sh
export ATE_CREDENTIAL_PROVIDER='[{"name":"k8s.io"},{"name":"openbao","address":"openbao-credential-provider.credprovider-openbao.svc:50051"}]'
go run ./cmd/ate-setup deploy ate-system ...
```

For `actor-jwt` mode, list `openbao-actor` at `openbao-credential-provider.credprovider-openbao-actor.svc:50051` instead or as well, and grant its identity the `egress_gateway` role:

```sh
export ATE_EGRESS_GATEWAY_EXTRA_SPIFFE_IDS=spiffe://cluster.local/ns/credprovider-openbao-actor/sa/openbao-credential-provider
```

Changing the extra SPIFFE IDs restarts ate-api-server. The gateway verifies the provider's servicedns certificate for the address's host name, so the address must be the provider Service's `<name>.<namespace>.svc`.

### 3. The provider

```sh
KO_DOCKER_REPO=<registry> make deploy                                         # kubernetes mode
kubectl kustomize config/actor-jwt | KO_DOCKER_REPO=<registry> ko apply -f -  # actor-jwt mode
```

`config/` deploys into namespace `credprovider-openbao`. `config/actor-jwt/` deploys into `credprovider-openbao-actor`, labeled `ate.dev/api-access: "true"` so ate-system's NetworkPolicy admits its calls to ateapi. Edit `--openbao-address` and `--openbao-ca-file` for your OpenBao.

| Flag | Default | |
| --- | --- | --- |
| `--injector-identity` | (required) | SPIFFE ID the caller must present: the egress gateway |
| `--server-cred-bundle`, `--client-ca-file` | (required) | serving credential bundle; trust bundle for the gateway's certificate |
| `--openbao-address` | (required) | e.g. `https://openbao.openbao.svc:8200` |
| `--openbao-ca-file` | (required for https) | OpenBao's trust bundle |
| `--openbao-allow-insecure-http` | `false` | allow `http://`; tokens and secrets then travel in cleartext |
| `--openbao-auth` | `kubernetes` | `kubernetes` or `actor-jwt` |
| `--openbao-auth-mount`, `--openbao-role` | by mode: `kubernetes`, `substrate-credential-provider`; or `jwt`, `substrate-actor` | |
| `--service-account-token-file` | `/var/run/secrets/openbao/token` | `kubernetes`: ServiceAccount token projected with audience `openbao`; reread at each login |
| `--ateapi-address` | `dns:///api.ate-system.svc:443` | `actor-jwt`: ateapi, for minting Actor JWTs |
| `--ateapi-ca-file`, `--ateapi-client-cert` | (required for `actor-jwt`) | ateapi's trust bundle; this pod's identity bundle |
| `--actor-jwt-audience` | `openbao` | `actor-jwt`: must match the role's `bound_audiences` |
| `--actor-jwt-lifetime` | `300s` | `actor-jwt`: 300s–3600s; each JWT is used once, to log in |
| `--provider-name` | `openbao` | URI host; must match the gateway's provider list |
| `--fetch-timeout` | `3s` | keep under the gateway's four-second provider budget |

### Status codes

The gateway turns `PermissionDenied` and `NotFound` into a 403, and `Unavailable` into a retryable 503.

| Condition | Code |
| --- | --- |
| A secret outside the Actor's atespace (`kubernetes`), OpenBao refuses or lacks the secret, the field is missing, the Actor no longer exists, OpenBao refuses an Actor's login | `PermissionDenied`, one message |
| OpenBao or ateapi unreachable, sealed, rate limiting, 5xx, or the fetch timeout passes | `Unavailable` |
| OpenBao refuses the provider's own login, the token file is unreadable, the provider lacks the `egress_gateway` role, a wrong auth mount, other unexpected answers | `Internal`, logged |
| A malformed URI | `InvalidArgument` |

## Development

```sh
make verify test          # gofmt, vet, go mod tidy, unit tests
```

`cmd/openbao-credential-provider/main_test.go` runs the provider in-process in both modes against a TLS fake ateapi and a TLS fake OpenBao, with the gateway's mTLS and SAN pinning.

### End-to-end on kind

On a kind cluster with substrate installed as in [Install step 2](#2-substrate), whose router also admits the test driver, `spiffe://cluster.local/ns/credprovider-openbao-e2e/sa/e2e-driver` (`--ingress-allowed-spiffe-ids`, or the chart's `atenetRouter.ingressAllowedSPIFFEIDs`):

```sh
KO_DOCKER_REPO=localhost:5001 hack/e2e-kind.sh               # kubernetes mode
KO_DOCKER_REPO=localhost:5001 hack/e2e-kind.sh --actor-jwt   # actor-jwt mode
hack/e2e-kind.sh --cleanup
```

Set `KUBECTL_ATE` to a `kubectl-ate` built for the cluster's substrate version if the one on `PATH` is not.

It deploys the development OpenBao (`hack/kind/openbao.yaml`: dev mode, in-memory, TLS from a servicedns pod certificate, audit log on stdout), the provider, a header-echo target, probe Actors in atespaces `team-a` and `team-b`, and a driver pod that calls them through the router with its own pod identity certificate. It then checks that:

1. `team-a`'s Actor receives `team-a`'s secret in place of its placeholder header;
2. `team-b`'s Actor naming `team-a`'s secret gets a 403;
3. a missing secret gets a 403;
4. OpenBao's audit log records the read for `actor/team-a/alpha`, by the provider's ServiceAccount or by the Actor's own entity;
5. with OpenBao down, a request needing a credential gets a 503.
