# credprovider-openbao

An [Agent Substrate](https://github.com/agent-substrate/substrate) egress credential provider backed by [OpenBao](https://openbao.org). The egress gateway calls it to resolve `ate-secret://openbao/...` URIs in an Actor's `EgressPolicy` and injects the result into the Actor's outbound request, so the secret never enters the sandbox.

Unlike substrate's bundled Kubernetes Secrets provider, this provider makes no authorization decision of its own. For each Actor it mints a substrate Actor JWT, logs in to OpenBao's JWT auth method **as that Actor**, and reads the secret with the Actor's own OpenBao token. OpenBao's policies decide what each Actor may read, and OpenBao's audit log names the Actor on every read. The provider holds no OpenBao credential.

## How a fetch works

1. The egress gateway selects an Actor's `http` or `https` rule that injects a header from a credential URI, and calls `FetchSecret(uri, actor_spiffe_id)` over mTLS. The provider admits only the gateway's identity (`--injector-identity`).
2. If it holds no reusable OpenBao token for that Actor, the provider calls ateapi `Control.MintActorJwt` for the Actor with audience `openbao`, then logs in to `auth/jwt` with that JWT. Concurrent requests for one Actor share one login.
3. OpenBao verifies the JWT against the issuer's OIDC discovery document (`ate-idp-server`), maps the Actor's atespace, name and UID into the entity alias metadata, and issues a token carrying the `substrate-actor` policy.
4. The provider reads `kv/data/<path>` with the Actor's token and returns the named field. It reuses the token until a third of its TTL is left, and logs in again once if a cached token is refused.

The Actor JWT carries `sub: actor/<atespace>/<name>` and an `actor.ate.dev` claim with `atespace`, `actorName` and `actorUID`. With `user_claim=sub`, each Actor is one OpenBao entity named `actor/<atespace>/<name>`.

## Trust model

- **What moves into OpenBao:** the authorization decision and the audit trail. Grants change with an OpenBao policy, with no provider restart, and every read is attributed to an Actor entity.
- **What does not move:** trust in the gateway. The provider believes the gateway's claim about which Actor is asking, as every substrate credential provider does. To mint, the provider's identity needs substrate's `egress_gateway` role, which also lets it mint a JWT for **any** Actor and read every egress policy. Protect the provider like the gateway.
- **Policy author vs. Actor:** an atespace editor writes the egress policy and chooses the URI, but OpenBao still decides whether the Actor may read it. A URI naming another atespace's secret is refused.
- **Refusals look alike:** a refused path, a missing secret, a missing field, an unknown Actor and a refused login all return the same `PermissionDenied` message, so an Actor cannot probe what exists.
- **Recreated Actors:** the gateway does not forward the Actor UID, and the provider caches tokens by atespace and name. A deleted and recreated Actor with the same name maps to the same OpenBao entity, and may reuse its predecessor's cached token for up to two thirds of the token TTL. The Actor JWT's UID reaches OpenBao as alias metadata at login, but policies here do not depend on it.
- **Secrecy is not end-to-end:** as with any injected credential, a destination can echo the header back to the Actor. Inject only toward trusted destinations.

## Credential URIs

```
ate-secret://openbao/kv/<mount>/<path>.../<field>
```

The string value of `<field>` in the latest version of the KV version 2 secret at `<path>` in the engine mounted at `<mount>`. For example, `ate-secret://openbao/kv/secret/atespaces/team-a/example-api/token` reads field `token` of `secret/atespaces/team-a/example-api`.

Segments are 1–255 of `A–Z a–z 0–9 _ - .`; dot segments, percent-encoding, queries and fragments are rejected. The host must equal `--provider-name`.

## Install

### 1. OpenBao

The provider needs a JWT auth role and a policy along these lines. `hack/kind/setup-openbao.sh` applies them to a development OpenBao.

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

Install substrate with this provider in the gateway's provider list and its identity granted the `egress_gateway` role:

```sh
export ATE_CREDENTIAL_PROVIDER='[{"name":"k8s.io"},{"name":"openbao","address":"openbao-credential-provider.credprovider-openbao.svc:50051"}]'
export ATE_EGRESS_GATEWAY_EXTRA_SPIFFE_IDS=spiffe://cluster.local/ns/credprovider-openbao/sa/openbao-credential-provider
go run ./cmd/ate-setup deploy ate-system ...
```

Changing the extra SPIFFE IDs restarts ate-api-server. The gateway verifies the provider's servicedns certificate for the address's host name, so the address must be the provider Service's `<name>.<namespace>.svc`.

### 3. The provider

```sh
KO_DOCKER_REPO=<registry> make deploy
```

`config/` deploys into namespace `credprovider-openbao`, labeled `ate.dev/api-access: "true"` so ate-system's NetworkPolicy admits its calls to ateapi. Edit `--openbao-address` and `--openbao-ca-file` in `config/deployment.yaml` for your OpenBao.

| Flag | Default | |
| --- | --- | --- |
| `--injector-identity` | (required) | SPIFFE ID the caller must present: the egress gateway |
| `--server-cred-bundle`, `--client-ca-file` | (required) | serving credential bundle; trust bundle for the gateway's certificate |
| `--ateapi-address` | `dns:///api.ate-system.svc:443` | ateapi, for minting Actor JWTs |
| `--ateapi-ca-file`, `--ateapi-client-cert` | (required) | ateapi's trust bundle; this pod's identity bundle |
| `--openbao-address` | (required) | e.g. `https://openbao.openbao.svc:8200` |
| `--openbao-ca-file` | (required for https) | OpenBao's trust bundle |
| `--openbao-allow-insecure-http` | `false` | allow `http://`; tokens and secrets then travel in cleartext |
| `--openbao-jwt-mount`, `--openbao-role` | `jwt`, `substrate-actor` | |
| `--actor-jwt-audience` | `openbao` | must match the role's `bound_audiences` |
| `--actor-jwt-lifetime` | `300s` | 300s–3600s; each JWT is used once, to log in |
| `--provider-name` | `openbao` | URI host; must match `ATE_CREDENTIAL_PROVIDER` |
| `--fetch-timeout` | `3s` | keep under the gateway's four-second provider budget |

### Status codes

The gateway turns `PermissionDenied` and `NotFound` into a 403, and `Unavailable` into a retryable 503.

| Condition | Code |
| --- | --- |
| OpenBao refuses or lacks the secret, the field is missing, the Actor no longer exists, OpenBao refuses the login | `PermissionDenied`, one message |
| OpenBao or ateapi unreachable, sealed, rate limiting, 5xx, or the fetch timeout passes | `Unavailable` |
| The provider lacks the `egress_gateway` role, a wrong JWT mount, other unexpected answers | `Internal`, logged |
| A malformed URI | `InvalidArgument` |

## Development

```sh
make verify test          # gofmt, vet, go mod tidy, unit tests
```

`cmd/openbao-credential-provider/main_test.go` runs the provider in-process against a TLS fake ateapi and a TLS fake OpenBao, with the gateway's mTLS and SAN pinning.

### End-to-end on kind

On a kind cluster with substrate installed as in [Install step 2](#2-substrate), whose router also admits the test driver, `spiffe://cluster.local/ns/credprovider-openbao-e2e/sa/e2e-driver` (`--ingress-allowed-spiffe-ids`, or the chart's `atenetRouter.ingressAllowedSPIFFEIDs`):

```sh
KO_DOCKER_REPO=localhost:5001 hack/e2e-kind.sh
hack/e2e-kind.sh --cleanup
```

Set `KUBECTL_ATE` to a `kubectl-ate` built for the cluster's substrate version if the one on `PATH` is not.

It deploys the development OpenBao (`hack/kind/openbao.yaml`: dev mode, in-memory, TLS from a servicedns pod certificate, audit log on stdout), the provider, a header-echo target, probe Actors in atespaces `team-a` and `team-b`, and a driver pod that calls them through the router with its own pod identity certificate. It then checks that:

1. `team-a`'s Actor receives `team-a`'s secret in place of its placeholder header;
2. `team-b`'s Actor naming `team-a`'s secret gets a 403;
3. a missing secret gets a 403;
4. OpenBao's audit log names `actor/team-a/alpha`;
5. with OpenBao down, a request needing a credential gets a 503.
