# CA Connector Design Notes

## Goal

RemoteSSL must stay CA-agnostic. GlobalSign is the first strategic connector, but the core domain model
and the request lifecycle may not depend on any GlobalSign concept. Everything provider-specific lives
inside the connector implementation and its own configuration JSON.

## The generic contract

`RemoteSSL.Domain.Abstractions.ICertificateAuthorityConnector`:

| Method | Purpose |
|---|---|
| `ValidateConnectionAsync` | Credential/connectivity check |
| `ListProfilesAsync` | Normalized issuing profiles (key algos, max validity, wildcard support) |
| `SubmitRequestAsync` | PKCS#10 CSR in, opaque `CaRequestRef` out |
| `GetRequestStatusAsync` | Pending / ValidationRequired / Issued / Rejected / Failed |
| `DownloadCertificateAsync` | Leaf + chain PEM |
| `RenewAsync` / `RevokeAsync` | Lifecycle operations |
| `RequestDomainValidationAsync` | Optional DV challenge (null when unsupported) |

The lifecycle engine only ever talks to this interface. Adding DigiCert, Sectigo, ACME or an internal
REST CA means writing one new implementation — no core changes.

## Mapping: GlobalSign HVCA (Atlas)

How the generic contract maps onto the HVCA API (api.docs.globalsign.com — HVCA section):

| Generic | HVCA |
|---|---|
| `ValidateConnectionAsync` | mTLS client certificate + `POST /login` with API key/secret → short-lived JWT |
| `ListProfilesAsync` | `GET /validationpolicy` — the account's validation policy constrains subject/SAN/key/validity |
| `SubmitRequestAsync` | `POST /certificates` with PKCS#10 → `202` + certificate identifier/URL |
| `GetRequestStatusAsync` | `GET /certificates/{id}` (issuance is near-synchronous in HVCA; poll until available) |
| `DownloadCertificateAsync` | `GET /certificates/{id}` (PEM); chain via `GET /trustchain` |
| `RevokeAsync` | `DELETE /certificates/{id}` |
| `RequestDomainValidationAsync` | Domain claims API (`/claims/domains/...`, DNS/HTTP validation) |

Notes:

- HVCA tokens are short-lived; the connector must transparently re-login on 401.
- HVCA enforces the validation policy server-side; the connector should surface the policy through
  `ListProfilesAsync` so the request wizard can pre-validate instead of failing at submit time.
- Quotas/counters (`/counters`, `/quotas`) are connector-internal health details, surfaced only as
  connector diagnostics.
- The docs site was unreachable from the development sandbox (network egress policy); the mapping above
  is based on the known HVCA v2 API surface and must be validated against the live docs/sandbox once a
  GlobalSign account is available.

## Manual CA fallback

For CAs without an API, a `manual` connector implementation keeps the same lifecycle: the wizard
produces a CSR, the request parks in `WaitingForCertificate`, and the user uploads the signed
certificate + chain to resume the flow.
