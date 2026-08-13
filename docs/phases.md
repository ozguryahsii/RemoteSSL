# RemoteSSL — Development Phases

Derived from the technical design document (v1.0, section 40) and the agreed kickoff decisions.

## Decisions (kickoff)

- **Stack:** .NET 8 (API + Runner), React + TypeScript (Vite), English UI with i18n from day one.
- **Infrastructure:** PostgreSQL + RabbitMQ + Redis via Docker Compose from the start.
- **CA strategy:** provider-agnostic `ICertificateAuthorityConnector`; GlobalSign (HVCA/Atlas) is the first
  connector candidate but nothing provider-specific may leak into the core model. See `docs/ca-connector.md`.
- **Platforms:** develop/test on macOS, deploy to Linux and Windows (all components cross-platform).

## Phases

| Phase | Scope | Definition of Done |
|---|---|---|
| **F0 — Skeleton** | Solution layout, Docker Compose infra, EF Core baseline, React shell, CI | Stack boots with one command on macOS |
| **F1 — Monitoring & Inventory** | Monitor CRUD, TLS probe engine (SNI), X.509 parser, Certificate/Version model, dedup/correlation, expiry thresholds (T-90…T-1), basic alerts | Credential-less endpoint is probed on schedule; renewal produces a new version; one cert on N endpoints = one inventory row |
| **F2 — Managed Targets & Runner** | Target/CredentialRef, secret provider abstraction, runner registration + heartbeat + mTLS, job engine, connection test, audit baseline | Endpoint linked to a target/store with a safe connection test |
| **F3 — Linux Deployment** | SSH adapter, generic file store, Nginx/Apache/HAProxy, transactional pipeline + rollback | PEM/KEY/chain deployed transactionally; thumbprint verified; rollback works |
| **F4 — Windows / IIS** | WinRM/PowerShell, cert store import, PFX, IIS binding, key ACL, rollback | LocalMachine\My + IIS binding updated and revertible |
| **F5 — Certificate Factory** | CSR wizard, RSA/EC keygen, PEM/PFX/P12 conversion, chain builder, artifact TTL/security | CSR + deployment artifacts produced via API/UI |
| **F6 — Java + Oracle Wallet** | keytool/orapki adapters, alias management, wallet backup/import | Store changes with versioned backup + verification |
| **F7 — CA Connectors** | Generic connector runtime, GlobalSign HVCA implementation, manual CA fallback | Request reaches CA without file shuffling; issued cert lands in inventory |
| **F8 — Automation** | Renewal scheduler, policy engine, approvals, maintenance windows, wave deployment, drift reconciliation, notifications | T-30 renewal runs end-to-end |
| **F9 — Network Adapters** | F5 BIG-IP first, then ISE/FortiGate/PA/Citrix, generic SSH toolkit | One LB vendor with HA-safe deploy |
| **F10 — Enterprise** | SSO/OIDC, fine-grained RBAC/ABAC, Vault/CyberArk, SIEM, HSM, HA/DR, multi-tenant | Enterprise hardening |

F0–F5 map to the MVP scope proposed in section 41 of the design document.
