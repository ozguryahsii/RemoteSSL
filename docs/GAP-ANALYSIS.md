# RemoteSSL — Doküman Karşılaştırmalı Eksik Analizi ve Faz Planı

Kaynak: `RemoteSSL Teknik Tasarım ve Yazılım Geliştirme Dokümanı v1.0` (tüm bölümler tarandı).
Bu dosya, dokümanda tanımlı olup üründe **henüz olmayan** her maddeyi listeler ve fazlara ayırır.
Tamamlanan işler burada tekrarlanmaz; referans için en altta özetlenmiştir.

Durum kodları: **YOK** = hiç yapılmadı · **KISMİ** = temel var, doküman kapsamı eksik.

---

## F11 — Sertifika politikası, lifecycle ve onay derinliği ✅ TAMAMLANDI

| # | Madde | Doküman | Durum |
|---|-------|---------|-------|
| 11.1 | Certificate policy modeli ve her aşamada uygulanması | §39 | ✅ `CertificatePolicy` entity'si, Policies ekranında CRUD, varsayılan politika seed'i |
| 11.2 | Request validation kuralları | §17.2 | ✅ wildcard, izinli/yasaklı domain suffix, max validity, ownership, EC curve, örtüşme uyarısı — bloklayan kurallar 422 + `findings` |
| 11.3 | Request state machine'de `PENDING_APPROVAL` → approve/reject | §19.1 | ✅ onay gelmeden key/CSR üretilmiyor; `POST /certificates/requests/{id}/approve` |
| 11.4 | Environment bazlı governance matrisi | §23.2 | ✅ `requireApprovalIn` / `requireWindowIn`; politika, çağıranın "onay gerekmiyor" demesini geçersiz kılar |
| 11.5 | Separation of duties + break-glass | §23.3 | ✅ kendi talebini onaylayamaz; `BreakGlassAdministrator` override eder ve `APPROVED_BREAK_GLASS` olarak audit'lenir |
| 11.6 | Lifecycle statülerinin yönetilmesi | §19.2 | ✅ `PendingDeployment` / `PartiallyDeployed` / `DeploymentFailed` / `Revoked` job sonucundan set ediliyor; expiry ile öncelik kuralı testli |
| 11.7 | Revoke akışı | FR-009, §19.2 | ✅ CA'ya revoke + envanterde işaretleme; manuel CA için `recordOnly` (audit'te `REVOKED_RECORDED`) |

## F12 — Deployment operasyon tamlığı

| # | Madde | Doküman | Durum |
|---|-------|---------|-------|
| 12.1 | `POST /api/v1/deployments/{id}/rollback` — manuel rollback endpoint'i ve UI aksiyonu | §27.1, FR-018 | YOK |
| 12.2 | `GET /api/v1/deployments/{id}/events` — ilerleme akışı / event geçmişi | §27.1 | YOK |
| 12.3 | Canary/wave stratejisinde onay bekleyen "manual per-target continuation" | §21.4 | YOK |
| 12.4 | HA pair standby-first stratejisi (F5 gibi çiftlerde standby önce) | §21.4, §14.3 | YOK |
| 12.5 | `Idempotency-Key` HTTP header'ı ile create endpoint'lerinde tekrar koruması | §27.2 | KISMİ (step düzeyinde idempotency var) |
| 12.6 | Deployment plan/impact önizlemesi: PROD deployment öncesi etkilenecek hedefler ve risk özeti | NFR-008 | YOK |
| 12.7 | Maintenance window'un manuel deployment'ta da uygulanması (şu an yalnız otomatik renewal yolunda) | FR-014, §20.1 | KISMİ |

## F13 — Artifact ve backup yönetimi

| # | Madde | Doküman | Durum |
|---|-------|---------|-------|
| 13.1 | `Artifact` entity'si: tip, hassasiyet sınıfı (public / sensitive / highly sensitive / backup), hash, TTL, sahiplik | §5.1, §31.1 | YOK |
| 13.2 | Artifact şifreleme zarfı: per-artifact data key + KMS/HSM korumalı KEK; DB'de yalnız referans + hash | §31.2 | YOK |
| 13.3 | S3 uyumlu object storage entegrasyonu (şifreli, versiyonlu, retention'lı) | §4.3, §31.1 | YOK |
| 13.4 | Private key içeren artifact için zorunlu TTL + secure deletion + erişim audit'i | §5.3, §15.4 | KISMİ (key hiç kalıcı tutulmuyor; politika nesnesi yok) |
| 13.5 | `POST /api/v1/artifacts/convert` — tek uçtan format dönüşümü (PEM/CRT/CER/P7B/PFX/P12/JKS/fullchain) | §27.1, FR-006 | KISMİ (csr/pfx/pfx-parse/chain/p7b ayrı ayrı var; JKS ve tek uç yok) |
| 13.6 | Backup retention politikası ve eski backup temizliği (hedefte veya object storage'da) | §31.1, §10.2/11 | KISMİ (hedefte timestamped backup var, retention yok) |
| 13.7 | Chain Builder derinliği: AIA üzerinden chain retrieval, cross-signed çoklu trust path gösterimi, eksik intermediate'te deployment bloklama | §15.3, FR-008 | KISMİ (sıralı chain kurulumu var) |

## F14 — Discovery ve monitoring derinliği

| # | Madde | Doküman | Durum |
|---|-------|---------|-------|
| 14.1 | Probe'da eksik X.509 alanları: Basic Constraints, Key Usage, Extended Key Usage, AIA/CDP/OCSP URI metadata | §6.2 | YOK |
| 14.2 | Gözlenen TLS sürümü **ve cipher** bilgisi (security posture) | §6.2 | KISMİ (protokol var, cipher yok) |
| 14.3 | Opsiyonel HTTP/HTTPS health-check ile application reachability izleme | §2.1 | YOK |
| 14.4 | Monitor bazlı probe policy alanları (protocol, timeout, retry) | §5.2 | KISMİ (interval var) |
| 14.5 | Monitor-certificate ilişkisinde `confidence` / `source` alanları | §5.2 | YOK |

## F15 — Kimlik, RBAC ve güvenlik mimarisi

| # | Madde | Doküman | Durum |
|---|-------|---------|-------|
| 15.1 | OIDC/SAML SSO (Entra ID/Keycloak) + upstream MFA | §4.3, §30.2 | YOK (yerel JWT var) |
| 15.2 | ABAC scope modeli: `scope.environment`, `scope.targetGroup`, `scope.adapter`, `condition.approvalRequired` | §24.2 | YOK (yalnız rol bazlı) |
| 15.3 | Rol seti tamlığı: Viewer, Security Auditor, Break-glass Administrator | §24.1 | KISMİ (4 rol var) |
| 15.4 | Runner kimliği için mTLS/client certificate ve revocation | §8.2, §30.2 | KISMİ (API key + HMAC imzalı job context) |
| 15.5 | Adapter paket imzalama / allowlist / sürüm sabitleme (supply-chain kontrolü) | §30.2, ADR-006 | YOK |
| 15.6 | Secure coding hattı: SBOM/dependency scan, SAST/DAST, secret scanning, image scan | §30.3 | YOK |
| 15.7 | CSRF koruması ve API rate limit | §30.2, §4.2 | YOK |

## F16 — Secret provider ve private key koruması

| # | Madde | Doküman | Durum |
|---|-------|---------|-------|
| 16.1 | CyberArk ve Azure Key Vault secret provider implementasyonları (enum'da var, kod yok) | §7.2, FR-020 | YOK |
| 16.2 | Credential tipleri: SSH certificate, Kerberos/WinRM service account, OAuth client credentials, bearer token, client certificate/PFX | §7.2 | KISMİ (user/pass + SSH key) |
| 16.3 | Secret rotation ve secret erişim audit'i | §7.3 | YOK |
| 16.4 | Runner'ın secret'ı doğrudan provider'dan short-lived credential ile alması | §7.3, ADR-003 | KISMİ (control plane broker) |
| 16.5 | HSM/KMS: PKCS#11 provider soyutlaması, cloud HSM key referansı, key export policy, key sahiplik metadata'sı | §16.3 | YOK |
| 16.6 | Windows non-exportable private key üretimi ve private key ACL (app pool/service account yetkisi) | §11.4 | YOK |

## F17 — Entegrasyonlar, event modeli ve bildirim

| # | Madde | Doküman | Durum |
|---|-------|---------|-------|
| 17.1 | SIEM/Syslog/Splunk forwarder | §33, §25.3 | YOK |
| 17.2 | ServiceNow change/ticket entegrasyonu | §33 | YOK |
| 17.3 | PagerDuty/Opsgenie incident entegrasyonu | §33 | YOK |
| 17.4 | Outbox pattern: DB commit ile event publish tutarlılığı | §28.2 | YOK |
| 17.5 | Domain event setinin tamamlanması (`CertificateDiscovered`, `RenewalDue`, `DeploymentApproved`, `RollbackStarted`, `RunnerOffline` …) ve şema/sözleşme | §28.1 | KISMİ |
| 17.6 | Bildirim başarısızlığının ayrı alarm üretmesi (lifecycle'ı bloklamadan) | §33 | KISMİ |

## F18 — Audit ve compliance sertleştirme

| # | Madde | Doküman | Durum |
|---|-------|---------|-------|
| 18.1 | Append-only garantisi: DB seviyesinde update/delete engeli (trigger/izin) veya hash-chain ile bütünlük | §5.3, §25.3, ADR-007 | YOK |
| 18.2 | WORM/object-lock veya SIEM forward ile dış kopya | §25.3 | YOK |
| 18.3 | Audit retention politikası (silme yalnızca retention ile) | §25.3 | YOK |
| 18.4 | Eksik audit alanları: authentication session id, source IP/device metadata, approval reference, old/new fingerprint | §25.1 | KISMİ |
| 18.5 | Audit arama/filtreleme ekranı (actor, action, tarih aralığı, obje, sonuç) | §43 | KISMİ (son 100 kayıt + trace) |

## F19 — Platform adapter derinliği ve capability-driven UI

| # | Madde | Doküman | Durum |
|---|-------|---------|-------|
| 19.1 | Capability-driven UI: adapter yeteneğine göre buton/aksiyon gösterimi | §9.3 | YOK |
| 19.2 | Windows Centralized Certificate Store (CCS) adapter'ı | §11.4 | YOK |
| 19.3 | RDP/WinRM sistem servis binding'leri | §11.4 | YOK |
| 19.4 | Network cihazlarında partition/tenant/context, HA pair sırası, commit/publish, management vs data plane ayrımı | §14.3 | KISMİ |
| 19.5 | Generic SSH/API fallback adapter'ı (kontrollü custom script/template) | §14.2 | YOK |
| 19.6 | Java: `keytool -list` çıktısından alias envanteri çıkarma (store discovery) | §12.3 | KISMİ |
| 19.7 | Vendor adapter'larının gerçek lab'da doğrulanması (IIS, Java, Oracle, F5, FortiGate, PA, ADC, ISE) | §36.2 | YOK (kod hazır, lab gerekli) |

## F20 — CA connector genişlemesi

| # | Madde | Doküman | Durum |
|---|-------|---------|-------|
| 20.1 | GlobalSign HVCA'nın canlı hesapla doğrulanması | §18.2 | Bekliyor (hesap gelince) |
| 20.2 | ACME connector (Let's Encrypt / enterprise ACME) | §18.3 | YOK |
| 20.3 | Microsoft AD CS connector | §18.3 | YOK |
| 20.4 | DigiCert, Sectigo, internal REST CA connector'ları | §18.3 | YOK |
| 20.5 | Asenkron durum modeli: polling + **webhook** hibriti | ADR-009 | KISMİ (polling var) |
| 20.6 | Domain validation akışı (HVCA domain claim / ACME challenge) uçtan uca UI | §18.1 | KISMİ (interface var) |

## F21 — Multi-tenant, HA/DR ve ölçek

| # | Madde | Doküman | Durum |
|---|-------|---------|-------|
| 21.1 | Tenant/organization sınırı: tüm ana entity'lerde tenant id + query-level isolation | §35, ADR-008 | YOK |
| 21.2 | Runner failover: offline runner'ın job'unun uyumlu ikinci runner'a devri (+ stateful backup uyarısı) | §8.2, §34.2 | KISMİ (pinned runner) |
| 21.3 | Runner affinity grupları | §34.2 | YOK |
| 21.4 | DB HA / PITR ve RPO-RTO planı; artifact object storage versioning | §34.1, §34.3 | YOK (dokümantasyon + runbook) |
| 21.5 | 10.000+ monitor endpoint ölçeğinde probe/deployment mimarisi doğrulaması | NFR-004 | YOK |

## F22 — Test stratejisi

| # | Madde | Doküman | Durum |
|---|-------|---------|-------|
| 22.1 | Contract test: adapter interface ve CA connector interface | §36.1 | YOK |
| 22.2 | Integration test lab: container'lı nginx/Apache/HAProxy/Java hedefleri (CI) | §36.1/36.2 | YOK |
| 22.3 | Failure injection: SSH timeout, invalid chain, reload failure, disk full, permission denied | §36.1 | YOK |
| 22.4 | Her adapter için zorunlu rollback testi | §36.1 | KISMİ (nginx E2E doğrulandı) |
| 22.5 | Security test: secret leakage, command injection, authorization bypass | §36.1 | YOK |
| 22.6 | Performance test: binlerce endpoint ve paralel deployment | §36.1 | YOK |

## F23 — Declarative manifest

| # | Madde | Doküman | Durum |
|---|-------|---------|-------|
| 23.1 | `apiVersion: remotessl/v1 / kind: CertificateDeployment` manifest'inin import/apply edilmesi (strategy + verification + targets) | §38 | YOK |

---

## Şu an tamam olanlar (referans)

Faz 1–10 çıktıları: monitor CRUD + TLS probe motoru + X.509 parser + inventory dedup/versioning;
dual-vantage (dış/iç) probe ve karşılaştırma; service path (F5→nginx→IIS) çok katmanlı analiz;
managed target/store/binding modeli ve tam CRUD; runner kayıt/heartbeat/job kuyruğu ve imzalı job
context; Linux (nginx/apache/haproxy/generic file), Windows/IIS (WinRM birincil, SSH alternatif),
Java keystore/truststore, Oracle wallet, F5/FortiGate/PaloAlto/Citrix ADC/Cisco ISE adapter'ları;
transactional pipeline (§21.1 remote verify dahil) + rollback; §21.4 sequential/parallel/wave/
all-at-once; certificate factory (CSR/PFX/chain/P7B); on-target key generation; manual + GlobalSign
HVCA connector; renewal policy + scheduler + drift reconciliation; approval workflow (deployment);
rol bazlı yetkilendirme + JWT; audit trail; Vault KV v2; e-posta/Teams/webhook/RabbitMQ bildirim;
§26 ekranları (inventory sütunları, 9 sekmeli detay, endpoint alanları); §43 dashboard;
§32.1 metrikler + `/metrics`, §32.2 uçtan uca trace + OpenTelemetry, §32.3 alarmlar.
