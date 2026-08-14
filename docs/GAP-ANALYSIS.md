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

## F12 — Deployment operasyon tamlığı ✅ TAMAMLANDI

| # | Madde | Doküman | Durum |
|---|-------|---------|-------|
| 12.1 | Manuel rollback | §27.1, FR-018 | ✅ `POST /deployments/{id}/rollback` — önceki sürümü aynı transactional pipeline ile geri koyar; Deployments ekranında "Roll back" |
| 12.2 | Job event akışı | §27.1 | ✅ `GET /deployments/{id}/events` — audit + step + runner job'ları tek zaman çizelgesinde; ekranda "Progress timeline" |
| 12.3 | Manual per-target continuation | §21.4 | ✅ `canary` / `manual` stratejileri dalgalar arasında durur; `POST /deployments/{id}/continue` |
| 12.4 | HA pair standby-first | §21.4, §14.3 | ✅ `ha-pair` stratejisi + target'ta `HaRole` (Managed Targets'tan düzenlenebilir) |
| 12.5 | `Idempotency-Key` header'ı | §27.2 | ✅ deployment ve request create uçlarında; tekrar aynı yanıtı döner (`Idempotency-Replayed: true`), farklı gövde 409 |
| 12.6 | Plan/impact önizlemesi | NFR-008 | ✅ `POST /deployments/plan` + Certificates ekranında "Preview impact": hedefler, bugün ne sunuyor, sıra, governance, blocker/uyarılar |
| 12.7 | Maintenance window manuel deployment'ta | FR-014, §20.1 | ✅ F11 ile geldi — `requireWindowIn` ortamlarında manuel deployment da pencereye tabi |

Ek olarak (listede yoktu, operasyonel çıkmazı kapatmak için eklendi): başlamamış job'lar için
`POST /deployments/{id}/cancel` — onaylanıp hiç çalıştırılmamış bir job binding'i §21.3
concurrency guard'ı yüzünden süresiz kilitliyordu.

## F13 — Artifact ve backup yönetimi ✅ TAMAMLANDI

| # | Madde | Doküman | Durum |
|---|-------|---------|-------|
| 13.1 | `Artifact` entity'si | §5.1, §31.1 | ✅ tip, hassasiyet sınıfı, hash, boyut, TTL, sahiplik, storage referansı; Certificates → Files/Artifacts sekmesinde listeleniyor |
| 13.2 | Envelope encryption | §31.2 | ✅ artifact başına rastgele AES-256-GCM data key, DataProtection KEK ile sarmalanıyor; DB'de yalnız ciphertext + hash, açarken bütünlük doğrulaması |
| 13.3 | S3 uyumlu object storage | §4.3, §31.1 | ✅ `Storage:S3:*` ayarlanınca devreye girer (MinIO/Ceph dahil), SSE-S3 ile yazar; ayarlanmazsa ciphertext veritabanında kalır |
| 13.4 | Key'li artifact için TTL + secure deletion + erişim audit'i | §5.3, §15.4 | ✅ Sensitive/HighlySensitive'e zorunlu TTL (varsayılan 24s), retention job'ı içeriği imha eder (metadata kanıt olarak kalır), her okuma `artifact.access` olarak audit'lenir |
| 13.5 | `POST /api/v1/artifacts/convert` | §27.1, FR-006 | ✅ pem/crt/cer/der/p7b/pfx/p12/**jks**/chain/fullchain/key tek uçta; sonuç inline dönebilir veya şifreli artifact olarak saklanabilir |
| 13.6 | Backup retention | §31.1 | ✅ adapter'ın hedefte bıraktığı backup'lar artifact metadata'sı olarak kaydediliyor; retention penceresi geçince temizlik gerektiği raporlanıyor (silinmiş gibi gösterilmiyor) |
| 13.7 | Chain Builder derinliği | §15.3, FR-008 | ✅ `POST /artifacts/chain/analyze`: tüm trust path'ler, cross-signed uyarısı, eksik intermediate isimlendirmesi, AIA URL'leri; eksik chain ile deployment chain'i üretilemez |

Not: RemoteSSL'in sakladığı private key'i içeren bir dönüşüm çıktısı API üzerinden **inline
dönmez** (§7.3/§22.3) — yalnızca şifreli artifact olarak saklanabilir ve indirme ucu da
key taşıyan artifact'leri reddeder.

## F14 — Discovery ve monitoring derinliği ✅ TAMAMLANDI

| # | Madde | Doküman | Durum |
|---|-------|---------|-------|
| 14.1 | Eksik X.509 alanları | §6.2 | ✅ Basic Constraints (CA + path length), Key Usage, Extended Key Usage, AIA caIssuers/OCSP, CRL dağıtım noktaları — parse edilip sürümle saklanıyor ve sertifika detayında görünüyor |
| 14.2 | TLS sürümü + cipher | §6.2 | ✅ negotiated cipher suite hem dış hem iç vantage'da kaydediliyor, Monitors ekranında protokolle birlikte gösteriliyor |
| 14.3 | HTTP/HTTPS health-check | §2.1 | ✅ monitor başına URL + beklenen durum kodu; sonuç TLS gözlemine karışmıyor, başarısızlıkta bildirim üretiliyor |
| 14.4 | Probe policy alanları | §5.2 | ✅ protocol, timeout, retry (transient hatalarda backoff'lu tekrar) — Monitors → Edit'ten düzenlenebilir |
| 14.5 | Monitor-certificate `confidence` / `source` | §5.2 | ✅ doğrudan handshake gözlemi 100 güven + `probe` / `internal-probe` kaynağı olarak kaydediliyor |

## F15 — Kimlik, RBAC ve güvenlik mimarisi ✅ TAMAMLANDI

| # | Madde | Doküman | Durum |
|---|-------|---------|-------|
| 15.1 | OIDC SSO + MFA | §4.3, §30.2 | ✅ `Auth:Oidc:*` ile Entra ID/Keycloak; yerel JWT ile birlikte çalışır, roller yerel hesaptan gelir, `Auth:Oidc:RequireMfa` ile IdP'nin MFA iddiası (amr/acr) zorunlu kılınır. **SAML yapılmadı** — her iki hedef IdP de OIDC konuşuyor; SAML üçüncü parti yığın gerektirir (aşağıdaki kalan listesinde) |
| 15.2 | ABAC scope modeli | §24.2 | ✅ kullanıcı başına kural listesi (action + environment + targetGroup + adapter + approvalRequired); deployment oluşturma her hedef için ayrı kontrol edilir, ret audit'lenir (`authorization.denied`) |
| 15.3 | Rol seti | §24.1 | ✅ yedi rolün tamamı; `Reader` ve `Auditor` politikaları eklendi, Settings ekranından atanabiliyor |
| 15.4 | Runner mTLS kimliği + revocation | §8.2, §30.2 | ✅ runner kendi anahtarını üretip CSR gönderir, control plane iç CA ile clientAuth sertifikası imzalar; `Runner:RequireMutualTls` ile zorunlu, revoke edilen kimlik API key'i geçerli olsa bile reddedilir |
| 15.5 | Adapter allowlist + sürüm sabitleme | §30.2, ADR-006 | ✅ `Security:Adapters:Allowed` / `PinnedVersions`; runner adapter sürümlerini bildirir, uymayan hedefe iş kuyruğa bile girmez. **Paket imzalama** dosya olarak dağıtılan plugin modeli olmadığı için kapsam dışı bırakıldı (gerekçe kodda) |
| 15.6 | Güvenlik CI hattı | §30.3 | ✅ `.github/workflows/security.yml`: NuGet/npm zafiyet taraması, gitleaks secret taraması, CodeQL SAST, CycloneDX SBOM, Trivy dosya sistemi taraması |
| 15.7 | Rate limit + güvenlik başlıkları | §30.2, §4.2 | ✅ çağıran başına dakikalık limit (runner trafiği ayrı, daha geniş kova; health/metrics muaf), 429 + Retry-After; `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Cross-Origin-Resource-Policy`. CSRF ayrı bir önlem gerektirmiyor: API cookie değil bearer token ile çalışıyor |

### F15'ten kalan
- **SAML SSO** — Entra ID ve Keycloak OIDC ile karşılandığı için ertelendi; SAML gerekirse
  Sustainsys.Saml2 benzeri bir yığın eklenmelidir.
- **Adapter paket imzalama** — adapter'lar runner binary'si içinde geldiği sürece imzalanacak
  bir paket yok; süreç dışı plugin modeli gelirse ADR-006 yeniden ele alınmalı.

## F16 — Secret provider ve private key koruması ✅ TAMAMLANDI

| # | Madde | Doküman | Durum |
|---|-------|---------|-------|
| 16.1 | CyberArk ve Azure Key Vault secret provider implementasyonları (enum'da var, kod yok) | §7.2, FR-020 | ✅ `ExternalSecretProviders.cs`: Vault + CyberArk CCP + Azure Key Vault, `ISecretProvider` arkasında |
| 16.2 | Credential tipleri: SSH certificate, Kerberos/WinRM service account, OAuth client credentials, bearer token, client certificate/PFX | §7.2 | ✅ `SecretMaterial` tüm tipleri taşıyor; `CredentialValidation` her tip için zorunlu alanları doğruluyor; UI tipe göre alan gösteriyor |
| 16.3 | Secret rotation ve secret erişim audit'i | §7.3 | ✅ `RotationIntervalDays`/`LastRotatedAt`, `/credentials/{id}/rotate`, `SecretRotationService` (leader-elected), `credential.access` + `credential.rotate` audit'i, `LastAccessedAt/By` |
| 16.4 | Runner'ın secret'ı doğrudan provider'dan short-lived credential ile alması | §7.3, ADR-003 | ✅ `Secrets:RunnerDirect=true` iken broker "Reference" döner; runner `RunnerSecretResolver` ile secret'ı kendisi çeker, plaintext control plane'e hiç uğramaz |
| 16.5 | HSM/KMS: PKCS#11 provider soyutlaması, cloud HSM key referansı, key export policy, key sahiplik metadata'sı | §16.3 | ✅ `IKeyProvider` + Software/PKCS#11/CloudKMS; `ManagedKey` (owner, team, environment, purpose, export policy); non-exportable key export'u 403 + audit; token key'i CSR'ı token üzerinde imzalıyor |
| 16.6 | Windows non-exportable private key üretimi ve private key ACL (app pool/service account yetkisi) | §11.4 | ✅ `Import-PfxCertificate` varsayılan non-exportable; `PrivateKeyReadAccounts` ile CNG/CSP key dosyasına read ACL |

### F16 notları
- PKCS#11 sağlayıcısı `Hsm:Pkcs11:LibraryPath` + `Pin` verilmedikçe `Enabled=false` döner; UI'da
  seçilemez. Cloud HSM için `AzureKeyVault:*` ayarları kullanılır (`azurekms://<vault>/<key>`).
- Token ve cloud key'ler tanım gereği exportable oluşturulamaz; istenirse istek reddedilir,
  sessizce software key'e düşülmez.

## F17 — Entegrasyonlar, event modeli ve bildirim ✅ TAMAMLANDI

| # | Madde | Doküman | Durum |
|---|-------|---------|-------|
| 17.1 | SIEM/Syslog/Splunk forwarder | §33, §25.3 | ✅ `SyslogChannel` (RFC 5424 + CEF, UDP/TCP) ve `SplunkHecChannel`; `Integrations:ForwardAuditToSiem` ile audit satırları `audit.*` olarak aynı transaction'da aynalanıyor |
| 17.2 | ServiceNow change/ticket entegrasyonu | §33 | ✅ `ServiceNowChannel` — Table API, sadece `ChangeWorthy` olaylar, correlation id ve urgency ile |
| 17.3 | PagerDuty/Opsgenie incident entegrasyonu | §33 | ✅ `PagerDutyChannel` (Events API v2) + `OpsgenieChannel`; sadece `Incidents` seti, dedup key/alias correlation id'den |
| 17.4 | Outbox pattern: DB commit ile event publish tutarlılığı | §28.2 | ✅ `OutboxMessage` + `OutboxNotificationSink` (çağıranın transaction'ına yazar) + `OutboxDispatcher` (kanal başına teslim, exponential backoff, leader-elected `OutboxDispatcherService`) |
| 17.5 | Domain event setinin tamamlanması ve şema/sözleşme | §28.1 | ✅ `DomainEvents` sözlüğü + `EventEnvelope` (id, event, schemaVersion, occurredAt, correlationId, payload); `CertificateDiscovered`, `RenewalDue`, `DeploymentRequested/Approved`, `RollbackStarted`, `RunnerOffline` artık yayımlanıyor |
| 17.6 | Bildirim başarısızlığının ayrı alarm üretmesi (lifecycle'ı bloklamadan) | §33 | ✅ `NotificationHealth` + dashboard `NotificationDeliveryFailure` alarmı + `notification.delivery-failed` olayı; Settings ekranında kanal durumu ve teslim edilemeyen olaylar için **Requeue** |

### F17 notları
- Bildirim artık hiçbir yerde fire-and-forget değil: `Notify` bir outbox satırı yazar, olay ancak
  onu doğuran değişiklikle birlikte commit olur. Rollback edilen bir iş kendini duyuramaz,
  commit olan bir iş de bir webhook düştüğü için sessiz kalamaz.
- Bir kanal teslim aldığında satıra işlenir; retry yalnızca başarısız kanalları tekrar dener,
  aynı olay ikinci kez gönderilmez. 6 denemeden sonra olay `Failed` olur ve kendi alarmını üretir.
- `audit.*` aynalama yalnız SIEM ve mesaj kuyruğuna gider; chat/mail kanalları onu almaz.

## F18 — Audit ve compliance sertleştirme ✅ TAMAMLANDI

| # | Madde | Doküman | Durum |
|---|-------|---------|-------|
| 18.1 | Append-only garantisi: DB seviyesinde update/delete engeli (trigger/izin) veya hash-chain ile bütünlük | §5.3, §25.3, ADR-007 | ✅ Her ikisi: Postgres trigger'ı içerik kolonlarının UPDATE'ini ve retention dışı DELETE'i reddediyor; `AuditChain` SHA-256 hash zinciri kuruyor ve `VerifyAsync` ilk kırılma noktasını raporluyor |
| 18.2 | WORM/object-lock veya SIEM forward ile dış kopya | §25.3 | ✅ `AuditArchive` mühürlenmiş satırları JSON Lines olarak object store'a yazıyor; `Storage:S3:ObjectLockDays` ile compliance-mode object lock. SIEM forward (F17) ikinci dış kopya |
| 18.3 | Audit retention politikası (silme yalnızca retention ile) | §25.3 | ✅ `Audit:RetentionDays`; yalnız arşivlenmiş ve bitişik prefix silinir (zincir kırılmaz), silme işlemi kendisi audit'lenir, DB trigger'ı başka yoldan silmeyi engeller |
| 18.4 | Eksik audit alanları: authentication session id, source IP/device metadata, approval reference, old/new fingerprint | §25.1 | ✅ `SessionId`, `SourceIp`, `UserAgent` request middleware'inden; `ApprovalReference`, `OldFingerprint`, `NewFingerprint` yazar parametreleri. Hepsi hash'e dahil |
| 18.5 | Audit arama/filtreleme ekranı (actor, action, tarih aralığı, obje, sonuç) | §43 | ✅ `/api/v1/audit` actor/action/objectType/objectId/result/from/to + skip/take; `/facets` form için; ekranda filtre çubuğu, sayfalama, satır detayı ve zincir durumu |

### F18 notları
- Mühürleme insert anında değil, leader-elected arka plan geçişinde yapılır: eşzamanlı yazarlar tek
  bir zincir başına serileşmez, sıralama da veritabanının atadığı monotonik id'den gelir.
- Zincir kırıldığında `audit.chain-broken` olayı üretilir, `AuditPipelineHealth`'e işlenir ve
  dashboard alarmı çıkar — sessizce log'a yazılmaz.
- Trigger, retention işine `SET LOCAL remotessl.audit_retention = 'on'` ile izin verir; başka
  hiçbir yol audit satırı silemez. Canlı Postgres'te dört senaryo da doğrulandı.

## F19 — Platform adapter derinliği ve capability-driven UI ✅ TAMAMLANDI (19.7 hariç — lab gerekli)

| # | Madde | Doküman | Durum |
|---|-------|---------|-------|
| 19.1 | Capability-driven UI: adapter yeteneğine göre buton/aksiyon gösterimi | §9.3 | ✅ `AdapterCatalog` + `GET /api/v1/adapters`; UI adapter listesini, alan tanımlarını ve aksiyonları buradan alıyor. Rollback yeteneği sunucuda da uygulanıyor |
| 19.2 | Windows Centralized Certificate Store (CCS) adapter'ı | §11.4 | ✅ `windows-ccs`: PFX UNC paylaşımına host adıyla yazılır, önceki dosya yedeklenir, `Enable-WebCentralCertProvider` opsiyonel |
| 19.3 | RDP/WinRM sistem servis binding'leri | §11.4 | ✅ `bindingTargets: ["rdp","winrm"]` — RDP thumbprint'i WMI'ya yazılır, WinRM HTTPS listener'ı yeniden oluşturulur |
| 19.4 | Network cihazlarında partition/tenant/context, HA pair sırası, commit/publish, management vs data plane ayrımı | §14.3 | ✅ FortiGate VDOM, PA vsys, Citrix admin partition, F5 partition; PA'da SSL/TLS profil binding + commit, Citrix'te config save; `skipCommit` ile kontrol. HA sırası F12'den (`HaRank`) |
| 19.5 | Generic SSH/API fallback adapter'ı (kontrollü custom script/template) | §14.2 | ✅ `generic-ssh`: install/validate/reload/verify/rollback komut şablonları, sabit placeholder seti, aynı transactional boru hattı |
| 19.6 | Java: `keytool -list` çıktısından alias envanteri çıkarma (store discovery) | §12.3 | ✅ `JavaKeystoreInventory` — alias, entry type, subject/issuer, serial, SHA-256, expiry; `POST /targets/{id}/stores/{storeId}/inventory` ve UI'da **Inventory** düğmesi |
| 19.7 | Vendor adapter'larının gerçek lab'da doğrulanması | §36.2 | ⛔ ERTELENDİ — bu ortamda gerçek IIS/Java/Oracle/F5/FortiGate/PA/ADC/ISE cihazı yok. Kod ve birim testleri hazır; doğrulama fiziksel/sanal lab gerektiriyor |

### F19 notları
- Capability kataloğu tek kaynak: UI'nın gösterdiği ile runner'ın yapabildiği ayrışamaz. Katalogda
  olmayan bir adapter UI'da görünmez, katalogda `supportsRollback=false` olan bir adapter için
  rollback ne UI'da sunulur ne de sunucuda kabul edilir (Cisco ISE sertifikayı yerinde değiştirir).
- `generic-ssh` komutları yalnızca target'ın kendi yapılandırmasından gelir; sertifika alanı,
  target adı veya dışarıdan etkilenebilen hiçbir veri komut üretmez.
- PAN-OS ve Citrix'te commit/save adımı varsayılan açık: sonradan kaybolan bir değişiklik,
  görünür bir hatadan daha kötüdür.

## F20 — CA connector genişlemesi ✅ TAMAMLANDI (20.1 hariç — canlı hesap gerekli)

| # | Madde | Doküman | Durum |
|---|-------|---------|-------|
| 20.1 | GlobalSign HVCA'nın canlı hesapla doğrulanması | §18.2 | ⛔ BEKLİYOR — hesap gelince. Kod ve endpoint eşlemesi hazır (docs/ca-connector.md) |
| 20.2 | ACME connector (Let's Encrypt / enterprise ACME) | §18.3 | ✅ RFC 8555: directory, nonce, ES256 JWS, EAB, order → authorization → challenge → finalize → download; dns-01/http-01; revocation |
| 20.3 | Microsoft AD CS connector | §18.3 | ✅ certsrv web enrollment: template = profile, certfnsh.asp submit, request id çıkarımı, manager onayı bekleyen istek ayrımı, certnew.cer/p7b indirme |
| 20.4 | DigiCert, Sectigo, internal REST CA connector'ları | §18.3 | ✅ `digicert` (CertCentral), `sectigo` (SCM preset), `rest-ca` (endpoint yolları yapılandırmadan) |
| 20.5 | Asenkron durum modeli: polling + **webhook** hibriti | ADR-009 | ✅ `POST /api/v1/ca/webhook/{connectorId}` (HMAC veya token), callback yalnızca ipucu — durum daima CA'dan okunur; polling fallback olarak açık kalır |
| 20.6 | Domain validation akışı uçtan uca UI | §18.1 | ✅ `DomainValidation` entity + `IOrderValidationConnector`; `GET/POST /api/v1/requests/{id}/validations`; Requests ekranında "Domain validation" paneli (yayımlanacak DNS/HTTP kaydı + Verify) |

### F20 notları
- Webhook gövdesinden **hiçbir** issuance bilgisi alınmaz; sahte bir callback en fazla fazladan bir
  poll'a yol açar. Callback'te tanınan bir request id yoksa o connector'ın tüm açık istekleri
  yeniden kontrol edilir.
- ACME'de finalize ayrı bir adımdır; polling döngüsü sipariş "ready" olduğunda CSR'ı gönderir,
  aksi halde sipariş sonsuza kadar orada kalırdı.
- Canlı doğrulama sınırı: bu ortamdan dışarı ACME dizinine (Let's Encrypt staging) erişim yok,
  bu yüzden protokol alışverişi uçtan uca çalıştırılamadı. Kriptografik kısım (key authorization,
  JWK thumbprint, dns-01 kayıt değeri, CSR isim çıkarımı, PEM bundle ayrımı) birim testleriyle
  doğrulandı; webhook kimlik doğrulaması canlı API'de doğrulandı.

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
