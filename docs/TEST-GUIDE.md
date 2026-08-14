# RemoteSSL — macOS Test Rehberi

Tüm fazların çekirdeği implemente edildi. Bu rehber, macOS üzerinde uçtan uca test adımlarını içerir.

## Önkoşullar

- .NET 8 SDK (`brew install dotnet-sdk` veya dot.net'ten)
- Node.js 20+ (`brew install node`)
- Docker Desktop

## 1. Kurulum ve başlatma

```bash
git clone <repo> && cd RemoteSSL
git checkout claude/tls-lifecycle-manager-qv7tc5

docker compose up -d                  # PostgreSQL + RabbitMQ + Redis

dotnet run --project src/RemoteSSL.Api        # → http://localhost:5200 (Swagger: /swagger)
# İlk açılışta veritabanı şeması otomatik uygulanır (dotnet-ef gerekmez).
dotnet run --project src/RemoteSSL.Runner     # ayrı terminalde — runner otomatik register olur
cd frontend && npm install && npm run dev     # → http://localhost:5173
```

Doğrulama: `curl http://localhost:5200/health` → `Healthy`; UI'da **Runners** ekranında `runner-local` Online görünmeli.

## 2. Dashboard (§43 / §32.1 / §32.3)

Dashboard tek çağrıda (`GET /api/v1/dashboard`) şunları gösterir:

- **Aktif alarmlar (§32.3):** critical certificate expiry, deployment partial failure, rollback failure,
  runner offline, renewal failure, CA error, drift/vantage mismatch, probe failure
- **Metrikler (§32.1):** toplam/expiring sertifika, probe success rate, deployment success rate,
  ortalama deploy süresi, rollback sayısı, runner online/total, job queue depth, renewal failure,
  drift (7 gün), bekleyen onay
- **Critical & expiring certificates:** 30 günden az kalanlar — durum, kalan gün, issuer, environment,
  monitor/deployment sayısı, auto-renew durumu
- **Failed deployment jobs:** başarısız/kısmi/rollback olan işler, kaç hedefin patladığı
- **Runner health:** her runner'ın durumu, segmenti, son heartbeat'i
- **Renewal queue:** işlemde olan sertifika talepleri, state ve yaş
- **Pending approvals** ve son **drift/vantage mismatch** olayları

Her bölümün başlığında ilgili ekrana giden link vardır. Veriler 20 saniyede bir tazelenir.

## 3. Faz 1 — SSL Monitoring & Inventory

1. UI → **Monitors** → `google.com` port `443` ekleyin → **Probe now**.
2. Beklenen: Success, TLS protokolü, gözlenen sertifika CN'i, kalan gün, chain durumu.
3. Aynı sertifikayı kullanan ikinci bir endpoint ekleyin (ör. `www.google.com`) → **Certificates** ekranında tek envanter kaydı, iki monitor bağı.
4. Sertifika detayında version, SAN, thumbprint ve monitor listesi görünmeli.
5. **Audit** ekranında `certificate.expiring` eşik olayları (T-90/T-60…) görünür.

## 4. Faz 2+3 — Managed Target & Linux (Nginx) Deployment

Test hedefi olarak lokal bir nginx + SSH kullanın (`test-lab/README.md`'de Docker imajı var; macOS'te Docker ile):

```bash
docker build -t remotessl-lab test-lab/
docker run -d --name remotessl-lab -p 2222:22 -p 8444:443 remotessl-lab
```

1. UI → **Credentials** → name `lab-root`, username `root`, password `remotessl`.
2. **Managed Targets** → name `lab-nginx`, adapter `nginx`, host `localhost`, port `2222`, credential `lab-root` → **Test connection** → `OK` beklenir.
3. **Add store** → `/etc/nginx/ssl`.
4. Yeni sertifika üretin ve envantere yükleyin (Swagger `POST /api/v1/artifacts/csr` + kendi CA'nızla imzalayın, ya da hızlıca):
   ```bash
   openssl req -x509 -newkey rsa:2048 -keyout new.key -out new.crt -days 60 -nodes -subj "/CN=deployed.local"
   # Swagger → POST /api/v1/artifacts/upload  { certPem, keyPem }
   ```
5. Binding oluşturun (Swagger `POST /api/v1/targets/stores/{storeId}/bindings`):
   ```json
   { "certificateId": "<certId>", "serviceBinding": {
       "certPath": "/etc/nginx/ssl/server.crt", "keyPath": "/etc/nginx/ssl/server.key",
       "validateCmd": "nginx -t", "reloadCmd": "nginx -s reload" } }
   ```
   (Container'da systemd yok; gerçek sunucuda `reloadCmd` vermezseniz `systemctl reload nginx` kullanılır.)
6. `POST /api/v1/deployments` `{ certificateVersionId, bindingIds: [...] }` → `POST /api/v1/deployments/{id}/execute`.
7. **Deployments** ekranında adım adım pipeline'ı izleyin: PreCheck → Backup → Install → ConfigValidate → Reload → LocalVerify → Commit.
8. Doğrulama: `echo | openssl s_client -connect localhost:8444 | openssl x509 -noout -subject` → yeni CN.

### Rollback testi
Uyumsuz key ile yeni bir version yükleyin (`openssl genrsa` ile bağımsız key) ve deploy edin →
`nginx -t` fail olur, job **RolledBack** biter, eski sertifika sunulmaya devam eder.

## 5. Faz 5 — Certificate Factory

Swagger üzerinden:
- `POST /api/v1/artifacts/csr` — RSA 2048/4096, EC P-256/P-384 CSR + key
- `POST /api/v1/artifacts/pfx` / `pfx/parse` — PEM↔PFX dönüşümü
- `POST /api/v1/artifacts/chain` — leaf + karışık intermediate havuzundan sıralı chain (root hariç)

## 6. Faz 7 — CA Connector (Manual + GlobalSign)

Manual akış (GlobalSign hesabı gelene kadar):
1. UI → **Certificate Requests** → CN girin, CA olarak `Manual CA` seçin (yoksa Swagger `POST /api/v1/ca-connectors` `{"name":"Manual CA","connectorType":"manual"}`).
2. CSR üretilir, state `WaitingForCertificate` olur. CSR'ı kendi CA'nızla imzalayın.
3. **Upload issued cert** ile imzalı sertifikayı yükleyin → state `Issued`, envantere private key'li version düşer → deploy edilebilir.

GlobalSign geldiğinde: `POST /api/v1/ca-connectors` `{"name":"GlobalSign","connectorType":"globalsign-hvca","config":{"baseUrl":"...","apiKey":"...","apiSecret":"...","clientPfxBase64":"...","clientPfxPassword":"..."}}` → `POST /api/v1/ca-connectors/{id}/test`.

## 7. Faz 8 — Otomasyon (renewal + approval + drift)

1. Swagger → `POST /api/v1/policies` `{ "name":"prod-30", "triggerDays":30, "autoDeploy":true, "approvalRequired":true, "caConnectorId":"<manual-ca-id>" }`
2. `POST /api/v1/policies/{id}/assign` `{ "certificateId": "<30 günden az kalmış cert>" }`
3. ~1 dk içinde otomasyon renewal request üretir (**Certificate Requests**'te `automation` tarafından).
4. Manual CA ise imzalayıp yükleyin → binding'i varsa otomatik deployment job'ı oluşur → **Approvals** ekranında onaylayın (requester ≠ approver kuralı zorunlu) → maintenance window açıksa otomatik execute edilir.
5. Drift: hedefteki sertifikayı elle eski haline döndürün; monitor probe + otomasyon `drift.detected` audit olayı üretir.
6. Bildirimler: `appsettings.json` → `Notifications:WebhookUrl` / `TeamsWebhookUrl` / `Smtp:*` doldurun; expiring/deployment/drift olayları bu kanallara ve RabbitMQ `remotessl.events` exchange'ine düşer (RabbitMQ UI: http://localhost:15672, remotessl/remotessl_dev).

## 8. Faz 10 — Auth, RBAC ve kullanıcılar

`src/RemoteSSL.Api/appsettings.json` → `"Auth": { "Enabled": true }` yapıp API'yi yeniden başlatın.
- UI otomatik olarak `/login` sayfasına yönlendirir; `admin` / `admin` ile girin.
- **Settings** ekranından yeni kullanıcılar oluşturun (rol seçerek). Rol → yetki eşlemesi:
  Viewer (okuma), CertificateOperator (request/factory), DeploymentOperator (target/deployment),
  CertificateApprover (onay), PlatformAdministrator (credential/CA/policy/user).
- Yanlış roldeki kullanıcıyla yazma endpoint'i çağırın → 403 beklenir.
- Auth kapalıyken tüm ekranlar login'siz çalışır (dev modu).

## 9. UI üzerinden deployment (yeni)

**Certificates** ekranında bir sertifikaya tıklayın → **Deploy** bölümü: version + binding seçin,
istenirse "require approval" işaretleyin → **Deploy**. Onaysızsa job anında koşar; onaylıysa Approvals ekranına düşer.

## 10. On-target key generation (yeni)

Private key'in hedeften hiç çıkmadığı model (tasarım §16.1):
```
POST /api/v1/certificates/requests
{ "commonName":"ontarget.local", "keyOrigin":"target",
  "targetId":"<lab-nginx-target-id>", "targetKeyPath":"/etc/nginx/ssl/ontarget.key",
  "caConnectorId":"<manual-ca-id>" }
```
Runner hedefte `openssl` ile 0600 izinli key + CSR üretir; CSR kontrol düzlemine döner, state `CsrGenerated`/`WaitingForCertificate` olur. İmzalayıp yükleyince deploy sırasında key gönderilmez (hedefte zaten var).

## 11. HashiCorp Vault (opsiyonel)

`appsettings.json` → `"Vault": { "Addr": "http://localhost:8200", "Token": "..." }`.
Credential oluştururken provider `HashiCorpVault`, secretIdentifier `vault://secret/prod/web01`
(KV v2; data içinde `password` ve/veya `privateKey` alanları). Runner, secret'i broker üzerinden execution anında alır.

## 12. İç DNS endpoint'leri ve katmanlı (F5 → nginx → IIS) analiz — yeni

**Dış + iç çift sorgu (dual vantage) — en pratik yöntem:**

Monitor eklerken/düzenlerken uygulamanın yanında çalışan bir runner seçin. RemoteSSL aynı endpoint'i
**iki yerden birden** sorgular ve cevapları karşılaştırır:

- **Outside (control plane)** — dış/kurumsal DNS'ten çözülen, yayınlanan endpoint ne sunuyor
- **Inside (runner)** — uygulama sunucusunun kendisi ne sunuyor

Karşılaştırma sonucu (Comparison sütunu):

| Sonuç | Anlamı |
|---|---|
| `Match` | İki taraf aynı sertifikayı sunuyor — sorun yok |
| `Mismatch` | **Farklı sertifikalar** — hangi tarafın eski kaldığı (dış mı iç mi) detayda yazar; yenilemede atlanan katman odur |
| `InternalOnly` | Dışarıdan çözülmüyor/erişilmiyor (iç servis) |
| `ExternalOnly` | Uygulama sunucusu runner'a cevap vermedi |
| `NotConfigured` | Runner atanmamış, karşılaştıracak ikinci taraf yok |

Sadece iç DNS'te olan servisler için **"probe externally"** kutusunu kapatın; dış sorgu denenmez.
`Mismatch` durumunda audit'e `vantage.mismatch` olayı düşer ve bildirim kanallarına gider.

(Runner'ı ilgili segmentte çalıştırmanız gerekir: `dotnet run --project src/RemoteSSL.Runner`,
`appsettings.json` → `ControlPlane:Url` kontrol düzlemine bakacak şekilde.)

**Service Paths (katman analizi) — nasıl tanımlanır:**

Önce **her katman için ayrı bir monitor** ekleyin. Hepsinde host o katmanın **kendi adresi**,
SNI ise **uygulamanın hostname'i** olur (böylece her katman aynı sertifikayı sunmak zorundadır):

| Katman | Host (monitor) | Port | SNI | Probe |
|---|---|---|---|---|
| 1. F5 VIP | `10.184.10.20` (VIP IP) | 443 | `emakin.viennalife.com.tr` | via runner |
| 2. nginx | `10.184.20.31` (nginx sunucu IP) | 443 | `emakin.viennalife.com.tr` | via runner |
| 3. IIS | `10.184.33.5` (IIS sunucu IP) | 443 | `emakin.viennalife.com.tr` | via runner |

Sonra **Service Paths** bölümünde:
1. Sol kutuya path adı yazın (ör. `emakin prod`).
2. Açılır listeden 1. katmanı seçip **Add hop** → sonra 2. katman → sonra 3. katman.
   Eklenen hop'lar numaralı liste olarak görünür; sıra yanlışsa `↑ ↓` ile düzeltin, `×` ile çıkarın.
3. **Save path** → tabloda satır oluşur → **Analyze**.

Analiz her hop'u ayrı probe eder ve şu verdict'leri üretir:
- `Healthy` / `ExpiringSoon` / `Critical` — normal expiry durumu
- **`StaleCertificate`** — bu katman diğerlerinden farklı (daha eski) sertifika sunuyor;
  yani son yenilemede **bu katman atlanmış**
- `Expired` — süresi dolmuş
- `Unreachable` — erişilemedi (iç DNS ise: runner atayın)

Doğrulanmış örnek çıktı:
```
ATTENTION — hop 2 (localhost:8445): StaleCertificate
  hop1 localhost:8444 via=control-plane -> Healthy        (59 gün)
  hop2 localhost:8445 via=runner       -> StaleCertificate (bu katman son yenilemede atlanmış)
```

## 13. Windows / IIS, Java, Oracle, F5, diğer vendorlar (kod hazır, lab gerekli)

Bu adapterlar implemente edildi ancak bu ortamda gerçek hedef olmadığı için canlı test edilmedi:

- **Windows/IIS** — adım adım:
  1. **Hedef Windows sunucusunda OpenSSH Server kurun** (yönetici PowerShell):
     ```powershell
     Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
     Start-Service sshd
     Set-Service sshd -StartupType Automatic
     New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
     ```
     Doğrulama (kendi Mac'inizden): `ssh KULLANICI@10.184.33.5` → PowerShell/cmd açılmalı.
     Kullanıcı **yerel yönetici** olmalı (cert store + IIS binding yazma yetkisi için).
  2. **RemoteSSL → Credentials**: Windows kullanıcı adı + parolası (domain hesabıysa `DOMAIN\kullanici`).
  3. **Managed Targets**: adapter `iis`, host `10.184.33.5`, port `22`, credential'ı seçin → **Test connection** → OK beklenir.
  4. **Add store** → `LocalMachine\My`.
  5. Sertifikaya binding ekleyin; `serviceBinding` içine IIS bilgisi verin (Swagger `POST /api/v1/targets/stores/{storeId}/bindings`):
     ```json
     { "certificateId": "<certId>",
       "serviceBinding": { "iisSiteName": "Default Web Site", "iisPort": 443, "iisHostHeader": "btnobet.viennalife.com" } }
     ```
     (`iisSiteName` vermezseniz sadece store import yapılır, binding güncellenmez.)
  6. **Certificates → Deploy**: private key'li bir version seçin (upload/CSR ile gelmiş olmalı — sadece monitor'dan gözlenen versiyonların key'i yoktur, deploy edilemez).
     Pipeline: PFX kontrol düzleminde üretilir → SSH ile temp'e kopyalanır (parola argv'ye girmez) → `Import-PfxCertificate` → IIS https binding yeni thumbprint'e çevrilir → readback doğrulanır → hata halinde binding eski thumbprint'e geri döner. Temp PFX/parola dosyaları her durumda silinir.
- **Java keystore**: adapter `java-keystore`/`java-truststore`, store path JKS yolu, alias verin; parola credential'dan gelir, `storepass:env` ile komut satırına sızmaz.
- **Oracle Wallet**: adapter `oracle-wallet`, store path wallet dizini; `ewallet.p12`+`cwallet.sso` birlikte yedeklenip birlikte döner.
- **F5 BIG-IP**: adapter `f5-bigip`, connection `{"managementUrl":"https://...","allowInsecureTls":true}`; cert/key objeleri timestamped oluşturulur, client-ssl profili yeniden bağlanır, rollback profili eski objelere döndürür.
- **FortiGate / Palo Alto / Citrix ADC / Cisco ISE**: adapter tipleri `fortigate`, `paloalto`, `citrix-adc`, `cisco-ise`; connection `{"managementUrl":"...","apiToken":"..."}` (token'lı vendorlar), binding'e `certObjectName` + `bindingRef` (PA'da commit otomatik, ADC'de config save otomatik). Gerçek cihazda doğrulanmalı.

## 14. Observability: metrikler, latency ve uçtan uca trace — yeni

**Prometheus endpoint (§32.1)** — doküman metrik isimleriyle scrape edilebilir:

```bash
curl http://localhost:5200/metrics
# certificates_total / certificates_expiring / probe_success_rate
# probe_latency_seconds{quantile="0.5"} / {quantile="0.95"}
# deployment_success_rate / deployment_duration_seconds / rollback_count
# runner_online / runner_offline / queue_depth
# ca_request_latency_seconds{...} / renewal_failure_count / drift_detected_count
# audit_pipeline_failure_count
```

**Latency metrikleri**: her TLS probe (dış vantage kontrol düzleminde, iç vantage runner'da
ölçülür) ve her CA connector çağrısı `MetricSamples` tablosuna yazılır. Dashboard'da p50/p95
kartları ve 7 günlük p95 trendi görünür. Örneklem toplamak için birkaç probe çalıştırın:

```bash
MID=$(curl -s http://localhost:5200/api/v1/monitors | python3 -c "import json,sys;print(json.load(sys.stdin)[0]['id'])")
for i in 1 2 3; do curl -s -X POST http://localhost:5200/api/v1/monitors/$MID/probe -o /dev/null; done
curl -s http://localhost:5200/api/v1/dashboard | grep -o '"probeLatencyP50Ms":[^,]*'
```

Saklama süresi `Observability:MetricRetentionDays` (varsayılan 30 gün); temizlik leader-elected
arka plan görevi ile yapılır. Audit kayıtları bu temizliğe dahil değildir (§25.3).

**Expiry breakdown**: dashboard'da sertifikalar kalan ömre göre gruplanır
(Expired / 0-7 / 8-30 / 31-60 / 61-90 / 90+ gün).

**Audit pipeline failure alarmı (§32.3)**: audit satırı taşıyan bir SaveChanges hata alırsa
kayıt tutulur ve dashboard'da kritik alarm + `audit_pipeline_failure_count` metriği üretilir.

**Uçtan uca trace (§32.2)**: tek bir correlation ID
`certificate request → CA → deployment job → runner job → target` zinciri boyunca taşınır.

- **Audit** ekranında satırdaki trace id'ye tıklayın → istek, deployment job'ları, runner job'ları,
  latency örnekleri ve tüm audit adımları tek panelde listelenir.
- API: `GET /api/v1/audit/trace/{correlationId}`, ayrıca `GET /api/v1/audit?correlationId=...`.
- OpenTelemetry: `Observability:OtlpEndpoint` ayarlanırsa API ve runner span'leri OTLP ile
  (Jaeger/Tempo/collector) dışarı aktarılır; ayarlanmazsa hiçbir dış bağımlılık gerekmez.

  ```json
  // appsettings.json (API ve/veya Runner)
  { "Observability": { "OtlpEndpoint": "http://localhost:4317", "MetricRetentionDays": 30 } }
  ```

## 15. Sertifika politikası, onay ve revoke (F11) — yeni

**Politika ekranı**: **Policies → Certificate policies**. İlk açılışta "Default certificate policy"
otomatik oluşur (RSA ≥ 2048, EC P-256/P-384, PROD'da onay zorunlu, separation of duties açık).
Ekrandan yeni politika eklenebilir, düzenlenebilir, silinebilir; bir sertifikaya özel politika
`PATCH /api/v1/certificates/{id}` içindeki `certificatePolicyId` ile bağlanır.

**Politika ihlali** (bloklayan kural → 422 + hangi kuralın ihlal edildiği):

```bash
curl -s -X POST http://localhost:5200/api/v1/certificates/requests \
  -H 'Content-Type: application/json' \
  -d '{"commonName":"weak.company.com","keySizeOrCurve":1024,"requestedBy":"test"}'
# {"title":"Policy violation: RSA key size 1024 is below the policy minimum 2048.", ...}
```

**Örtüşme uyarısı** (bloklamaz, `warnings` içinde döner ve ekranda sarı satır olarak görünür):
envanterde zaten olan bir CN ile yeni request açın.

**PROD onay akışı** (§19.1 + §23.2 + §23.3):

1. **Certificate Requests** ekranında formu doldururken **Environment** alanına `PROD` yazın.
2. Request `PendingApproval` durumunda kalır — **bu aşamada henüz private key/CSR üretilmez**.
3. Satırdaki **Approve** ile onaylayın. Talebi açan kişinin kullanıcı adını girerseniz reddedilir
   ("Requester cannot approve their own certificate request"); farklı bir onaycı girin.
4. Onay sonrası CSR üretilir, CA seçiliyse otomatik gönderilir.

**Deployment onayı**: PROD ortamındaki bir sertifika için deployment açarsanız, istek `approvalRequired:false`
gelse bile politika onayı zorunlu kılar (`PendingApproval`). Onaylarken de separation of duties uygulanır.
`BreakGlassAdministrator` rolündeki kullanıcı kendi değişikliğini onaylayabilir; audit'te `APPROVED_BREAK_GLASS` görünür.

**Bakım penceresi**: politikada `requireWindowIn` içine bir ortam yazarsanız (örn. `PROD`), o ortamdaki
deployment yalnızca sertifikanın renewal policy'sindeki pencere açıkken çalışır — manuel deployment dahil.

**Lifecycle statüleri**: deployment devam ederken sertifika `PendingDeployment`, kısmi başarısızlıkta
`PartiallyDeployed`, başarısızlıkta `DeploymentFailed` görünür. Süresi dolmuşsa `Expired` her zaman öne çıkar,
revoke edilmişse `Revoked` kalıcıdır.

**Revoke**: **Certificates → sertifika → Overview → Versions** altındaki **Revoke at CA** düğmesi.
CA connector'ı ile üretilmiş sürümlerde CA'ya revoke isteği gider. Manuel/offline CA'da RemoteSSL revoke
edemez; ekran "kayıt olarak işaretleyeyim mi?" diye sorar ve onaylarsanız audit'e `REVOKED_RECORDED` düşer
(envanter "RemoteSSL revoke etti" demez).

## 16. Deployment operasyonları (F12) — yeni

**Plan / impact önizlemesi**: **Certificates → sertifika → Overview → Deploy** bölümünde
**Preview impact**. Hangi hedefler etkilenecek, o hedefler bugün hangi sertifikayı sunuyor,
çalışma sırası ne, onay/pencere gerekiyor mu ve çalışmayı engelleyecek bir şey var mı — hepsi
deploy'a basmadan önce görünür. Blocker varsa Deploy düğmesi pasifleşir.

```bash
curl -s -X POST http://localhost:5200/api/v1/deployments/plan -H 'Content-Type: application/json' \
  -d '{"certificateVersionId":"<versionId>","bindingIds":["<bindingId>"],"strategy":"ha-pair"}'
```

**Yeni stratejiler** (Deploy bölümündeki açılır listede):
- `canary` — önce N hedef, sonra elle devam.
- `manual` — her dalgada elle devam.
- `ha-pair` — çiftlerde **standby** üye önce. Rolü **Managed Targets → Edit → HA role** ile verirsiniz.

Duraklamış bir job'ı sürdürmek: **Deployments → job → Continue next wave**
(`POST /api/v1/deployments/{id}/continue`).

**Manuel rollback**: **Deployments → job → Roll back**. Önceki sertifika sürümü aynı hedeflere,
aynı transactional pipeline'dan (backup → install → validate → reload → remote verify) geri konur.
Ortam onay gerektiriyorsa rollback job'ı da onay bekler ve bunu yanıtta açıkça söyler.

**Job iptali**: onaylanmış ama hiç çalıştırılmamış bir job binding'i kilitler. **Cancel job**
düğmesi (`POST /api/v1/deployments/{id}/cancel`) bunu serbest bırakır. Çalışan bir job iptal
edilemez — onun yolu rollback'tir.

**Progress timeline**: job detayında audit kayıtları, adım sonuçları ve runner job'ları tek
zaman çizelgesinde (`GET /api/v1/deployments/{id}/events`).

**Idempotency-Key** (§27.2): aynı isteği iki kez göndermek ikinci bir job/talep yaratmaz.

```bash
curl -s -X POST http://localhost:5200/api/v1/certificates/requests \
  -H 'Content-Type: application/json' -H 'Idempotency-Key: my-key-1' \
  -d '{"commonName":"idem.company.com","keySizeOrCurve":2048,"requestedBy":"test"}'
# aynı komutu tekrar çalıştırın → aynı id döner, yanıtta "Idempotency-Replayed: true"
# aynı key + farklı gövde → 409
```

## 17. Artifact yönetimi ve format dönüşümü (F13) — yeni

**Ekran**: **Certificates → sertifika → Files / Artifacts**. Üstte dönüştürücü, altta bu sürüm
için saklanan artifact'ler (dosya, sınıf, depolama, TTL, hash) listelenir.

**Format dönüşümü** (§15.2, FR-006) — pem / der / p7b / pfx / jks / chain / fullchain:

```bash
# Public çıktı inline döner
curl -s -X POST http://localhost:5200/api/v1/artifacts/convert -H 'Content-Type: application/json' \
  -d '{"to":"pem","certificateVersionId":"<versionId>"}'

# Key taşıyan çıktı (PFX/JKS) inline DÖNMEZ; şifreli artifact olarak saklanır
curl -s -X POST http://localhost:5200/api/v1/artifacts/convert -H 'Content-Type: application/json' \
  -d '{"to":"jks","certificateVersionId":"<versionId>","password":"storepass","alias":"app","store":true}'
```

JKS gerçek bir Java keystore'dur: key varsa PrivateKeyEntry + sıralı chain, yoksa trusted
certificate entry (truststore) yazılır.

**Güvenlik davranışı**: RemoteSSL'in sakladığı private key'i içeren çıktı API'den inline
dönmez (422 ile açıklar), saklanan key'li artifact indirilemez (422). Public artifact indirilir.

**Saklama ve imha** (§31): her artifact kendi rastgele AES-256-GCM anahtarıyla şifrelenir,
anahtar DataProtection KEK'i ile sarmalanır; veritabanında düz içerik yoktur.

```bash
curl -s "http://localhost:5200/api/v1/artifacts/stored?certificateVersionId=<versionId>"
curl -s -X DELETE http://localhost:5200/api/v1/artifacts/stored/<artifactId>   # secure delete
```

Key taşıyan artifact'lere zorunlu TTL verilir (varsayılan 24 saat); arka plan görevi süresi
dolanların içeriğini imha eder, metadata satırı kanıt olarak kalır (`purgedAt`, `purgeReason`).
Public artifact'ler için `Storage:PublicArtifactRetentionDays` (varsayılan 365) geçerlidir.

**S3 / MinIO** (opsiyonel): `Storage:S3:BucketName` verilirse ciphertext bucket'a yazılır.

```json
{ "Storage": {
    "ArtifactProvider": "s3",
    "S3": { "BucketName": "remotessl-artifacts", "ServiceUrl": "http://localhost:9000",
            "AccessKey": "...", "SecretKey": "...", "ForcePathStyle": true } } }
```

**Chain analizi** (§15.3):

```bash
curl -s -X POST http://localhost:5200/api/v1/artifacts/chain/analyze -H 'Content-Type: application/json' \
  -d '{"leafPem":"-----BEGIN CERTIFICATE-----...","poolPem":"<intermediate+root PEM>"}'
# complete, missingIssuers (eksik ara sertifikanın adı), paths (cross-signed ise birden çok), aiaUrls
```

Eksik intermediate varsa deployment için chain üretimi hata verir — bozuk chain sahaya çıkmaz.

## 18. Discovery ve monitoring derinliği (F14) — yeni

**Sertifika alanları** (§6.2): **Certificates → sertifika → Overview → Versions** altında artık
Key Usage, Extended Key Usage, Basic Constraints (CA / end-entity, path length), OCSP, AIA
caIssuers ve CRL dağıtım noktaları görünür. Denemek için bu alanları taşıyan bir sertifika üretip
yükleyin:

```bash
openssl req -x509 -newkey rsa:2048 -keyout f.key -out f.crt -days 120 -nodes \
  -subj "/CN=fields.company.com" \
  -addext "keyUsage=digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth,clientAuth" \
  -addext "authorityInfoAccess=OCSP;URI:http://ocsp.example/,caIssuers;URI:http://ca.example/i.crt" \
  -addext "crlDistributionPoints=URI:http://crl.example/list.crl"
# Certificates ekranındaki upload ile veya POST /api/v1/artifacts/upload ile yükleyin
```

**Cipher bilgisi**: Monitors ekranında her vantage hücresinde TLS sürümünün yanında görüşülen
cipher suite yazar (ör. `Tls13 · TLS_AES_256_GCM_SHA384`). İç vantage için runner raporlar.

**Probe policy** (§5.2): **Monitors → Edit** satırında interval'in yanında **timeout (s)** ve
**retries** alanları vardır. Retry yalnızca geçici hatalarda (timeout / bağlantı reddi) çalışır;
DNS hatası veya handshake sonucu cevabın kendisidir, tekrar edilmez.

**Uygulama health-check** (§2.1): aynı satırda **Health check URL** ve **expect** (beklenen HTTP
kodu; boş bırakılırsa 2xx/3xx yeterli). Sonuç Monitors tablosunda **App health** sütununda
görünür ve TLS gözlemini etkilemez — 500 dönen bir uygulama, sertifika gözlemini bozmaz.
Başarısızlıkta `monitor.health-check-failed` bildirimi üretilir.

```bash
curl -s -X POST http://localhost:5200/api/v1/monitors -H 'Content-Type: application/json' \
  -d '{"host":"app.company.com","port":443,"timeoutSeconds":5,"retryCount":1,
       "healthCheckUrl":"https://app.company.com/health","healthCheckExpectedStatus":200}'
```

## 19. Kimlik, yetki ve güvenlik (F15) — yeni

**OIDC SSO** (§4.3): `appsettings.json`'da

```json
{ "Auth": {
    "Enabled": true,
    "JwtSecret": "…",
    "Oidc": {
      "Authority": "https://login.microsoftonline.com/<tenant>/v2.0",
      "Audience": "api://remotessl",
      "RoleClaim": "roles",
      "RequireMfa": true
    } } }
```

Kullanıcıyı IdP'ye bağlamak: **Settings → Users → SSO** düğmesiyle hesabın `sub` değerini girin.
Roller ve scope'lar yerel hesaptan okunur — kimlik doğrulama federe, yetkilendirme RemoteSSL'de.
`RequireMfa` açıkken IdP'nin token'ında MFA iddiası (amr/acr) yoksa istek reddedilir.

**Scope (ABAC) kuralları** (§24.2): **Settings → Users → Scopes**.

```json
[{"action":"certificate.deploy","environment":"PROD","targetGroup":"WEB","adapters":["nginx"]}]
```

Boş liste = "roller karar verir". Kural varken kapsam dışı bir deployment 403 döner ve audit'e
`authorization.denied` düşer. Target grubu **Managed Targets → Edit → Group** alanından verilir.

**Runner mTLS kimliği** (§8.2): runner ilk kayıtta kendi anahtarını üretip CSR gönderir, control
plane iç CA ile clientAuth sertifikası imzalar. **Runners** ekranında **Identity** sütunu
`client certificate` gösterir. Zorunlu kılmak için `Runner:RequireMutualTls=true` (HTTPS gerekir).
Kimliği iptal etmek: `POST /api/v1/runners/{id}/revoke-identity` — API key geçerli olsa bile
runner artık iş alamaz. CA sertifikası: `GET /api/v1/runners/ca-certificate`.

**Adapter allowlist / sürüm sabitleme** (§30.2):

```json
{ "Security": { "Adapters": {
    "Allowed": ["nginx", "iis"],
    "PinnedVersions": { "nginx": "1.0.0" } } } }
```

Listede olmayan adapter'a deployment açılamaz (422, sebebiyle birlikte); sabitlenen sürüm
runner'ın bildirdiğiyle uyuşmazsa iş kuyruğa girmez.

**Rate limit ve güvenlik başlıkları** (§30.2): varsayılan çağıran başına dakikada 300 istek
(runner trafiği için 1200; `/health` ve `/metrics` muaf). Aşımda 429 + `Retry-After`.

```json
{ "Security": { "RateLimit": { "PermitsPerMinute": 300, "RunnerPermitsPerMinute": 1200 } } }
```

**Güvenlik CI hattı** (§30.3): `.github/workflows/security.yml` — NuGet/npm zafiyet taraması,
gitleaks, CodeQL, CycloneDX SBOM ve Trivy. Her push/PR'da ve haftalık çalışır.

## 20. Secret sağlayıcıları, rotation ve anahtar koruması (F16)

**Credential tipleri** (§7.2). **Credentials** ekranında tip + sağlayıcı seçilir; form seçilen
tipin gerektirdiği alanları gösterir. Desteklenen tipler: `UsernamePassword`, `SshPrivateKey`,
`SshCertificate`, `KerberosServiceAccount`, `ApiKeySecret`, `OAuthClientCredentials`,
`BearerToken`, `ClientCertificate`, `ExternalSecretReference`. Eksik alanla kayıt 400 döner —
örneğin OAuth için client id + client secret + token endpoint üçü de zorunludur.

**Dış sağlayıcılar.** `InternalVault` dışında bir sağlayıcı seçildiğinde secret burada tutulmaz,
yalnızca identifier saklanır:

| Sağlayıcı | Identifier | Ayarlar |
|-----------|-----------|---------|
| HashiCorpVault | `vault://<mount>/<path>` | `Vault:Addr`, `Vault:Token` |
| CyberArk (CCP) | `cyberark://<safe>/<object>` | `CyberArk:BaseUrl`, `CyberArk:AppId` |
| AzureKeyVault | `azurekv://<vault>/<secret>` | `AzureKeyVault:TenantId`, `ClientId`, `ClientSecret` |

Ayarı olmayan bir sağlayıcı çağrıldığında iş sessizce devam etmez; 422 ile "not configured" döner.

**Rotation ve erişim audit'i** (§7.3). Credential'a gün cinsinden rotation aralığı verilir; süre
dolunca satır **overdue** görünür, `credential.rotation_due` audit kaydı ve bildirimi üretilir
(kimse bloklanmaz). **Rotate** düğmesi yeni materyali alır ve saati sıfırlar; dış sağlayıcılarda
secret provider'da döndürülür, buradaki onay yalnızca saati sıfırlar. Her okuma
`credential.access` olarak audit'e düşer ve **Last access** sütununda görünür — audit detayında
secret değeri asla yer almaz.

**Runner-direct secret** (§7.3, ADR-003). Control plane'de `Secrets:RunnerDirect=true` yapılırsa,
dış sağlayıcıdaki credential'lar runner'a değer olarak değil **referans** olarak verilir; runner
kendi `Vault:*` / `CyberArk:*` / `AzureKeyVault:*` ayarlarıyla secret'ı doğrudan çeker. Runner'da
o sağlayıcı yapılandırılmamışsa iş açık bir hata ile durur. `InternalVault` credential'ları bu
modda da control plane'de çözülür.

**Anahtar yönetimi** (§16.3). Yeni **Keys** ekranı: sağlayıcı (Software / Pkcs11 / CloudKms),
algoritma, sahip (owner/team), environment, purpose ve **export policy**.

```bash
curl -s localhost:5200/api/v1/keys/providers
# [{"provider":"Software","enabled":true},{"provider":"Pkcs11","enabled":false},...]
```

- **CSR**: satırdaki **CSR** düğmesi subject + SAN alır ve anahtarla imzalanmış PKCS#10 üretir.
  PKCS#11 / cloud HSM anahtarlarında imza token'ın kendisinde atılır, özel anahtar hiç dışarı çıkmaz.
- **Export policy**: non-exportable oluşturulan anahtarın private half'i hiçbir yoldan verilmez —
  deneme 403 döner ve `key.export` / `DENIED` olarak audit'e yazılır. Token ve cloud anahtarları
  tanım gereği exportable oluşturulamaz.
- **HSM ayarları**: `Hsm:Pkcs11:LibraryPath`, `Hsm:Pkcs11:TokenLabel`, `Hsm:Pkcs11:Pin`.
  Cloud HSM için `AzureKeyVault:*` + `AzureKeyVault:KeyVaultName` (`azurekms://<vault>/<key>`).
  Yapılandırılmamış sağlayıcı UI'da seçilemez.

**Windows private key koruması** (§11.4). Windows deployment'ı PFX'i varsayılan olarak
**non-exportable** import eder. Servis kimliğine okuma yetkisi vermek için store'un service
binding JSON'una eklenir:

```json
{ "iisSiteName": "Default Web Site", "privateKeyReadAccounts": ["IIS AppPool\\Default Web Site"] }
```

Anahtarın dışa aktarılabilir olması gerekiyorsa `"exportablePrivateKey": true` eklenir. Job
adımlarında `PrivateKeyAcl` adımı yetkinin verildiğini gösterir.

## 21. Event modeli, outbox ve entegrasyonlar (F17)

**Outbox** (§28.2). Bildirim artık anlık gönderim değil: `Notify` çağrısı, onu doğuran değişikliğin
transaction'ına bir satır yazar. Olay ancak commit ile var olur; teslim ayrı bir arka plan
servisinde (leader-elected) yapılır.

```bash
curl -s "localhost:5200/api/v1/events?take=10"          # son olaylar
curl -s "localhost:5200/api/v1/events?status=Failed"    # teslim edilemeyenler
curl -s localhost:5200/api/v1/events/channels           # kanal listesi + yapılandırılmış mı
curl -s localhost:5200/api/v1/events/delivery-health    # 24 saatlik hata özeti
```

Bir kanal teslim aldığında satıra işlenir; sonraki deneme yalnızca başarısız kanalları tekrar
dener. Backoff 30s → 1m → 2m → 4m → 8m; 6 deneme sonunda olay `Failed` olur.
**Settings → Event delivery** panelinde kanal durumu, teslim edilemeyen olaylar ve **Requeue**
düğmesi vardır.

**Domain event seti** (§28.1). Yayımlanan olaylar: `certificate.discovered`,
`certificate.expiring`, `certificate.revoked`, `certificate.renewal-due`, `deployment.requested`,
`deployment.approved`, `deployment.awaiting-continue`, `deployment.completed`,
`deployment.failed`, `deployment.rollback-started`, `monitor.health-check-failed`,
`vantage.mismatch`, `drift.detected`, `runner.offline`, `credential.rotation_due`,
`notification.delivery-failed`. Zarf şekli her kanalda aynıdır:

```json
{ "id": "...", "event": "deployment.failed", "schemaVersion": 1,
  "timestamp": "2026-05-04T10:30:00Z", "correlationId": "...", "data": { } }
```

RabbitMQ'da olay adı routing key'dir (`remotessl.events` topic exchange), yani tüketici
`deployment.*` gibi bağlanabilir.

**SIEM / Syslog** (§33, §25.3):

```json
{ "Integrations": { "Syslog": {
    "Host": "siem.local", "Port": 514, "Protocol": "udp",
    "Facility": 16, "Format": "rfc5424", "Hostname": "clm01" } } }
```

`Format: "cef"` ArcSight CEF üretir, `Protocol: "tcp"` RFC 6587 octet-counting kullanır.
Audit kayıtlarının da SIEM'e gitmesi için `Integrations:ForwardAuditToSiem=true` — her audit
satırı `audit.<action>` olayı olarak aynı transaction'da outbox'a yazılır. Chat/mail kanalları
bu aynaları almaz, yalnız SIEM ve mesaj kuyruğu alır.

Yerel deneme (UDP dinleyici):

```bash
python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('127.0.0.1',5514))
while True: print(s.recvfrom(65535)[0].decode())"
```

Splunk HEC için: `Integrations:Splunk:{Url,Token,Index,SourceType}`.

**ServiceNow** (§33). Yalnız değişiklik sayılan olaylar (`deployment.requested/approved/completed/
failed`, `deployment.rollback-started`, `certificate.revoked`) kayıt açar:

```json
{ "Integrations": { "ServiceNow": {
    "BaseUrl": "https://acme.service-now.com", "Username": "svc_remotessl",
    "Password": "…", "Table": "change_request", "AssignmentGroup": "Platform" } } }
```

**PagerDuty / Opsgenie** (§33). Yalnız incident seviyesindeki olaylar sayfa açar
(`deployment.failed`, `deployment.rollback-started`, `certificate.issuance-failed`,
`certificate.expired`, `drift.detected`, `runner.offline`, `notification.delivery-failed`):

```json
{ "Integrations": {
    "PagerDuty": { "RoutingKey": "…" },
    "Opsgenie": { "ApiKey": "…", "Team": "platform" } } }
```

Dedup key / alias correlation id'den üretilir, böylece tekrar eden hatalar tek incident'ta toplanır.

**Bildirim hatası alarmı** (§33). Bir kanal teslim edemezse lifecycle etkilenmez; bunun yerine
dashboard'da `NotificationDeliveryFailure` alarmı çıkar (`UndeliveredEvents > 0` ise critical),
`notification.delivery-failed` olayı üretilir ve audit'e yazılır. Bu olay kendi hatası için
tekrar olay üretmez — döngü oluşmaz.

## 22. Audit bütünlüğü, WORM ve arama (F18)

**Hash zinciri** (§25.3, ADR-007). Her audit satırı, kendi içeriği + bir önceki satırın hash'i
üzerinden SHA-256 ile mühürlenir. Mühürleme insert anında değil, arka plan geçişinde yapılır
(varsayılan 30 saniye, `Audit:SealIntervalSeconds`).

```bash
curl -s localhost:5200/api/v1/audit/integrity
# {"intact":true,"sealed":156,"unsealed":0,"headHash":"A8C6…","archived":0}
```

**Audit** ekranının üstünde aynı bilgi görünür: `Chain: intact · 156 sealed`. Zincir kırılırsa
kırılmanın ilk noktası (sequence + sebep) yazılır, `audit.chain-broken` olayı üretilir ve
dashboard'da alarm çıkar.

**DB seviyesinde append-only.** Migration bir Postgres trigger'ı kurar. Denemek için:

```bash
docker exec remotessl-postgres-1 psql -U remotessl -d remotessl \
  -c 'UPDATE "AuditEvents" SET "Result"=$$X$$ WHERE "Sequence"=5;'
# ERROR:  AuditEvents is append-only; audited content cannot be modified

docker exec remotessl-postgres-1 psql -U remotessl -d remotessl \
  -c 'DELETE FROM "AuditEvents" WHERE "Sequence"=5;'
# ERROR:  AuditEvents is append-only; rows are removed only by the retention job
```

Mühürlenmiş bir satırın `Hash`'i de değiştirilemez. Retention işi ise kendi transaction'ında
`SET LOCAL remotessl.audit_retention = 'on'` diyerek silme iznini alır — başka hiçbir yol silemez.

**Dış kopya / WORM** (§25.3). Object store yapılandırılmışsa mühürlenmiş satırlar JSON Lines
olarak dışarı yazılır (`audit/YYYY/MM/DD/<from>-<to>.jsonl`) ve satırlar `ArchivedAt` ile
işaretlenir. Bucket'ta object lock için:

```json
{ "Storage": { "S3": { "BucketName": "remotessl", "ObjectLockDays": 2555 } } }
```

Bucket'ın kendisinde object lock açık olmalıdır. Object store yoksa SIEM forward (bkz. §21)
tek dış kopyadır.

**Retention** (§25.3):

```json
{ "Audit": { "RetentionDays": 2555, "SealIntervalSeconds": 30, "VerifyIntervalHours": 6 } }
```

`RetentionDays` verilmezse hiçbir şey silinmez. Silme yalnız **arşivlenmiş** ve **bitişik en eski
prefix** için yapılır — ortadan satır silmek zinciri kıracağı için reddedilir. Silme işlemi
`audit.purge` olarak audit'lenir.

**Yeni audit alanları** (§25.1). Her satır artık `SessionId`, `SourceIp`, `UserAgent` taşır
(request middleware'inden), ayrıca gerektiğinde `ApprovalReference`, `OldFingerprint`,
`NewFingerprint`. Hepsi hash'e dahildir; yani bunları sonradan değiştirmek de zinciri kırar.

**Arama ekranı** (§43). **Audit** ekranında actor, action, object type, object id, result ve
tarih aralığı filtreleri, sayfalama ve satıra tıklayınca tam bağlam (session, IP, user agent,
approval, fingerprint öncesi/sonrası, zincir durumu) vardır.

```bash
curl -s "localhost:5200/api/v1/audit?actor=ozgur&action=certificate.revoke&from=2026-01-01T00:00:00Z"
curl -s localhost:5200/api/v1/audit/facets   # formdaki açılır listeler
```

## 23. Adapter derinliği ve capability-driven UI (F19)

**Adapter kataloğu** (§9.3). Her adapter'ın ne yapabildiği tek bir yerde tanımlı; UI hem adapter
listesini hem alanları hem de hangi aksiyonun sunulacağını buradan okur.

```bash
curl -s localhost:5200/api/v1/adapters | jq '.[] | {type, channel, supportsRollback, requiresCommit}'
curl -s localhost:5200/api/v1/adapters/paloalto
```

**Managed Targets** ekranında adapter seçilince altında bir satır çıkar: kanal (ssh/winrm/rest),
private key gerekiyor mu, rollback var mı, commit gerekiyor mu. Adapter yeteneği yoksa aksiyon
gösterilmez — Cisco ISE sertifikayı yerinde değiştirdiği için rollback ne UI'da sunulur ne de
sunucuda kabul edilir (deneme, hangi target'ın neden geri alınamadığını söyleyen bir hata döner).

**Windows CCS** (§11.4). Yeni `windows-ccs` adapter'ı sertifikayı makine store'una değil, IIS'in
host adına göre okuduğu UNC paylaşımına yazar:

```json
{ "ccsPath": "\\\\fileserver\\certs", "ccsFileName": "app.example.com", "enableCcs": true }
```

Önceki dosya `.<timestamp>.bak` olarak yedeklenir; herhangi bir adım başarısız olursa geri konur.

**RDP / WinRM binding'leri** (§11.4). IIS veya windows-cert-store store'unun service binding
JSON'una eklenir:

```json
{ "iisSiteName": "Default Web Site", "bindingTargets": ["rdp", "winrm"] }
```

RDP için thumbprint `Win32_TSGeneralSetting` üzerinden yazılır, WinRM için HTTPS listener'ı yeni
thumbprint'le yeniden oluşturulur. Job adımlarında `Activate:rdp` / `Activate:winrm` görünür.

**Network cihaz context'i** (§14.3). Target'ın connection config'inde:

| Cihaz | Alan | Örnek |
|-------|------|-------|
| FortiGate | `vdom` | `"vdom": "root"` |
| Palo Alto | `vsys` | `"vsys": "vsys1"` |
| Citrix ADC | `partition` | `"partition": "prod"` |
| F5 BIG-IP | `partition` | `"partition": "Common"` |

PAN-OS'ta SSL/TLS service profile binding'i `bindingRef` ile yapılır ve ardından **commit** çalışır;
Citrix'te binding sonrası **config save** yapılır. İkisi de varsayılan açıktır; kapatmak için
connection config'e `"skipCommit": true` eklenir (değişiklik canlı olur ama reboot'ta kaybolur).

**Generic SSH şablonu** (§14.2). Adapter'ı olmayan bir cihaz için, komutları operatörün yazdığı
kontrollü şablon:

```json
{
  "certPath": "/opt/app/tls/server.crt",
  "keyPath": "/opt/app/tls/server.key",
  "installCmd": "/opt/app/bin/import-cert {certPath} {keyPath}",
  "validateCmd": "/opt/app/bin/check-config",
  "reloadCmd": "systemctl reload app",
  "verifyCmd": "/opt/app/bin/show-cert | grep -q {thumbprint}",
  "rollbackCmd": "/opt/app/bin/import-cert {backupPath} && systemctl reload app"
}
```

Placeholder seti sabittir: `{certPath} {keyPath} {chainPath} {backupPath} {thumbprint} {host}`.
Tanınmayan bir `{...}` olduğu gibi bırakılır. Komutlar yalnızca bu yapılandırmadan gelir; sertifika
alanları veya target adı komut üretmez. Boru hattı diğer adapter'larla aynı: pre-check → backup →
upload → install → validate → reload → verify, hata olursa yedekten geri dönüş.

**Java alias envanteri** (§12.3). Deployment tek bir alias'a dokunur; store'da başka ne olduğunu
görmek için **Managed Targets → Inventory**:

```bash
curl -s -X POST localhost:5200/api/v1/targets/<targetId>/stores/<storeId>/inventory
curl -s localhost:5200/api/v1/targets/jobs/<jobId>
```

Sonuç her alias için entry type, subject/issuer, serial, SHA-256 parmak izi ve son kullanma
tarihini içerir. Salt okunur — store'a hiçbir şey yazılmaz.

## 24. CA connector'ları, webhook ve domain validation (F20)

**Desteklenen connector tipleri.** **CA Integrations** ekranında tip seçilir; her tipin kendi
yapılandırma JSON'u vardır (şifreli saklanır).

| Tip | Ne | Zorunlu ayarlar |
|-----|-----|-----------------|
| `manual` | Offline CA — CSR üret, imzalıyı elle yükle | — |
| `globalsign-hvca` | GlobalSign Atlas | `baseUrl`, `apiKey`, `apiSecret`, `clientPfxBase64` |
| `acme` | Let's Encrypt / kurumsal ACME | `directoryUrl`, `contact`, `challengeType` |
| `adcs` | Microsoft AD CS (certsrv) | `baseUrl`, `username`, `password`, `templates` |
| `digicert` | DigiCert CertCentral | `apiKey`, `organizationId` |
| `sectigo` | Sectigo Certificate Manager | `baseUrl`, `apiKey`, `profiles` |
| `rest-ca` | Kurum içi REST CA | `baseUrl`, `apiKey` + endpoint yolları |

**ACME** (§18.3). Yapılandırma:

```json
{ "directoryUrl": "https://acme-v02.api.letsencrypt.org/directory",
  "contact": "pki@acme.com", "challengeType": "dns-01",
  "eabKeyId": "...", "eabHmacKeyBase64Url": "..." }
```

Hesap anahtarı ilk kullanımda üretilir ve connector yapılandırmasında saklanır — **kaybedilirse
hesap ve kazanılmış tüm yetkilendirmeler kaybolur**. `dns-01` wildcard verebilir, `http-01` veremez;
profil listesi bu ikisini gösterir. ACME'de yenileme diye bir uç yoktur, aynı isimler için yeni
sipariş açılır.

**Domain validation** (§18.1). Sipariş açıldıktan sonra **Certificate Requests** ekranında ilgili
satırda **Domain validation** düğmesi çıkar. Panel her isim için:

- yayımlanacak DNS TXT kaydını (`_acme-challenge.<host> IN TXT "..."`), veya
- sunulacak HTTP yolunu ve gövdesini

gösterir. Yayımladıktan sonra **I have published it — verify** denir; CA asenkron doğrular, durum
kendiliğinden `Valid`'e geçer.

```bash
curl -s localhost:5200/api/v1/requests/<requestId>/validations
curl -s -X POST localhost:5200/api/v1/requests/<requestId>/validations/<id>/submit
```

**AD CS** (§18.3). certsrv web enrollment üzerinden:

```json
{ "baseUrl": "https://ca01.corp", "username": "CORP\\svc_pki", "password": "…",
  "authScheme": "ntlm", "templates": ["WebServer", "WebServerV2"] }
```

Template'ler profil olarak listelenir (certsrv bunları API ile vermez). Manager onayı gerektiren
bir template'te istek `ValidationRequired` olarak görünür ve onaylanınca kendiliğinden toplanır.
Revocation certsrv'de yoktur; CA üzerinde `certutil -revoke` ile yapılır.

**Webhook + polling hibriti** (ADR-009). Connector başına paylaşılan sır:

```json
{ "Ca": { "Webhook": { "Secret": "…",
    "<connectorGuid>": { "Secret": "connector'a özel sır" } } } }
```

CA'nın çağıracağı adres: `POST /api/v1/ca/webhook/{connectorId}`. Kimlik doğrulama iki şekilde:

```bash
# HMAC-SHA256 (tercih edilen)
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET" -hex | sed 's/.*= //')
curl -X POST localhost:5200/api/v1/ca/webhook/$CID -H "X-RemoteSSL-Signature: $SIG" -d "$BODY"

# İmzalayamayan CA'lar için düz token
curl -X POST localhost:5200/api/v1/ca/webhook/$CID -H "X-RemoteSSL-Token: $SECRET" -d "$BODY"
```

Yanlış imza → 401 ve audit'e `ca.webhook.rejected / DENIED`. **Callback gövdesinden hiçbir issuance
bilgisi alınmaz**: sadece hangi isteğin etkilendiği okunur, durum daima CA'dan sorulur. Callback
hiç gelmezse zamanlanmış polling zaten toplar.

## 25. Multi-tenant, runner failover ve ölçek (F21)

**Tenant izolasyonu** (§35, ADR-008). Yükseltme sonrası mevcut her satır **Default** tenant'a
taşınır; tek tenant'lı kurulum hiçbir şey yapmadan çalışmaya devam eder.

```bash
curl -s localhost:5200/api/v1/tenants          # tenant listesi + kayıt sayıları
curl -s localhost:5200/api/v1/tenants/current  # bu kullanıcının tenant'ı
curl -s -X POST localhost:5200/api/v1/tenants -H 'Content-Type: application/json' \
  -d '{"name":"Acme Corp","slug":"acme"}'
```

Tenant **yalnızca kimlikten** çözülür: token'daki `tenant` claim'i, yoksa kullanıcı kaydındaki
tenant. Header veya query parametresiyle tenant değiştirilemez. İçi dolu bir tenant silinemez
(409), default tenant hiç silinemez.

Doğrulama: iki tenant'ta birer sertifika oluşturup her kullanıcıyla listeleyin — her biri yalnız
kendi satırını görür. Doğrudan id ile de diğerine erişilemez (404).

Arka plan işleri (probe, outbox, audit mühürleme, rotation, failover) **cross-tenant** çalışır;
aksi halde bir tenant'ın monitor'larını görüp diğerininkini atlarlardı.

**Runner failover** (§34.2). Runner yapılandırması:

```json
{ "Runner": { "AffinityGroup": "dc1", "Segment": "dc1" } }
```

Control plane tarafı:

```json
{ "Runner": { "JobLeaseSeconds": 300, "FailoverIntervalSeconds": 30, "MaxJobAttempts": 3 } }
```

Nasıl çalışır: runner işi aldığında lease konur, heartbeat lease'i yeniler. Runner susarsa lease
dolar ve iş **aynı affinity group'taki** başka bir runner'a geçer (`runner.job-reassigned`).

Denemek için: bir deployment başlatın ve runner'ı `PreCheck` ile `Install` arasında durdurun —
runner `jobs/{id}/started` dediği için iş `NonReassignable` olur ve devredilmez; bunun yerine
açık sebeple **Failed** olur ve `runner.job-abandoned` (incident seviyesi) olayı üretilir. Bu
kasıtlıdır: hedefte yedek ve yarım uygulanmış bir değişiklik olabileceği için işi başka bir
runner'da tekrarlamak değişikliği iki kez uygulayabilir.

Read-only işler (probe, discover, test-connection, generate-csr, java-inventory) `started`
demediği için her zaman devredilebilir.

**Ölçek** (NFR-004):

```json
{ "Monitoring": { "MaxProbesPerTick": 500, "MaxParallelProbes": 8, "SchedulerTickSeconds": 60 } }
```

Zamanlayıcı tick başına sınırlı bir yığın alır ve **en uzun bekleyenden** başlar; yığına sığmayan
bir sonraki tick'in başına geçer, hiçbir monitor aç kalmaz. Yığın dolduğunda log'a bir satır düşer.
Endpoint sayısına göre önerilen değerler `docs/HA-DR-RUNBOOK.md` §6'da.

**HA / felaket kurtarma**: `docs/HA-DR-RUNBOOK.md` — leader election doğrulaması, PITR adımları,
geri dönüş sonrası `GET /api/v1/audit/integrity` kontrolü, S3 versioning/object-lock ve üç aylık
tatbikat listesi.

## 26. Test paketini çalıştırmak: lab ve ölçek (F22)

Test paketi varsayılan olarak **hermetiktir** — hiçbir dış bağımlılık istemez:

```bash
dotnet test RemoteSSL.sln
# Passed: 335
```

Lab ve ölçek testleri ortam değişkeni verilmediğinde kendilerini atlar. Açmak için:

**Gerçek SSH hedefine karşı entegrasyon + failure injection (§36.2):**

```bash
./tests/lab/start-lab.sh          # sshd container'ını başlatır ve export satırlarını yazdırır
export REMOTESSL_LAB_SSH=127.0.0.1:2222
export REMOTESSL_LAB_USER=remotessl
export REMOTESSL_LAB_PASSWORD=labpassword

dotnet test RemoteSSL.sln --filter "FullyQualifiedName~LinuxDeployerLabTests"
./tests/lab/stop-lab.sh
```

Bu testler gerçek SSH açar, gerçek dosya yazar ve gerçek komut çalıştırır: sertifika kurulumu,
private key izninin 600 olması, config testi/reload hatasında rollback, izin verilmeyen dizinde
geriye hiçbir şey bırakmadan reddetme, erişilemeyen host'ta PreCheck'te durma.

**10.000 endpoint ölçek testi (NFR-004):**

```bash
docker exec remotessl-postgres-1 psql -U remotessl -d postgres -c 'CREATE DATABASE remotessl_perf;'
export REMOTESSL_PERF_DB="Host=localhost;Port=5432;Database=remotessl_perf;Username=remotessl;Password=remotessl_dev"

dotnet test RemoteSSL.sln --filter "FullyQualifiedName~ScaleTests" --logger "console;verbosity=detailed"
```

Beklenen çıktı: `due batch of 500 selected from 10000 endpoints in 8 ms`, `EXPLAIN` planında
`Index Scan` (ne `Seq Scan` ne `Sort`), `4000 distinct endpoints probed across 8 ticks`.

> Test kendi veritabanını sıfırlayıp migrate ettiği için **uygulama veritabanını vermeyin**;
> ayrı bir `remotessl_perf` kullanın.

## Bilinen sınırlar

- **GlobalSign HVCA connector canlı hesapla doğrulanacak** (tek bilinçli eksik; docs/ca-connector.md).
- Runner transport'u API key + kısa ömürlü HMAC-imzalı job context kullanır (ADR-002 pull modeli); tam mTLS production'da LB/ingress katmanında sonlandırılmalıdır.
- Job dağıtımı DB-claim ile (at-least-once, idempotent); domain olayları RabbitMQ'ya yayınlanır. Windows/Java/Oracle/network adapterları gerçek hedef gerektirir.
- Scheduler'lar Postgres advisory lock ile leader-elected; çok node'lu API güvenlidir.
- **Integration lab yalnızca SSH hedefi barındırır**: bu ortamın proxy'si alpine paket depolarına
  HTTP 403 döndüğü için container içine nginx/Apache/HAProxy kurulamadı. Taşıma katmanı ve
  deployment boru hattı gerçek, servis reload adımı gerçek `nginx -t` yerine gerçek bir komutla
  temsil ediliyor.
