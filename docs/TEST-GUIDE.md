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

## 2. Faz 1 — SSL Monitoring & Inventory

1. UI → **Monitors** → `google.com` port `443` ekleyin → **Probe now**.
2. Beklenen: Success, TLS protokolü, gözlenen sertifika CN'i, kalan gün, chain durumu.
3. Aynı sertifikayı kullanan ikinci bir endpoint ekleyin (ör. `www.google.com`) → **Certificates** ekranında tek envanter kaydı, iki monitor bağı.
4. Sertifika detayında version, SAN, thumbprint ve monitor listesi görünmeli.
5. **Audit** ekranında `certificate.expiring` eşik olayları (T-90/T-60…) görünür.

## 3. Faz 2+3 — Managed Target & Linux (Nginx) Deployment

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

## 4. Faz 5 — Certificate Factory

Swagger üzerinden:
- `POST /api/v1/artifacts/csr` — RSA 2048/4096, EC P-256/P-384 CSR + key
- `POST /api/v1/artifacts/pfx` / `pfx/parse` — PEM↔PFX dönüşümü
- `POST /api/v1/artifacts/chain` — leaf + karışık intermediate havuzundan sıralı chain (root hariç)

## 5. Faz 7 — CA Connector (Manual + GlobalSign)

Manual akış (GlobalSign hesabı gelene kadar):
1. UI → **Certificate Requests** → CN girin, CA olarak `Manual CA` seçin (yoksa Swagger `POST /api/v1/ca-connectors` `{"name":"Manual CA","connectorType":"manual"}`).
2. CSR üretilir, state `WaitingForCertificate` olur. CSR'ı kendi CA'nızla imzalayın.
3. **Upload issued cert** ile imzalı sertifikayı yükleyin → state `Issued`, envantere private key'li version düşer → deploy edilebilir.

GlobalSign geldiğinde: `POST /api/v1/ca-connectors` `{"name":"GlobalSign","connectorType":"globalsign-hvca","config":{"baseUrl":"...","apiKey":"...","apiSecret":"...","clientPfxBase64":"...","clientPfxPassword":"..."}}` → `POST /api/v1/ca-connectors/{id}/test`.

## 6. Faz 8 — Otomasyon (renewal + approval + drift)

1. Swagger → `POST /api/v1/policies` `{ "name":"prod-30", "triggerDays":30, "autoDeploy":true, "approvalRequired":true, "caConnectorId":"<manual-ca-id>" }`
2. `POST /api/v1/policies/{id}/assign` `{ "certificateId": "<30 günden az kalmış cert>" }`
3. ~1 dk içinde otomasyon renewal request üretir (**Certificate Requests**'te `automation` tarafından).
4. Manual CA ise imzalayıp yükleyin → binding'i varsa otomatik deployment job'ı oluşur → **Approvals** ekranında onaylayın (requester ≠ approver kuralı zorunlu) → maintenance window açıksa otomatik execute edilir.
5. Drift: hedefteki sertifikayı elle eski haline döndürün; monitor probe + otomasyon `drift.detected` audit olayı üretir.
6. Bildirimler: `appsettings.json` → `Notifications:WebhookUrl` / `TeamsWebhookUrl` / `Smtp:*` doldurun; expiring/deployment/drift olayları bu kanallara ve RabbitMQ `remotessl.events` exchange'ine düşer (RabbitMQ UI: http://localhost:15672, remotessl/remotessl_dev).

## 7. Faz 10 — Auth, RBAC ve kullanıcılar

`src/RemoteSSL.Api/appsettings.json` → `"Auth": { "Enabled": true }` yapıp API'yi yeniden başlatın.
- UI otomatik olarak `/login` sayfasına yönlendirir; `admin` / `admin` ile girin.
- **Settings** ekranından yeni kullanıcılar oluşturun (rol seçerek). Rol → yetki eşlemesi:
  Viewer (okuma), CertificateOperator (request/factory), DeploymentOperator (target/deployment),
  CertificateApprover (onay), PlatformAdministrator (credential/CA/policy/user).
- Yanlış roldeki kullanıcıyla yazma endpoint'i çağırın → 403 beklenir.
- Auth kapalıyken tüm ekranlar login'siz çalışır (dev modu).

## 8. UI üzerinden deployment (yeni)

**Certificates** ekranında bir sertifikaya tıklayın → **Deploy** bölümü: version + binding seçin,
istenirse "require approval" işaretleyin → **Deploy**. Onaysızsa job anında koşar; onaylıysa Approvals ekranına düşer.

## 9. On-target key generation (yeni)

Private key'in hedeften hiç çıkmadığı model (tasarım §16.1):
```
POST /api/v1/certificates/requests
{ "commonName":"ontarget.local", "keyOrigin":"target",
  "targetId":"<lab-nginx-target-id>", "targetKeyPath":"/etc/nginx/ssl/ontarget.key",
  "caConnectorId":"<manual-ca-id>" }
```
Runner hedefte `openssl` ile 0600 izinli key + CSR üretir; CSR kontrol düzlemine döner, state `CsrGenerated`/`WaitingForCertificate` olur. İmzalayıp yükleyince deploy sırasında key gönderilmez (hedefte zaten var).

## 10. HashiCorp Vault (opsiyonel)

`appsettings.json` → `"Vault": { "Addr": "http://localhost:8200", "Token": "..." }`.
Credential oluştururken provider `HashiCorpVault`, secretIdentifier `vault://secret/prod/web01`
(KV v2; data içinde `password` ve/veya `privateKey` alanları). Runner, secret'i broker üzerinden execution anında alır.

## 11. İç DNS endpoint'leri ve katmanlı (F5 → nginx → IIS) analiz — yeni

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

## 12. Windows / IIS, Java, Oracle, F5, diğer vendorlar (kod hazır, lab gerekli)

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

## Bilinen sınırlar

- **GlobalSign HVCA connector canlı hesapla doğrulanacak** (tek bilinçli eksik; docs/ca-connector.md).
- Runner transport'u API key + kısa ömürlü HMAC-imzalı job context kullanır (ADR-002 pull modeli); tam mTLS production'da LB/ingress katmanında sonlandırılmalıdır.
- Job dağıtımı DB-claim ile (at-least-once, idempotent); domain olayları RabbitMQ'ya yayınlanır. Windows/Java/Oracle/network adapterları gerçek hedef gerektirir.
- Scheduler'lar Postgres advisory lock ile leader-elected; çok node'lu API güvenlidir.
