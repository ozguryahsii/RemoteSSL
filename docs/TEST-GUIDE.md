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

## 7. Faz 10 — Auth (opsiyonel)

`src/RemoteSSL.Api/appsettings.json` → `"Auth": { "Enabled": true, ... }` yapıp API'yi yeniden başlatın.
`POST /api/v1/auth/login` `{"username":"admin","password":"admin"}` → JWT. Artık tüm endpoint'ler (runner + health hariç) `Authorization: Bearer <token>` ister. UI login akışı henüz yok — API üzerinden test edin.

## 8. Windows / IIS, Java, Oracle, F5 (kod hazır, lab gerekli)

Bu adapterlar implemente edildi ancak bu ortamda gerçek hedef olmadığı için canlı test edilmedi:

- **Windows/IIS**: Hedefte Windows OpenSSH + PowerShell gerekir. Target adapter `windows-cert-store` veya `iis`, store `LocalMachine\My`, binding'e `iisSiteName`/`iisPort` verin. PFX kontrol düzleminde üretilir, parola dosya ile taşınır, binding rollback'i eski thumbprint'e döner.
- **Java keystore**: adapter `java-keystore`/`java-truststore`, store path JKS yolu, alias verin; parola credential'dan gelir, `storepass:env` ile komut satırına sızmaz.
- **Oracle Wallet**: adapter `oracle-wallet`, store path wallet dizini; `ewallet.p12`+`cwallet.sso` birlikte yedeklenip birlikte döner.
- **F5 BIG-IP**: adapter `f5-bigip`, connection `{"managementUrl":"https://...","allowInsecureTls":true}`; cert/key objeleri timestamped oluşturulur, client-ssl profili yeniden bağlanır, rollback profili eski objelere döndürür.

## Bilinen sınırlar / sonraki adımlar

- RabbitMQ/Redis bağlı ama job akışı şu an DB-polling ile (tasarımda öngörülen outbox/queue geçişi hazır altyapı üzerinde yapılacak).
- Runner mTLS yerine bootstrap-token + API key kullanıyor (mTLS production hardening adımı).
- HVCA connector canlı GlobalSign hesabıyla doğrulanacak (docs/ca-connector.md).
- UI login ekranı, RBAC'ın ekranlara işlenmesi, e-posta/Teams bildirimi ve F9 dışındaki network vendorları sonraki iterasyon.
