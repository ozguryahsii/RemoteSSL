# RemoteSSL — HA, yedekleme ve felaket kurtarma runbook'u

Bu belge tasarım dokümanının §34.1 (HA), §34.3 (DR) ve NFR-004 (ölçek) maddelerinin işletme
karşılığıdır. Kod tarafındaki karşılıkları F21'de tamamlandı; burada anlatılan adımlar operasyon
ekibinin uygulaması gereken kısımdır.

## 1. Bileşenler ve durum nerede duruyor

| Bileşen | Durum tutar mı | Kaybı ne demek |
|---------|----------------|----------------|
| API (control plane) | Hayır | Bir instance düşerse diğerleri devam eder |
| PostgreSQL | **Evet — tek gerçek kaynak** | Envanter, işler, audit, secret referansları |
| Object storage (S3/MinIO) | **Evet** | Artifact'lar ve audit'in dış WORM kopyası |
| RabbitMQ | Hayır (outbox kalıcı) | Sadece yayımlama gecikir; olay kaybolmaz |
| Redis | Hayır (cache) | Sadece performans |
| Runner | Hayır | Devam eden iş failover ile devralınır (§34.2) |

DataProtection anahtarları kritik: şifrelenmiş secret'lar ve artifact key'leri bunlarla açılır.
Çok node'lu kurulumda anahtar halkası **paylaşılan** bir yerde olmalıdır (paylaşılan volume veya
veritabanı); aksi halde bir node'un şifrelediğini diğeri açamaz.

## 2. Control plane HA (§34.1)

- API stateless'tır; N instance bir load balancer arkasına konur.
- Zamanlanmış işler Postgres advisory lock ile **leader-elected**'tır. Aynı anda yalnız bir node
  probe atar, outbox boşaltır, audit mühürler, runner failover'ı çalıştırır. Ek yapılandırma
  gerekmez — lock anahtarları koda gömülüdür.
- Sağlık: `GET /health`. Load balancer bunu kullanmalıdır.

Doğrulama:

```bash
# İki API instance'ı başlat, ikisinin de log'unu izle:
# yalnız birinde "Probing N due monitor(s)" satırı görünür.
dotnet run --project src/RemoteSSL.Api --urls http://localhost:5200
dotnet run --project src/RemoteSSL.Api --urls http://localhost:5201
```

## 3. PostgreSQL HA ve PITR (§34.1, §34.3)

**Hedefler.** Kurumun kabul ettiği değerler:

| Metrik | Hedef | Nasıl sağlanır |
|--------|-------|----------------|
| RPO | ≤ 5 dakika | WAL arşivleme (`archive_timeout = 300`) |
| RTO | ≤ 30 dakika | Streaming replica'ya promote |

**Replikasyon.** En az bir senkron olmayan streaming replica:

```
# primary postgresql.conf
wal_level = replica
max_wal_senders = 5
archive_mode = on
archive_command = 'test ! -f /wal/%f && cp %p /wal/%f'
archive_timeout = 300
```

**PITR yedeği.** Günlük temel yedek + sürekli WAL arşivi:

```bash
pg_basebackup -h $PRIMARY -U replicator -D /backup/base-$(date +%F) -Fp -Xs -P
```

**Geri dönüş (belirli bir ana).**

```bash
# 1) Servisi durdur
systemctl stop remotessl-api

# 2) Temel yedeği aç, recovery hedefini yaz
cp -a /backup/base-2026-08-14/. /var/lib/postgresql/data/
cat >> /var/lib/postgresql/data/postgresql.conf <<'EOF'
restore_command = 'cp /wal/%f %p'
recovery_target_time = '2026-08-14 09:15:00+03'
EOF
touch /var/lib/postgresql/data/recovery.signal

# 3) Postgres'i başlat, recovery bitince promote et
pg_ctl start -D /var/lib/postgresql/data
pg_ctl promote -D /var/lib/postgresql/data

# 4) API'yi başlat; migration'lar zaten uygulanmış olmalı
systemctl start remotessl-api
```

**Geri dönüş sonrası zorunlu kontrol** — audit zinciri geri sarma ile kırılmış olabilir:

```bash
curl -s localhost:5200/api/v1/audit/integrity
```

`intact: false` çıkarsa bu bir saldırı değil, geri dönüşün beklenen sonucudur; olay kaydı açılıp
hangi ana dönüldüğü yazılmalıdır. Dış WORM kopyası (§25.3) geri dönüşten etkilenmez ve kaybolan
aralığın kanıtı orada durur.

## 4. Object storage (§31.1, §25.3)

- **Versioning açık olmalıdır.** Artifact'lar ve audit arşivi silinmeye karşı böyle korunur.
- Audit arşivi için **object lock** (compliance mode): `Storage:S3:ObjectLockDays`. Bucket'ın
  kendisinde object lock etkin olmalıdır; sonradan açılamaz.
- Bucket replikasyonu ikinci bölgeye açılırsa DR sırasında artifact'lar da taşınmış olur.

```json
{ "Storage": { "S3": {
    "BucketName": "remotessl", "ObjectLockDays": 2555 } } }
```

## 5. Runner failover (§34.2)

Runner'lar durum tutmaz; devam eden iş **lease** ile korunur.

- Bir runner işi aldığında `LeaseExpiresAt` konur (`Runner:JobLeaseSeconds`, varsayılan 300 sn).
- Heartbeat lease'i yeniler. Uzun süren bir deployment terk edilmiş sayılmaz.
- Runner susarsa lease dolar; `RunnerFailoverService` işi aynı **affinity group**'taki başka bir
  runner'a devreder (`runner.job-reassigned` olayı).
- **Hedefe dokunmuş** bir iş devredilmez: runner `jobs/{id}/started` dediği andan itibaren
  `NonReassignable` olur. Bu durumda iş açık bir sebeple **başarısız** işaretlenir
  (`runner.job-abandoned`, incident seviyesi) — hedefte yedek ve yarım uygulanmış bir değişiklik
  olabileceği için tekrar çalıştırmak değişikliği iki kez uygulayabilir. Operatör hedefe bakıp
  yeniden deploy eder.

Runner tarafı yapılandırma:

```json
{ "Runner": { "AffinityGroup": "dc1", "Segment": "dc1" } }
```

`AffinityGroup` verilmezse `Segment` kullanılır. Aynı hedeflere erişebilen runner'lar aynı grupta
olmalıdır — grup, "bu işi kim devralabilir" sorusunun cevabıdır.

## 6. Ölçek: 10.000+ endpoint (NFR-004)

Ölçüm ve mimari kararlar:

- Probe zamanlayıcısı tick başına **sınırlı bir yığın** alır (`Monitoring:MaxProbesPerTick`,
  varsayılan 500) ve en uzun beklemiş monitor'dan başlar. Bellek envanterle değil yığınla orantılı
  kalır; yığına sığmayan bir sonraki tick'in başına geçer, yani açlık oluşmaz.
- Eşzamanlılık `Monitoring:MaxParallelProbes` (varsayılan 8) ile sınırlıdır.
- 10.000 endpoint / 60 dakikalık varsayılan aralık ≈ dakikada 167 probe. 60 saniyelik tick'te
  yığın 500 olduğu için tek node yeterlidir; yığın ve eşzamanlılık şu şekilde ölçeklenir:

| Endpoint | Aralık | Gereken probe/dk | Önerilen `MaxProbesPerTick` | Önerilen `MaxParallelProbes` |
|----------|--------|------------------|------------------------------|------------------------------|
| 1.000 | 60 dk | 17 | 100 | 4 |
| 10.000 | 60 dk | 167 | 500 | 16 |
| 10.000 | 15 dk | 667 | 1.000 | 32 |
| 50.000 | 60 dk | 833 | 1.000 | 32 + runner'a dağıt |

- İç vantajlı (runner) probe'lar ayrı kuyruğa gider; kontrol düzlemi CPU'su onlarla artmaz.
- `MonitorEndpoints` üzerinde `LastProbeAt` sıralaması ve `Enabled` filtresi kullanılır; büyük
  kurulumda şu indeks eklenmelidir:

```sql
CREATE INDEX CONCURRENTLY ix_monitor_due
  ON "MonitorEndpoints" ("Enabled", "LastProbeAt");
```

- Metrik saklama (`MetricSamples`) en hızlı büyüyen tablodur; `MetricsRetentionService` süreyi
  sınırlar, `Metrics:RetentionDays` ile ayarlanır.

**Dürüst sınır:** yukarıdaki tablo tasarım hesabıdır. 10.000 gerçek endpoint'e karşı uçtan uca
yük testi bu ortamda yapılmadı; F22'de (test stratejisi) performans testi maddesi bunun için
duruyor.

## 7. Felaket senaryoları ve müdahale

| Senaryo | Belirti | Müdahale |
|---------|---------|----------|
| API node kaybı | LB sağlık kontrolü düşer | Diğer node'lar devralır; leader işler yeni node'a geçer |
| Postgres primary kaybı | API 500, `/health` unhealthy | Replica'yı promote et, bağlantı dizesini çevir, API'leri yeniden başlat |
| Object storage kaybı | Artifact indirme hatası, audit arşivi durur | Bucket'ı geri yükle; audit mühürlemesi devam eder, arşiv birikir ve toparlanır |
| RabbitMQ kaybı | Olaylar `Pending` birikir | Broker dönünce outbox kaldığı yerden teslim eder (§28.2) |
| Runner kaybı | İşler kuyrukta bekler | Failover devreder; dokunulmuş işler `runner.job-abandoned` ile bildirilir |
| DataProtection anahtar kaybı | "The payload was invalid" | Anahtar halkası yedeğinden geri yükle; yoksa secret'lar yeniden girilmelidir |

## 8. Düzenli tatbikat

Üç ayda bir:

1. PITR ile ayrı bir ortama geri dönüş yapılır, `audit/integrity` ve envanter sayıları kontrol edilir.
2. Bir runner kasıtlı durdurulur; işin başka runner'a geçtiği (`runner.job-reassigned`) doğrulanır.
3. Leader node kapatılır; zamanlanmış işlerin diğer node'da başladığı log'dan doğrulanır.
