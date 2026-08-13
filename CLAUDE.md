# RemoteSSL — Çalışma Kuralları

## Kaynak doküman
Tek gerçek kaynak: `RemoteSSL Teknik Tasarım ve Yazılım Geliştirme Dokümanı v1.0`.
Tüm mimari kararlar, adapter davranışları, ekranlar ve fazlar bu dokümana göre yapılır.
Dokümandan sapma gerekiyorsa ÖNCE kullanıcıya sorulur; sormadan alternatif/hafif ("light")
versiyon üretilmez.

## İletişim kuralları
- Kullanıcıya yorum/görüş katılmaz; sorulmadıkça tasarım tartışması açılmaz.
- Kullanıcı istemeden test istenmez; önce iş bitirilir.
- Kullanıcıyla iletişim Türkçe; kod, commit ve UI metinleri İngilizce.

## Ürün kuralları
- Ana menülerdeki her varlık (monitor, credential, target, policy, CA connector,
  user, certificate…) UI'dan düzenlenebilir ve silinebilir olmalıdır.
- Windows yönetim kanalı: doküman §11.1 gereği WinRM/PowerShell Remoting birincil
  (Windows runner üzerinden); SSH yalnızca alternatif kanal.
- Deployment pipeline'ı §21.1'deki tam sırayı izler (remote TLS verify dahil);
  §21.4 stratejileri (sequential/parallel/wave) desteklenir.
- Secret'lar hiçbir yerde plaintext görünmez (§7.3, §22.3).

## Teslimat kuralı
Her push sonrası kullanıcıya güncelleme/çalıştırma adımları (git pull + hangi
servislerin yeniden başlatılacağı) her mesajda eksiksiz tekrarlanır.
