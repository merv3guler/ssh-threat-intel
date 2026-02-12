# 🛡️ Sentinel: SSH Threat Intelligence (Serverless)

**Sentinel**, `auth.log` verilerini analiz ederek aktif brute-force saldırılarını raporlayan ve görselleştiren **Serverless** bir güvenlik projesidir. GitHub Actions üzerinde çalışır.

[🔗 **Canlı Dashboard'u Görüntüle**](https://merv3guler.github.io/ssh-threat-intel/)

## 🚀 Nasıl Çalışır?
1. **Veri Girişi:** Topluluk veya sunucular `logs/` klasörüne log dosyası yükler.
2. **Otomasyon:** GitHub Actions tetiklenir, Python motoru logları analiz eder.
3. **Zenginleştirme:** Saldırgan IP'leri **AbuseIPDB API** ile sorgulanır.
4. **Yayın:** Sonuçlar statik bir JSON ve Dashboard olarak yayınlanır.

## 🛠️ Mimari
- **Core:** Python 3.10
- **CI/CD:** GitHub Actions
- **Frontend:** HTML5 / CSS3 (No-Framework)
- **Data Source:** AbuseIPDB & Community Logs

---
