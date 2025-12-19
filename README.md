# 🌐 NetMonitor - Kurumsal Ağ & Sistem Takip Platformu

[![Canlı Demo](https://img.shields.io/badge/Canlı_Site-Görüntüle-2ea44f?style=for-the-badge&logo=google-chrome&logoColor=white)](https://ilkertgv.pythonanywhere.com)
[![Python](https://img.shields.io/badge/Python-3.10-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Bootstrap](https://img.shields.io/badge/Frontend-Bootstrap_5-7952B3?style=for-the-badge&logo=bootstrap&logoColor=white)](https://getbootstrap.com/)

**NetMonitor**, BT altyapınızı, sunucularınızı ve web sitelerinizi tek bir merkezden 7/24 izlemenizi sağlayan, kesinti durumunda anında aksiyon almanıza yardımcı olan modern bir izleme aracıdır.

---

## ⚠️ Demo ve Giriş Hakkında Önemli Not

🔴 **Canlı Demo Sınırlaması:** [Canlı Demo](https://ilkertgv.pythonanywhere.com) sitesindeki **"Google ile Giriş"** özelliği, güvenlik nedeniyle sadece yetkili yönetici hesaplarına (Proje Sahibine) açıktır. Kendi Gmail hesabınızla giriş yapmaya çalışırsanız yetki hatası alabilirsiniz.

✅ **Sistemi Tam Yetkiyle İncelemek İçin:** Sistemi tüm admin özellikleriyle (Cihaz Ekleme/Silme, Ayarlar, Personel Yönetimi vb.) test etmek için **projeyi kendi bilgisayarınıza (Localhost) kurmanız gerekmektedir.** Kurulum adımları aşağıdadır.

---

## 🔥 Temel Özellikler

### 📡 1. Gerçek Zamanlı İzleme
* **Web (SSL) Takibi:** Sitelerin HTTP durum kodlarını ve SSL sertifika bitiş sürelerini kontrol eder.
* **Port Kontrolü:** Sunucuların belirli portlarının (Örn: 3306, 8080) açık olup olmadığını denetler.
* **Ping (ICMP):** Yerel ağ veya izin verilen sunucular için ping takibi yapar.

### 🔔 2. Akıllı Bildirim Sistemi
* Bir cihaz **OFFLINE** olduğunda veya tekrar **ONLINE** olduğunda **Telegram Bot** entegrasyonu sayesinde saniyesinde cebinize bildirim gelir.
* *Not: Telegram ayarları, kurulum sonrası paneldeki "Ayarlar" sayfasından kolayca yapılır.*

### 🛡️ 3. Kolay Kurulum & Güvenlik
* **Otomatik Kurulum Sihirbazı:** Kodla uğraşmanıza gerek yok. İlk çalıştırmada Google Client ID ve Admin bilgilerinizi girebileceğiniz kurulum ekranı açılır.
* **Google OAuth 2.0:** Güvenli ve şifresiz hızlı giriş.
* **Admin Paneli:** Cihaz ekleme/silme, personel yönetimi ve ayarlar için özel panel.

### 🎫 4. Destek Masası (Ticket System)
* Kullanıcılar sistemle ilgili sorunlar için talep oluşturabilir.
* Yöneticiler talepleri yanıtlayabilir, durumlarını güncelleyebilir.

---

## 🛠️ Kullanılan Teknolojiler

| Alan | Teknoloji |
| :--- | :--- |
| **Backend** | Python 3, Flask, SQLAlchemy, APScheduler |
| **Frontend** | HTML5, CSS3, JavaScript, Bootstrap 5, FontAwesome |
| **Veritabanı** | SQLite (Otomatik Oluşur) |
| **Auth** | Authlib (Google), Flask-Login |

---

## 🚀 Kurulum ve Çalıştırma (Tam Yetki İçin)

Projeyi tam fonksiyonel kullanmak için local ortamda çalıştırın:

### 1. Repoyu Klonlayın
```bash
git clone https://github.com/ilkerys/NetMonitor.git
cd NetMonitor
```

### 2. Sanal Ortam (Opsiyonel)
```bash
python -m venv venv
# Windows: venv\Scripts\activate
# Mac/Linux: source venv/bin/activate
```

### 3. Gereksinimleri Yükleyin
```bash
pip install -r requirements.txt
```

### 4. Başlatın ve Tarayıcıyı Açın
```bash
python app.py
```
Tarayıcınızda `http://localhost:5000` adresine gidin.

### 5. Kurulumu Tamamlayın
Sistem ilk açıldığında sizi **Kurulum Sihirbazı** karşılayacaktır.
1. **Google Client ID & Secret:** Google Cloud Console'dan aldığınız anahtarları girin.
2. **Admin Hesabı:** Yönetici e-posta ve şifrenizi belirleyin.
3. **Telegram:** Kurulum bittikten sonra panelden **Ayarlar** menüsüne gidip Telegram Bot Token ve Chat ID'nizi girin.

---

## 👤 İletişim & Geliştirici

**Geliştirici:** [İlker Y.](https://github.com/ilkerys)  
**Canlı Demo:** [https://ilkertgv.pythonanywhere.com](https://ilkertgv.pythonanywhere.com)

Bu proje açık kaynaklıdır ve eğitim amaçlı geliştirilmiştir. ⭐ Yıldız vermeyi unutmayın!
