# 🌐 NetMonitor - Kurumsal Ağ & Sistem Takip Platformu

[![Canlı Demo](https://img.shields.io/badge/Canlı_Site-Görüntüle-2ea44f?style=for-the-badge&logo=google-chrome&logoColor=white)](https://ilkerys.pythonanywhere.com)
[![Python](https://img.shields.io/badge/Python-3.10-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Bootstrap](https://img.shields.io/badge/Frontend-Bootstrap_5-7952B3?style=for-the-badge&logo=bootstrap&logoColor=white)](https://getbootstrap.com/)

**NetMonitor**, BT altyapınızı, sunucularınızı ve web sitelerinizi tek bir merkezden 7/24 izlemenizi sağlayan, kesinti durumunda anında aksiyon almanıza yardımcı olan modern bir izleme aracıdır.

---

## 🔥 Temel Özellikler

### 📡 1. Gerçek Zamanlı İzleme
* **Web (SSL) Takibi:** Sitelerin HTTP durum kodlarını ve SSL sertifika bitiş sürelerini kontrol eder.
* **Port Kontrolü:** Sunucuların belirli portlarının (Örn: 3306, 8080) açık olup olmadığını denetler.
* **Ping (ICMP):** Yerel ağ veya izin verilen sunucular için ping takibi yapar.

### 🔔 2. Akıllı Bildirim Sistemi
* Bir cihaz **OFFLINE** olduğunda veya tekrar **ONLINE** olduğunda **Telegram Bot** entegrasyonu sayesinde saniyesinde cebinize bildirim gelir.

### 🛡️ 3. Güvenlik ve Yetkilendirme
* **Google OAuth 2.0:** Güvenli ve şifresiz hızlı giriş.
* **Misafir (Demo) Modu:** Sistemi incelemek isteyenler için kısıtlı yetkili demo girişi.
* **Admin Paneli:** Cihaz ekleme/silme, personel yönetimi ve ayarlar için özel panel.

### 🎫 4. Destek Masası (Ticket System)
* Kullanıcılar sistemle ilgili sorunlar için talep oluşturabilir.
* Yöneticiler talepleri yanıtlayabilir ve durumlarını güncelleyebilir.
* WhatsApp tarzı modern mesajlaşma arayüzü.

### 📱 5. Modern Arayüz
* **Bootstrap 5** ile geliştirilmiş %100 Mobil Uyumlu (Responsive) tasarım.
* Karanlık/Aydınlık mod uyumlu bileşenler.
* Dinamik grafikler ve animasyonlar.

---

## 🛠️ Kullanılan Teknolojiler

| Alan | Teknoloji |
| :--- | :--- |
| **Backend** | Python 3, Flask, SQLAlchemy, APScheduler |
| **Frontend** | HTML5, CSS3, JavaScript, Bootstrap 5, FontAwesome |
| **Veritabanı** | SQLite (Geliştirme), PostgreSQL (Prodüksiyon uyumlu) |
| **Auth** | Authlib (Google), Flask-Login |
| **API** | Telegram Bot API, Requests |

---

## 🚀 Kurulum ve Çalıştırma

Projeyi kendi bilgisayarınızda çalıştırmak için aşağıdaki adımları izleyin:

### 1. Repoyu Klonlayın
```bash
git clone https://github.com/ilkerys/NetMonitor.git
cd NetMonitor
```

### 2. Sanal Ortam Oluşturun (Önerilen)
```bash
python -m venv venv
# Windows için:
venv\Scripts\activate
# Mac/Linux için:
source venv/bin/activate
```

### 3. Gereksinimleri Yükleyin
```bash
pip install -r requirements.txt
```

### 4. Yapılandırma
`app.py` dosyasını açın ve aşağıdaki alanları kendi bilgilerinizle doldurun:
* `GOOGLE_CLIENT_ID` & `GOOGLE_CLIENT_SECRET` (Google Cloud Console'dan alınır)
* `TELEGRAM_BOT_TOKEN` & `CHAT_ID` (BotFather'dan alınır)

### 5. Uygulamayı Başlatın
```bash
python app.py
```
Tarayıcınızda `http://localhost:5000` adresine gidin.

---

## 📸 Ekran Görüntüleri

| Dashboard (Masaüstü) | Mobil Görünüm |
| :---: | :---: |
| *(Ekran görüntüsü eklenecek)* | *(Ekran görüntüsü eklenecek)* |

---

## 👤 İletişim & Geliştirici

**Geliştirici:** [İlker Y.](https://github.com/ilkerys)  
**Canlı Demo:** [https://ilkerys.pythonanywhere.com](https://ilkerys.pythonanywhere.com)

Bu proje açık kaynaklıdır ve eğitim amaçlı geliştirilmiştir. ⭐ Yıldız vermeyi unutmayın!
