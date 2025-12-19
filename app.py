from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from authlib.integrations.flask_client import OAuth
from datetime import datetime, timedelta
import platform
import subprocess
import requests
import urllib3
from flask_apscheduler import APScheduler
import os
import socket
import ssl
import csv
import io

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = "cok_gizli_bisi_yaz_buraya_kanka"

# --- VERİTABANI YOLU (PythonAnywhere Uyumlu) ---
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'network.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- LOGIN & OAUTH ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "google_login"

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=None,
    client_secret=None,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

# Scheduler
app.config['SCHEDULER_API_ENABLED'] = True
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

# --- VERİTABANI MODELLERİ ---

class SystemConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    google_client_id = db.Column(db.String(200))
    google_client_secret = db.Column(db.String(200))
    admin_email = db.Column(db.String(100))
    panel_user = db.Column(db.String(50))
    panel_pass = db.Column(db.String(50))
    is_configured = db.Column(db.Boolean, default=False)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(100), unique=True)
    name = db.Column(db.String(100))
    picture = db.Column(db.String(200))
    role = db.Column(db.String(20), default="user")
    telegram_token = db.Column(db.String(150), nullable=True)
    telegram_chat_id = db.Column(db.String(100), nullable=True)
    cihazlar = db.relationship('Cihaz', backref='sahip', lazy=True)

class AllowedUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    aciklama = db.Column(db.String(100))

class Cihaz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    isim = db.Column(db.String(100), nullable=False)
    ip = db.Column(db.String(100), nullable=False)
    takip_tipi = db.Column(db.String(20), default="Ping")
    port = db.Column(db.Integer, nullable=True)
    ssl_bitis = db.Column(db.DateTime, nullable=True)
    tip = db.Column(db.String(50), default="Diğer")
    marka_model = db.Column(db.String(100), default="-")
    konum = db.Column(db.String(100), default="-")
    sorumlu = db.Column(db.String(100), default="-")
    durum = db.Column(db.String(20), default="Bilinmiyor")
    offline_counter = db.Column(db.Integer, default=0)
    son_kontrol = db.Column(db.DateTime, default=datetime.now)
    loglar = db.relationship('Log', backref='cihaz', lazy=True, cascade="all, delete-orphan")

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cihaz_id = db.Column(db.Integer, db.ForeignKey('cihaz.id'), nullable=False)
    mesaj = db.Column(db.String(200), nullable=False)
    tur = db.Column(db.String(20), default="Info")
    tarih = db.Column(db.DateTime, default=datetime.now)

class Talep(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    gonderen_isim = db.Column(db.String(100))
    konu = db.Column(db.String(100), nullable=False)
    oncelik = db.Column(db.String(20), default="Normal")
    durum = db.Column(db.String(20), default="Açık")
    tarih = db.Column(db.DateTime, default=datetime.now)
    mesajlar = db.relationship('Mesaj', backref='talep', lazy=True, cascade="all, delete-orphan")

class Mesaj(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    talep_id = db.Column(db.Integer, db.ForeignKey('talep.id'), nullable=False)
    gonderen_id = db.Column(db.Integer, nullable=False)
    gonderen_isim = db.Column(db.String(100))
    icerik = db.Column(db.Text, nullable=False)
    tarih = db.Column(db.DateTime, default=datetime.now)
    is_admin = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- KURULUM KONTROLÜ ---
@app.before_request
def check_setup():
    if request.endpoint and 'static' in request.endpoint: return
    if not getattr(app, 'db_checked', False):
        db.create_all()
        app.db_checked = True
    config = SystemConfig.query.first()
    if (not config or not config.is_configured) and request.endpoint != 'setup_wizard':
        return redirect(url_for('setup_wizard'))
    if config and config.is_configured and request.endpoint == 'setup_wizard':
        return redirect(url_for('index'))

@app.route('/setup', methods=['GET', 'POST'])
def setup_wizard():
    if request.method == 'POST':
        config = SystemConfig.query.first() or SystemConfig()
        if not config.id: db.session.add(config)
        config.google_client_id = request.form.get('google_client_id')
        config.google_client_secret = request.form.get('google_client_secret')
        config.admin_email = request.form.get('admin_email')
        config.panel_user = request.form.get('panel_user')
        config.panel_pass = request.form.get('panel_pass')
        config.is_configured = True
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('setup.html')

# --- YARDIMCI FONKSİYONLAR ---
def cihaz_kontrol_et(cihaz):
    hedef = cihaz.ip
    hedef_temiz = hedef.replace('http://', '').replace('https://', '').split('/')[0]

    # 1. DEMO ve LOCALHOST
    if "demo" in hedef:
        import random
        return "ONLINE 🟢" if random.random() > 0.2 else "OFFLINE 🔴"
    if hedef_temiz in ["127.0.0.1", "localhost"]: return "ONLINE 🟢"

    try:
        # URL Hazırla
        url = f"http://{hedef_temiz}"
        if cihaz.takip_tipi == "Web":
            url = f"https://{hedef_temiz}"

        # İsteği At
        resp = requests.get(url, timeout=5, verify=False)

        # --- DÜZELTME BURADA ---
        # PythonAnywhere whitelist dışı sitelere "403 Forbidden" döner.
        # Biz bunu OFFLINE saymalıyız.

        if resp.status_code == 403:
            print(f"Bloklandı (Proxy): {hedef}")
            return "OFFLINE 🔴" # Yasaklı site, erişilemiyor demek.

        # Sadece 200 ile 399 arası kodlar (Başarılı) ONLINE sayılsın
        if 200 <= resp.status_code < 400:
            # Web Moduysa SSL Tarihini de al
            if cihaz.takip_tipi == "Web":
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((hedef_temiz, 443), timeout=3) as s_sock:
                        with context.wrap_socket(s_sock, server_hostname=hedef_temiz) as ssock:
                            cert = ssock.getpeercert()
                            cihaz.ssl_bitis = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                except: pass
            return "ONLINE 🟢"

        else:
            # 404 (Bulunamadı), 500 (Sunucu Hatası) vb.
            return "OFFLINE 🔴"

    except Exception as e:
        print(f"Bağlantı Hatası: {e}")
        return "OFFLINE 🔴"

def telegram_gonder(mesaj):
    config = SystemConfig.query.first()
    if not config: return False
    admin = User.query.filter_by(email=config.admin_email).first()
    if not admin or not admin.telegram_token: return False
    try:
        requests.post(f"https://api.telegram.org/bot{admin.telegram_token}/sendMessage", data={"chat_id": admin.telegram_chat_id, "text": mesaj}, timeout=5)
        return True
    except: return False

def otomatik_tarama():
    print(f"⏰ Tarama: {datetime.now().strftime('%H:%M:%S')}")
    with app.app_context():
        if not SystemConfig.query.filter_by(is_configured=True).first(): return
        cihazlar = Cihaz.query.all()
        for c in cihazlar:
            if c.sahip and c.sahip.email == "demo@netmonitor.com": continue
            eski_durum = c.durum
            yeni_durum = cihaz_kontrol_et(c)

            if eski_durum != yeni_durum:
                c.durum = yeni_durum
                c.offline_counter = 0
                log_turu = "Success" if "ONLINE" in yeni_durum else "Danger"
                db.session.add(Log(cihaz_id=c.id, mesaj=f"Otomatik: {yeni_durum}", tur=log_turu))
                telegram_gonder(f"🚨 {c.isim} -> {yeni_durum}")

            elif "OFFLINE" in yeni_durum:
                c.offline_counter = (c.offline_counter or 0) + 1
                if c.offline_counter % 10 == 0:
                    telegram_gonder(f"🔁 HATIRLATMA: {c.isim} hala OFFLINE! ({c.offline_counter}. tarama)")
            else:
                c.offline_counter = 0

            c.son_kontrol = datetime.now()
        db.session.commit()

# --- LOGIN & AUTH ---
@app.route('/login/google')
def google_login():
    config = SystemConfig.query.first()
    google.client_id = config.google_client_id
    google.client_secret = config.google_client_secret
    return google.authorize_redirect(url_for('google_callback', _external=True))

@app.route('/google/callback')
def google_callback():
    config = SystemConfig.query.first()
    google.client_id = config.google_client_id
    google.client_secret = config.google_client_secret
    token = google.authorize_access_token()
    user_info = google.get('https://www.googleapis.com/oauth2/v1/userinfo').json()
    email = user_info['email']
    is_admin = (email == config.admin_email)
    allowed_entry = AllowedUser.query.filter_by(email=email).first()
    if not is_admin and not allowed_entry: return render_template('yetkisiz.html', email=email)
    user = User.query.filter_by(google_id=user_info['id']).first()
    if not user:
        user = User(google_id=user_info['id'], email=email, name=user_info['name'], picture=user_info['picture'], role="admin" if is_admin else "user")
        db.session.add(user)
    else: user.role = "admin" if is_admin else "user"
    db.session.commit()
    login_user(user)
    return redirect(url_for('index'))

@app.route('/login/demo')
def demo_login():
    email = "demo@netmonitor.com"
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(google_id="demo", email=email, name="Demo Mod", picture="https://cdn-icons-png.flaticon.com/512/149/149071.png", role="admin")
        db.session.add(user)
        db.session.commit()
        fake_list = [{"isim": "Web Sunucusu", "ip": "demo_web", "tip": "Web", "durum": "ONLINE 🟢"}, {"isim": "Arızalı Yazıcı", "ip": "demo_prn", "tip": "Yazıcı", "durum": "OFFLINE 🔴"}]
        for f in fake_list:
            dev = Cihaz(user_id=user.id, isim=f["isim"], ip=f["ip"], tip=f["tip"], durum=f["durum"], marka_model="Sanal", konum="Sanal", sorumlu="Demo")
            db.session.add(dev)
            db.session.flush()
            for i in range(5): db.session.add(Log(cihaz_id=dev.id, mesaj="Demo Log", tur="Info", tarih=datetime.now()-timedelta(hours=i*2)))
        db.session.commit()
    login_user(user)
    session['admin_logged_in'] = True
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('admin_logged_in', None)
    return redirect(url_for('index'))

@app.route('/admin/login', methods=['GET', 'POST'])
@login_required
def admin_login():
    if current_user.email == "demo@netmonitor.com":
        session['admin_logged_in'] = True
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        config = SystemConfig.query.first()
        if config and request.form.get('username') == config.panel_user and request.form.get('password') == config.panel_pass:
            session['admin_logged_in'] = True
            return redirect(url_for('dashboard'))
        else:
            return render_template('admin_login.html', hata="Hatalı giriş!")
    return render_template('admin_login.html')

@app.route('/admin/forgot')
@login_required
def admin_forgot():
    if current_user.email == "demo@netmonitor.com": return render_template('yetkisiz.html', email="Demo Mod")
    config = SystemConfig.query.first()
    if telegram_gonder(f"Panel: {config.panel_user} / {config.panel_pass}"):
        flash("Şifre Telegram'a gönderildi.", "success")
    else: flash("Telegram ayarları eksik!", "danger")
    return redirect(url_for('admin_login'))

# --- ANA İŞLEMLER ---

@app.route('/')
def index(): return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))

    if current_user.email == "demo@netmonitor.com":
        cihazlar = Cihaz.query.filter_by(user_id=current_user.id).all()
        # Demo talepler (Sahte)
        son_talepler = [
            {"id": 1, "konu": "Yazıcı Kağıt Sıkıştırdı", "gonderen_isim": "Ahmet Y.", "tarih": datetime.now(), "durum": "Açık", "oncelik": "Normal"},
            {"id": 2, "konu": "İnternet Çok Yavaş", "gonderen_isim": "Merve K.", "tarih": datetime.now(), "durum": "Kapalı", "oncelik": "Acil"}
        ]
    else:
        demo_user = User.query.filter_by(email="demo@netmonitor.com").first()
        if demo_user: cihazlar = Cihaz.query.filter(Cihaz.user_id != demo_user.id).all()
        else: cihazlar = Cihaz.query.all()
        son_talepler = Talep.query.order_by(Talep.tarih.desc()).limit(5).all()

    return render_template('dashboard.html', cihazlar=cihazlar, son_talepler=son_talepler)

@app.route('/ekle', methods=['POST'])
@login_required
def cihaz_ekle():
    if not session.get('admin_logged_in'): return "Yetkisiz", 403
    # YETKİSİZ SAYFASI GÖSTER
    if current_user.email == "demo@netmonitor.com": return render_template('yetkisiz.html', email="Demo Mod")

    yeni = Cihaz(
        user_id=current_user.id,
        isim=request.form.get('isim'),
        ip=request.form.get('ip'),
        tip=request.form.get('tip'),
        takip_tipi=request.form.get('takip_tipi'),
        port=request.form.get('port'),
        marka_model=request.form.get('marka_model'),
        konum=request.form.get('konum'),
        sorumlu=request.form.get('sorumlu')
    )
    db.session.add(yeni)
    db.session.commit()
    yeni.durum = cihaz_kontrol_et(yeni)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/sil/<int:id>')
@login_required
def cihaz_sil(id):
    if not session.get('admin_logged_in') or current_user.email == "demo@netmonitor.com":
        return render_template('yetkisiz.html', email="Demo Mod")
    db.session.delete(Cihaz.query.get_or_404(id))
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/cihaz/duzenle/<int:id>', methods=['POST'])
@login_required
def cihaz_duzenle(id):
    if not session.get('admin_logged_in') or current_user.email == "demo@netmonitor.com":
        return render_template('yetkisiz.html', email="Demo Mod")
    c = Cihaz.query.get_or_404(id)
    c.isim = request.form.get('isim')
    c.ip = request.form.get('ip')
    c.tip = request.form.get('tip')
    c.takip_tipi = request.form.get('takip_tipi')
    c.port = request.form.get('port')
    c.marka_model = request.form.get('marka_model')
    c.konum = request.form.get('konum')
    c.sorumlu = request.form.get('sorumlu')
    db.session.commit()
    return redirect(url_for('cihaz_detay', id=id))

@app.route('/cihaz/<int:id>')
@login_required
def cihaz_detay(id):
    c = Cihaz.query.get_or_404(id)
    if current_user.email == "demo@netmonitor.com" and c.user_id != current_user.id:
        return render_template('yetkisiz.html', email="Demo Mod")
    loglar = Log.query.filter_by(cihaz_id=id).order_by(Log.tarih.desc()).limit(20).all()
    return render_template('cihaz_detay.html', cihaz=c, loglar=loglar)

@app.route('/cihaz/tara/<int:id>')
@login_required
def tekli_tara(id):
    c = Cihaz.query.get_or_404(id)
    if current_user.email == "demo@netmonitor.com":
        import random
        c.durum = "ONLINE 🟢" if random.random() > 0.2 else "OFFLINE 🔴"
    else:
        c.durum = cihaz_kontrol_et(c)
        telegram_gonder(f"Manuel: {c.isim} -> {c.durum}")
    db.session.add(Log(cihaz_id=c.id, mesaj=f"Manuel Tarama: {c.durum}", tur="Info"))
    c.son_kontrol = datetime.now()
    db.session.commit()
    return redirect(url_for('cihaz_detay', id=id))

@app.route('/tara')
@login_required
def sistemi_tara():
    otomatik_tarama()
    return redirect(url_for('dashboard'))

@app.route('/import/csv', methods=['POST'])
@login_required
def csv_import():
    # CSV EKLERKEN DE YETKİSİZ SAYFASI ÇIKSIN
    if not session.get('admin_logged_in') or current_user.email == "demo@netmonitor.com":
        return render_template('yetkisiz.html', email="Demo Mod")

    file = request.files['file']
    if not file: return "Dosya yok", 400
    stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
    csv_input = csv.reader(stream)
    next(csv_input, None)
    count = 0
    for row in csv_input:
        if len(row) >= 2:
            isim, ip = row[0], row[1]
            tip = row[2] if len(row) > 2 else "Diğer"
            takip = row[3] if len(row) > 3 else "Ping"
            port = row[4] if len(row) > 4 else None
            db.session.add(Cihaz(user_id=current_user.id, isim=isim, ip=ip, tip=tip, takip_tipi=takip, port=port, durum="Bilinmiyor"))
            count += 1
    db.session.commit()
    flash(f"{count} cihaz eklendi!", "success")
    return redirect(url_for('dashboard'))

@app.route('/api/chart/<int:id>')
@login_required
def chart_data(id):
    son_24 = datetime.now() - timedelta(hours=24)
    logs = Log.query.filter(Log.cihaz_id == id, Log.tarih >= son_24).order_by(Log.tarih).all()
    data = []
    for log in logs:
        val = 1 if "ONLINE" in log.mesaj else (0 if "OFFLINE" in log.mesaj else 0.5)
        data.append({"x": log.tarih.strftime('%H:%M'), "y": val})
    return jsonify(data)

# --- DİĞER (AYARLAR, PERSONEL, DESTEK) ---
@app.route('/ayarlar', methods=['GET', 'POST'])
@login_required
def ayarlar():
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    # Demo mod ayarları görebilir ama değiştiremez
    if current_user.email == "demo@netmonitor.com":
        if request.method == 'POST': return render_template('yetkisiz.html', email="Demo Mod")
        return render_template('ayarlar.html', config=SystemConfig(), is_demo=True)

    config = SystemConfig.query.first()
    if request.method == 'POST':
        if request.form.get('telegram_token'):
            current_user.telegram_token = request.form.get('telegram_token')
            current_user.telegram_chat_id = request.form.get('telegram_chat_id')
        if request.form.get('panel_user'):
            config.panel_user = request.form.get('panel_user')
            config.panel_pass = request.form.get('panel_pass')
        if request.form.get('google_client_id'):
            config.google_client_id = request.form.get('google_client_id')
            config.google_client_secret = request.form.get('google_client_secret')
        db.session.commit()
        return redirect(url_for('ayarlar'))
    return render_template('ayarlar.html', config=config)

@app.route('/admin/personel', methods=['GET', 'POST'])
@login_required
def personel_yonetimi():
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    if current_user.email == "demo@netmonitor.com":
        # POST yapılırsa engelle
        if request.method == 'POST': return render_template('yetkisiz.html', email="Demo Mod")
        return render_template('personel.html', personeller=[], is_demo=True)

    if request.method == 'POST':
        email = request.form.get('email')
        aciklama = request.form.get('aciklama')
        if email and not AllowedUser.query.filter_by(email=email).first():
            db.session.add(AllowedUser(email=email, aciklama=aciklama))
            db.session.commit()
    return render_template('personel.html', personeller=AllowedUser.query.all())

@app.route('/admin/personel/sil/<int:id>')
@login_required
def personel_sil(id):
    if not session.get('admin_logged_in') or current_user.email == "demo@netmonitor.com":
        return render_template('yetkisiz.html', email="Demo Mod")
    db.session.delete(AllowedUser.query.get_or_404(id))
    db.session.commit()
    return redirect(url_for('personel_yonetimi'))

@app.route('/admin/talepler')
@login_required
def admin_talepler():
    if current_user.email == "demo@netmonitor.com": return render_template('talepler.html', talepler=[], baslik="Demo Mod")
    return render_template('talepler.html', talepler=Talep.query.order_by(Talep.tarih.desc()).all(), baslik="Talepler")

@app.route('/destek/yeni', methods=['GET', 'POST'])
@login_required
def destek_yeni():
    if request.method == 'POST':
        if current_user.email == "demo@netmonitor.com":
            return render_template('yetkisiz.html', email="Demo Mod")
        t = Talep(user_id=current_user.id, gonderen_isim=current_user.name, konu=request.form.get('konu'), oncelik=request.form.get('oncelik'))
        db.session.add(t)
        db.session.commit()
        db.session.add(Mesaj(talep_id=t.id, gonderen_id=current_user.id, gonderen_isim=current_user.name, icerik=request.form.get('mesaj'), is_admin=False))
        db.session.commit()
        return redirect(url_for('destek_detay', id=t.id))
    return render_template('destek_yeni.html')

@app.route('/destek', methods=['GET'])
@login_required
def destek_yonlendir(): return redirect(url_for('admin_talepler'))

@app.route('/destek/<int:id>', methods=['GET', 'POST'])
@login_required
def destek_detay(id):
    # DÜZELTME: Demo kullanıcısı detay sayfasına girmeye çalışırsa 404 almasın, Yetkisiz'e gitsin.
    if current_user.email == "demo@netmonitor.com":
        return render_template('yetkisiz.html', email="Demo Mod")

    t = Talep.query.get_or_404(id)
    if not session.get('admin_logged_in') and t.user_id != current_user.id: return "Yetkisiz", 403
    if request.method == 'POST':
        is_adm = True if session.get('admin_logged_in') else False
        db.session.add(Mesaj(talep_id=t.id, gonderen_id=current_user.id, gonderen_isim=current_user.name, icerik=request.form.get('icerik'), is_admin=is_adm))
        db.session.commit()
        return redirect(url_for('destek_detay', id=id))
    return render_template('destek_detay.html', talep=t)

@app.route('/admin/talepler/durum/<int:id>')
@login_required
def talep_durum_degistir(id):
    if not session.get('admin_logged_in') or current_user.email == "demo@netmonitor.com":
        return render_template('yetkisiz.html', email="Demo Mod")
    t = Talep.query.get_or_404(id)
    t.durum = 'Kapalı' if t.durum == 'Açık' else 'Açık'
    db.session.commit()
    return redirect(url_for('admin_talepler'))

@app.route('/admin/talepler/sil/<int:id>')
@login_required
def talep_sil(id):
    if not session.get('admin_logged_in') or current_user.email == "demo@netmonitor.com":
        return render_template('yetkisiz.html', email="Demo Mod")
    db.session.delete(Talep.query.get_or_404(id))
    db.session.commit()
    return redirect(url_for('admin_talepler'))

    # --- GİZLİ TARAMA KAPISI (CRON İÇİN) ---
@app.route('/api/cron/tara/gizli_anahtar_999') # Buradaki 'gizli_anahtar_999' kısmını kafana göre değiştirebilirsin
def cron_tarama():
    # Login zorunluluğu yok, dışarıdan tetiklenebilir
    otomatik_tarama()
    return "Tarama Başarıyla Tetiklendi! 🚀", 200

if __name__ == '__main__':
    with app.app_context():
        if not scheduler.get_job('tarama_gorevi'):
            scheduler.add_job(id='tarama_gorevi', func=otomatik_tarama, trigger='interval', seconds=10)
    app.run(debug=True, use_reloader=False)