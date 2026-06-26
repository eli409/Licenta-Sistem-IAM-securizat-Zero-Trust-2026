from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from ldap3 import Server, Connection, ALL, SIMPLE
import pyotp
import qrcode
import sqlite3
import os
import io
import base64
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")
print(f"DEBUG: Aplicatia foloseste baza de date de la: {DB_PATH}")

app = Flask(__name__)
# Cheia secreta pentru securizarea sesiunii
app.secret_key = os.urandom(32)

# Configurari AD
AD_SERVER_IP = '192.168.101.130'
AD_DOMAIN = 'ELISAFOREST'

# Configurari Zero Trust
ALLOWED_SUBNET = '192.168.101.'

#Flask-login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, role='Standard'):
        self.id = id
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    #Luat rol din sesiune
    role = session.get('user_role', 'Standard')
    print(f"DEBUG LOAD_USER: Se încarcă userul {user_id} cu rolul: {role}")
    return User(user_id, role)

# Baza de date
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, mfa_secret TEXT, last_login TEXT)")
    conn.commit()
    conn.close()
init_db()

def get_user_role_ad(username, password):
     try:
         # Server AD
         server = Server(AD_SERVER_IP, get_info=ALL)
         # Utilzatorul AD
         user_login = f"{AD_DOMAIN}\\{username}"
         # Incercare de conectare
         conn = Connection(server, user=user_login, password=password, authentication=SIMPLE)
         # Verificare parola
         if conn.bind():
             search_filter = f"(&(objectClass=user)(sAMAccountName={username}))"
             conn.search(search_base="CN=Users,DC=ELISAFOREST,DC=LOCAL",
                         search_filter=search_filter,
                         attributes=['memberOf'])
             role = 'Standard'
             if conn.entries:
                 user_groups = str(conn.entries[0].memberOf)
                 if 'admini_licenta2026' in user_groups:
                     role = 'Administrator'
             conn.unbind()
             return True, role
         return False, None
     except Exception as e:
         print(f"Eroare Server: {e}")
         return False, None
     
def log_event(username, message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] USER:{username} -> {message}"
    print(log_entry)
    try:
        with open("audit_log.txt", "a") as f:
            f.write(log_entry + "\n")
    except Exception as e:
        print(f"Eroare scriere log: {e}")

# Verificare IP
@app.before_request
def check_ip():
    client_ip = request.remote_addr
    if not client_ip.startswith(ALLOWED_SUBNET) and client_ip != '127.0.0.1':
        return render_template('error_403.html', ip = client_ip, allowed = ALLOWED_SUBNET)

@app.route('/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for ('dashboard'))
    
    if request.method == 'POST':
        # Datele din formular
        user = request.form['username']
        parola = request.form['password']

        success, role = get_user_role_ad(user, parola)
        if success:
           session['temp_user'] = user
           session['temp_role'] = role
           log_event(user, f"Autentificare AD reușită, rol detectat: {role}")
           return redirect(url_for('mfa_check'))
        else:
            log_event(user, "Eroare autentificare AD(Date incorecte)")
            flash('Utilizator sau parolă greșită!', 'danger')
    
    return render_template('login.html')

@app.route('/mfa', methods=['GET', 'POST'])
def mfa_check():
    if 'temp_user' not in session:
        return redirect(url_for('login'))
    username = session['temp_user']
    role_final = session.get('temp_role', 'Standard')
    # Verificare existenta MFA
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT mfa_secret FROM users WHERE username=?", (username,))
    result=c.fetchone()
    conn.close()

    # Ultilizator nou, fara MFA
    if not result:
        if 'mfa_secret' not in session:
            session['mfa_secret'] = pyotp.random_base32()
        
        secret = session['mfa_secret']

        if request.method == 'POST':
            cod = request.form.get('code')
            totp = pyotp.TOTP(secret)
            if totp.verify(cod, valid_window=3):
                # Salvare secret in db
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute("INSERT INTO users (username, mfa_secret) VALUES (?, ?)", (username, secret))
                conn.commit()
                conn.close()
                # Logare user
                session['user_role'] = role_final
                user_obj = User(username, role=role_final)
                login_user(user_obj)
                # Curatenie in sesiune
                session.pop('temp_user', None)
                session.pop('mfa_secret', None)
                session.pop('temp_role', None)
                log_event(username, f"Configurare MFA și login reușit! Logat cu rol: {role_final}")
                return redirect(url_for('dashboard'))
            else:
                flash('Cod incorect! Scanează din nou.', 'danger')

        # Generare cod QR
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="Proiect Licenta")
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf)
        img_64 = base64.b64encode(buf.getvalue()).decode("utf-8")

        return render_template('mfa_setup.html', qr_code=img_64, secret=secret)

    # Utilizator existent, cu MFA setat deja
    else:
        db_secret = result[0]
        if request.method == 'POST':
            cod = request.form.get('code')
            totp = pyotp.TOTP(db_secret)
            if totp.verify(cod, valid_window=3):
                session['user_role'] = role_final
                user_obj = User(username, role=role_final)
                login_user(user_obj)
                session.pop('temp_user', None)
                session.pop('temp_role', None)
                log_event(username, f"Login MFA reușit! Rol: {role_final}")
                return redirect(url_for('dashboard'))
            else:
                flash('Cod MFA greșit!', 'danger')
                log_event(username, "Eșesc verificare MFA.")
            
        return render_template('mfa_verify.html')

@app.route('/dashboard')
@login_required
def dashboard(): 
    return render_template('dashboard.html', user=current_user)

@app.route('/logs')
@login_required
def view_logs():
    if current_user.role != 'Administrator':
        flash('Acces interzis fără drepturi de administrator', 'danger')
        return redirect(url_for('dashboard'))
    logs=[]
    try:
        if os.path.exists("audit_log.txt"):
            with open("audit_log.txt", "r") as f:
                logs = f.readlines()
                logs.reverse()
    except Exception as e:
        print(f"Eroare la citirea logurilor: {e}")    
    return render_template('logs.html', logs=logs)

@app.route('/logout')
@login_required
def logout():
    log_event(current_user.id, "Logout.")
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)