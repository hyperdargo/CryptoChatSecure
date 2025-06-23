from flask import Flask, request, session, redirect, url_for, render_template, flash, send_file
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import sqlite3
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import secrets
import logging
import io

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
UPLOAD_FOLDER = 'Uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
ca_public_key = ca_private_key.public_key()

def init_db():
    conn = None
    try:
        conn = sqlite3.connect('pki_chat.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            role TEXT,
            public_key BLOB,
            certificate BLOB
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS chats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER,
            receiver_id INTEGER,
            message TEXT,
            timestamp TEXT,
            signature BLOB,
            is_public INTEGER DEFAULT 0
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER,
            receiver_id INTEGER,
            filename TEXT,
            encrypted_content BLOB,
            encrypted_aes_key BLOB,
            signature BLOB
        )''')
        conn.commit()
        logger.info("Database initialized successfully")
    except sqlite3.Error as e:
        logger.error(f"Database initialization failed: {e}")
        raise
    finally:
        if conn:
            conn.close()

init_db()

def generate_key_pair_and_cert(username):
    try:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = private_key.public_key()
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, username)])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            public_key).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.utcnow()).not_valid_after(datetime.utcnow() + timedelta(days=365)).sign(
            ca_private_key, hashes.SHA256(), default_backend())
        return private_key, public_key, cert
    except Exception as e:
        logger.error(f"Key pair generation failed for {username}: {e}")
        raise

def verify_certificate(cert):
    try:
        ca_public_key.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        return True
    except Exception as e:
        logger.error(f"Certificate verification failed: {e}")
        return False

def get_certificate_details(cert):
    try:
        details = {
            'subject': cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            'issuer': cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            'serial_number': cert.serial_number,
            'not_valid_before': cert.not_valid_before.isoformat(),
            'not_valid_after': cert.not_valid_after.isoformat()
        }
        return details
    except Exception as e:
        logger.error(f"Failed to get certificate details: {e}")
        return {}

def sign_data(data, private_key):
    try:
        return private_key.sign(data.encode(), padding.PKCS1v15(), hashes.SHA256())
    except Exception as e:
        logger.error(f"Data signing failed: {e}")
        raise

def verify_signature(data, signature, public_key):
    try:
        public_key.verify(signature, data.encode(), padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False

def encrypt_file(file_content, public_key):
    try:
        aes_key = get_random_bytes(16)
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(file_content)
        encrypted_aes_key = public_key.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        encrypted_content = cipher_aes.nonce + tag + ciphertext
        return encrypted_content, encrypted_aes_key
    except Exception as e:
        logger.error(f"File encryption failed: {e}")
        raise

def decrypt_file(encrypted_content, encrypted_aes_key, private_key):
    try:
        aes_key = private_key.decrypt(encrypted_aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        nonce = encrypted_content[:16]
        tag = encrypted_content[16:32]
        ciphertext = encrypted_content[32:]
        cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        decrypted_content = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return decrypted_content
    except Exception as e:
        logger.error(f"File decryption failed: {e}")
        raise

# Custom Jinja2 filter for starts_with
def starts_with_filter(s, prefix):
    logger.debug(f"Applying starts_with filter to '{s}' with prefix '{prefix}'")
    return str(s).startswith(prefix)
app.jinja_env.filters['starts_with'] = starts_with_filter
logger.debug("Custom 'starts_with' filter registered")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']
        logger.debug(f"Register attempt for {username} as {role}")
        try:
            conn = sqlite3.connect('pki_chat.db')
            c = conn.cursor()
            c.execute("SELECT id FROM users WHERE username = ?", (username,))
            if c.fetchone():
                flash('Username already exists')
                conn.close()
                return redirect(url_for('register'))
            private_key, public_key, cert = generate_key_pair_and_cert(username)
            private_key_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()).decode()
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
            c.execute("INSERT INTO users (username, role, public_key, certificate) VALUES (?, ?, ?, ?)", (username, role, public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo), cert.public_bytes(serialization.Encoding.PEM)))
            conn.commit()
            user_id = c.lastrowid
            conn.close()
            session['user_id'] = user_id
            session['username'] = username
            session['role'] = role
            session['private_key'] = private_key_pem
            session['certificate'] = cert_pem
            logger.info(f"User {username} registered successfully")
            return redirect(url_for('show_key'))
        except Exception as e:
            logger.error(f"Registration failed for {username}: {e}")
            flash(f"Registration error: {str(e)}")
            return redirect(url_for('register'))
    return render_template('register.html')

@app.route('/show_key')
def show_key():
    if 'private_key' not in session or 'certificate' not in session:
        logger.warning("Attempt to access show_key without private key or certificate in session")
        return redirect(url_for('register'))
    private_key = session['private_key']
    cert_pem = session['certificate']
    username = session['username']
    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    cert_details = get_certificate_details(cert)
    return render_template('show_key.html', private_key=private_key, username=username, cert_pem=cert_pem, cert_details=cert_details)

@app.route('/download_cert')
def download_cert():
    if 'certificate' not in session:
        logger.warning("Attempt to download certificate without certificate in session")
        return redirect(url_for('login'))
    cert_pem = session['certificate']
    username = session['username']
    logger.info(f"User {username} downloaded certificate")
    return send_file(io.BytesIO(cert_pem.encode()), as_attachment=True, download_name=f"{username}_certificate.pem", mimetype='application/x-pem-file')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        private_key_pem = request.form['private_key']
        logger.debug(f"Login attempt for {username}")
        try:
            private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
            public_key = private_key.public_key()
            public_key_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            conn = sqlite3.connect('pki_chat.db')
            c = conn.cursor()
            c.execute("SELECT id, role, certificate, public_key FROM users WHERE username = ?", (username,))
            user = c.fetchone()
            if not user:
                flash('User not found')
                conn.close()
                return redirect(url_for('login'))
            cert = x509.load_pem_x509_certificate(user[2], default_backend())
            if not verify_certificate(cert):
                flash('Invalid certificate')
                conn.close()
                return redirect(url_for('login'))
            if public_key_pem != user[3]:
                flash('Private key does not match account')
                conn.close()
                return redirect(url_for('login'))
            session['user_id'] = user[0]
            session['username'] = username
            session['role'] = user[1]
            session['private_key'] = private_key_pem
            session['certificate'] = user[2].decode()
            conn.close()
            logger.info(f"User {username} logged in successfully")
            return redirect(url_for('chat'))
        except Exception as e:
            logger.error(f"Login failed for {username}: {e}")
            flash(f"Login error: {str(e)}")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/chat/<int:inbox_id>', methods=['GET', 'POST', 'DELETE'])
@app.route('/chat', methods=['GET', 'POST', 'DELETE'])
def chat(inbox_id=None):
    if 'user_id' not in session:
        logger.warning("Attempt to access chat without user_id in session")
        return redirect(url_for('login'))
    try:
        conn = sqlite3.connect('pki_chat.db')
        c = conn.cursor()
        c.execute("SELECT id, username, role FROM users WHERE id != ?", (session['user_id'],))
        users = c.fetchall()
        
        # Fetch all private chats for the user
        c.execute("SELECT c.id, c.sender_id, c.receiver_id, c.message, c.timestamp, u.username, c.signature, u.certificate, c.is_public, u2.username as receiver_username "
                  "FROM chats c "
                  "JOIN users u ON c.sender_id = u.id "
                  "LEFT JOIN users u2 ON c.receiver_id = u2.id "
                  "WHERE (c.receiver_id = ? OR c.sender_id = ?) AND c.is_public = 0 "
                  "ORDER BY c.timestamp ASC", (session['user_id'], session['user_id']))
        private_chats = c.fetchall()
        
        # Fetch public chats
        c.execute("SELECT c.id, c.sender_id, c.receiver_id, c.message, c.timestamp, u.username, c.signature, u.certificate, c.is_public "
                  "FROM chats c JOIN users u ON c.sender_id = u.id "
                  "WHERE c.is_public = 1 "
                  "ORDER BY c.timestamp ASC", ())
        public_chats = c.fetchall()
        
        # Fetch files
        c.execute("SELECT f.id, f.sender_id, f.receiver_id, f.filename, u.username, u.id AS receiver_username_id "
                  "FROM files f JOIN users u ON f.sender_id = u.id "
                  "WHERE f.sender_id = ? OR f.receiver_id = ?", (session['user_id'], session['user_id']))
        files = c.fetchall()
        
        # Group private chats into inboxes
        inboxes = {}
        for chat in private_chats:
            chat_id, sender_id, receiver_id, message, timestamp, username, signature, cert_pem, is_public, receiver_username = chat
            other_user_id = receiver_id if sender_id == session['user_id'] else sender_id
            other_username = receiver_username if sender_id == session['user_id'] else username
            if other_user_id not in inboxes:
                inboxes[other_user_id] = {'username': other_username, 'messages': []}
            inboxes[other_user_id]['messages'].append(chat)
        
        # Verify private chats
        verified_private_chats = []
        for chat in private_chats:
            chat_id, sender_id, receiver_id, message, timestamp, username, signature, cert_pem, is_public, receiver_username = chat
            message = str(message) if message is not None else ""
            if message is None:
                logger.warning(f"Found None message for chat_id {chat_id} in private chat")
            public_key = serialization.load_pem_public_key(c.execute("SELECT public_key FROM users WHERE id = ?", (sender_id,)).fetchone()[0], backend=default_backend())
            signature_verified = verify_signature(message, signature, public_key)
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            cert_verified = verify_certificate(cert)
            verified_private_chats.append((chat_id, sender_id, receiver_id, message, timestamp, username, signature, cert_pem, signature_verified, cert_verified, receiver_username))
        
        # Verify public chats
        verified_public_chats = []
        for chat in public_chats:
            chat_id, sender_id, receiver_id, message, timestamp, username, signature, cert_pem, is_public = chat
            message = str(message) if message is not None else ""
            if message is None:
                logger.warning(f"Found None message for chat_id {chat_id} in public chat")
            public_key = serialization.load_pem_public_key(c.execute("SELECT public_key FROM users WHERE id = ?", (sender_id,)).fetchone()[0], backend=default_backend())
            signature_verified = verify_signature(message, signature, public_key)
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            cert_verified = verify_certificate(cert)
            verified_public_chats.append((chat_id, sender_id, receiver_id, message, timestamp, username, signature, cert_pem, signature_verified, cert_verified))
        
        if request.method == 'POST':
            try:
                message = request.form['message']
                if not message:
                    flash("Message cannot be empty")
                    return redirect(url_for('chat', inbox_id=inbox_id))
                if 'receiver_id' in request.form:
                    receiver_id = request.form['receiver_id']
                    is_public = False
                elif 'is_public' in request.form:
                    receiver_id = None
                    is_public = True
                logger.debug(f"User {session['username']} sending {'public' if is_public else 'private'} message to {receiver_id}: {message}")
                private_key = serialization.load_pem_private_key(session['private_key'].encode(), password=None, backend=default_backend())
                signature = sign_data(message, private_key)
                c.execute("INSERT INTO chats (sender_id, receiver_id, message, timestamp, signature, is_public) VALUES (?, ?, ?, ?, ?, ?)",
                          (session['user_id'], receiver_id, message, datetime.utcnow().isoformat(), signature, 1 if is_public else 0))
                conn.commit()
                logger.info(f"Message sent from {session['username']} to {receiver_id if not is_public else 'public'}")
                flash('Message sent successfully')
                conn.close()
                return redirect(url_for('chat', inbox_id=receiver_id if not is_public else inbox_id))
            except KeyError as e:
                logger.error(f"Form field missing: {e}")
                flash(f"Form error: Missing {e}")
            except ValueError as e:
                logger.error(f"Value error during message send: {e}")
                flash(f"Error sending message: Invalid data - {str(e)}")
            except Exception as e:
                logger.error(f"Message sending failed: {e}", exc_info=True)
                flash(f"Error sending message: {str(e)}")
            finally:
                if conn:
                    conn.close()
            return redirect(url_for('chat', inbox_id=inbox_id))
        
        elif request.method == 'DELETE':
            try:
                chat_id = request.form.get('chat_id')
                c.execute("SELECT sender_id FROM chats WHERE id = ?", (chat_id,))
                sender_id = c.fetchone()
                if sender_id and sender_id[0] == session['user_id']:
                    c.execute("DELETE FROM chats WHERE id = ?", (chat_id,))
                    conn.commit()
                    logger.info(f"Message {chat_id} deleted by {session['username']}")
                    flash('Message deleted successfully')
                else:
                    flash('You can only delete your own messages')
            except Exception as e:
                logger.error(f"Message deletion failed: {e}")
                flash(f"Error deleting message: {str(e)}")
            finally:
                conn.close()
            return redirect(url_for('chat', inbox_id=inbox_id))
        
        conn.close()
        return render_template('chat.html', users=users, inboxes=inboxes, selected_inbox_id=inbox_id, private_chats=verified_private_chats, public_chats=verified_public_chats, files=files, role=session['role'])
    except Exception as e:
        logger.error(f"Chat route error: {e}", exc_info=True)
        flash(f"Chat error: {str(e)}")
        return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        logger.warning("Attempt to upload file without user_id in session")
        return redirect(url_for('login'))
    try:
        file = request.files['file']
        receiver_id = request.form['receiver_id']
        if file:
            filename = secure_filename(file.filename)
            file_content = file.read()
            logger.debug(f"Uploading file {filename} to {receiver_id}")
            conn = sqlite3.connect('pki_chat.db')
            c = conn.cursor()
            c.execute("SELECT public_key FROM users WHERE id = ?", (receiver_id,))
            public_key_pem = c.fetchone()[0]
            public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
            encrypted_content, encrypted_aes_key = encrypt_file(file_content, public_key)
            private_key = serialization.load_pem_private_key(session['private_key'].encode(), password=None, backend=default_backend())
            signature = sign_data(filename, private_key)
            c.execute("INSERT INTO files (sender_id, receiver_id, filename, encrypted_content, encrypted_aes_key, signature) VALUES (?, ?, ?, ?, ?, ?)",
                      (session['user_id'], receiver_id, filename, encrypted_content, encrypted_aes_key, signature))
            conn.commit()
            conn.close()
            logger.info(f"File {filename} uploaded successfully")
            flash('File uploaded successfully')
        else:
            flash('No file selected')
    except Exception as e:
        logger.error(f"File upload failed: {e}")
        flash(f"File upload error: {str(e)}")
    return redirect(url_for('chat'))

@app.route('/download/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        logger.warning("Attempt to download file without user_id in session")
        return redirect(url_for('login'))
    try:
        conn = sqlite3.connect('pki_chat.db')
        c = conn.cursor()
        c.execute("SELECT filename, encrypted_content, encrypted_aes_key, signature, sender_id FROM files WHERE id = ?", (file_id,))
        file_data = c.fetchone()
        if not file_data:
            flash('File not found')
            return redirect(url_for('chat'))
        filename, encrypted_content, encrypted_aes_key, signature, sender_id = file_data
        c.execute("SELECT public_key FROM users WHERE id = ?", (sender_id,))
        public_key_pem = c.fetchone()[0]
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
        if not verify_signature(filename, signature, public_key):
            flash('Invalid file signature')
            return redirect(url_for('chat'))
        private_key = serialization.load_pem_private_key(session['private_key'].encode(), password=None, backend=default_backend())
        decrypted_content = decrypt_file(encrypted_content, encrypted_aes_key, private_key)
        conn.close()
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(temp_path, 'wb') as f:
            f.write(decrypted_content)
        logger.info(f"File {filename} downloaded successfully")
        return send_file(temp_path, as_attachment=True)
    except Exception as e:
        logger.error(f"File download failed: {e}")
        flash(f"File download error: {str(e)}")
        return redirect(url_for('chat'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
