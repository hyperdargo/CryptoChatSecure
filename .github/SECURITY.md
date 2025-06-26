Below is a **comprehensive breakdown** of what each part of your `Flask` + `PKI-based Secure Chat App` code does:

---

### 🔧 **Imports**

```python
from flask import Flask, request, session, ...
from cryptography.hazmat.primitives import ...
from Crypto.Cipher import AES
...
```

* Flask: Web framework to handle routing, sessions, file uploads.
* Cryptography & PyCrypto: Used for asymmetric (RSA) and symmetric (AES) encryption, certificate generation, signing, and verifying.
* SQLite3: Lightweight database for storing users, messages, files.
* `os`, `io`, `secrets`, `logging`: For file management, generating tokens, logging, and in-memory file handling.

---

### 🚀 **App Setup**

```python
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
UPLOAD_FOLDER = 'Uploads'
...
```

* Initializes Flask app.
* Generates a random secret key for session security.
* Creates a folder to store uploaded files (if not already exists).
* Configures logging.

---

### 🔐 **CA Key Generation**

```python
ca_private_key = rsa.generate_private_key(...)
```

* Creates a **Certificate Authority (CA)** private/public key for issuing certificates to users.

---

### 🗃️ **Database Initialization**

```python
def init_db():
```

* Creates 3 tables:

  1. `users`: Stores username, role, public key, certificate.
  2. `chats`: Stores chat messages (sender, receiver, message, timestamp, signature).
  3. `files`: Stores encrypted files (with encrypted AES key), filename, sender/receiver.

---

### 🔑 **Key & Certificate Handling**

#### `generate_key_pair_and_cert(username)`

* Generates user’s RSA key pair.
* Creates a self-signed certificate for the user, signed by the CA.

#### `verify_certificate(cert)`

* Verifies the certificate's signature using the CA’s public key.

#### `get_certificate_details(cert)`

* Extracts details like subject, issuer, validity period, and serial number from the certificate.

---

### ✍️ **Digital Signing & Verification**

#### `sign_data(data, private_key)`

* Signs the `data` (message or filename) using user’s private key (PKCS#1 v1.5 + SHA-256).

#### `verify_signature(data, signature, public_key)`

* Verifies that the signature matches the data using the public key.

---

### 🔒 **File Encryption & Decryption**

#### `encrypt_file(file_content, public_key)`

* Encrypts the file content using AES.
* Encrypts the AES key using the receiver’s RSA public key.

#### `decrypt_file(...)`

* Decrypts AES key using the user’s private key.
* Decrypts file content using AES.

---

### 🔧 **Jinja2 Custom Filter**

```python
def starts_with_filter(...)
```

* Adds a custom filter `starts_with` for template use (e.g., to check if strings start with a prefix).

---

### 📃 **Flask Routes Overview**

---

### `/` ➝ `index()`

* Renders the homepage (e.g., links to login/register).

---

### `/register` ➝ `register()`

* GET: Displays registration form.
* POST:

  * Gets username & role from form.
  * Checks for existing user.
  * Generates keys and certificate.
  * Stores public key and certificate in DB.
  * Saves private key and certificate in session (for further use).
  * Redirects to `/show_key`.

---

### `/show_key`

* Displays:

  * User’s private key
  * Certificate PEM
  * Parsed certificate details.

---

### `/download_cert`

* Sends user’s certificate as a `.pem` download.

---

### `/login` ➝ `login()`

* GET: Renders login form.
* POST:

  * Accepts username and pasted private key PEM.
  * Reconstructs public key and validates against DB.
  * Verifies that certificate is valid and matches.
  * Logs user in by saving session values.

---

### `/chat` and `/chat/<inbox_id>` ➝ `chat()`

* Core chat handler.
* GET:

  * Loads all private/public chats and related users.
  * Verifies signatures and certificates for integrity.
  * Groups private chats per user.
* POST:

  * Sends message:

    * Signs it with private key.
    * Inserts into DB (private/public depending on form).
* DELETE:

  * Deletes a message if sender matches session user.

---

### `/upload` ➝ `upload_file()`

* Accepts file upload.
* Encrypts the file using:

  * AES for content.
  * RSA (receiver's key) for the AES key.
* Signs the filename using sender's private key.
* Stores encrypted file in the DB.

---

### `/download/<int:file_id>` ➝ `download_file()`

* Retrieves file by ID.
* Verifies signature using sender’s public key.
* Decrypts AES key and content.
* Returns file to user.

---

### 🔚 `if __name__ == '__main__'`

```python
app.run(host='0.0.0.0', port=25569, debug=True)
```

* Starts the Flask development server on port `25569`.

---

### ✅ **Features Summary**

| Feature             | Description                                                   |
| ------------------- | ------------------------------------------------------------- |
| 🧾 Registration     | Generates private key, certificate, saves them securely       |
| 🔐 PKI Auth         | Validates users by key and certificate                        |
| 💬 Chat             | Private and public messages with digital signature validation |
| 📁 File Sharing     | Encrypted file transfer with signature & key wrapping         |
| 🧾 Certificate Mgmt | View/download PEM certificate                                 |
| ✅ Integrity         | All messages and files signed and verified                    |

---

### **Flow diagram**

![image](https://github.com/user-attachments/assets/8f4953c0-1bdd-4e74-a9a6-4774cc912970)

