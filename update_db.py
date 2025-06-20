import sqlite3

conn = sqlite3.connect('pki_chat.db')
c = conn.cursor()
c.execute("ALTER TABLE files ADD COLUMN encrypted_aes_key BLOB")
conn.commit()
conn.close()
print("Database updated successfully")