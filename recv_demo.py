import socket, json, base64, sys, time, hashlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA512, SHA256

# Load keys
with open('keys/receiver_priv.pem','rb') as f:
    recv_priv = RSA.import_key(f.read())
with open('keys/sender_pub.pem','rb') as f:
    sender_pub = RSA.import_key(f.read())

# Handshake
srv = socket.socket(); srv.bind(('0.0.0.0',9999)); srv.listen(1)
conn, _ = srv.accept()
assert conn.recv(5) == b"Hello!"
conn.sendall(b"Ready!")

# Receive header
size = int.from_bytes(conn.recv(4),'big')
hdr = json.loads(conn.recv(size))
enc_key = base64.b64decode(hdr["enc_key"])
sig = base64.b64decode(hdr["sig"])
pwd_hash = hdr["pwd"]

# Decrypt session_key
try:
    session_key = PKCS1_OAEP.new(recv_priv, hashAlgo=SHA512).decrypt(enc_key)
except Exception as e:
    print("[!] Lỗi giải mã RSA:", e); sys.exit(1)

# Password check
pw = input("Nhập mật khẩu: ")
if SHA256.new(pw.encode()).hexdigest() != pwd_hash:
    print("[!] Mật khẩu sai"); sys.exit(1)

# Receive payload
size = int.from_bytes(conn.recv(4),'big')
data = json.loads(conn.recv(size))
iv = base64.b64decode(data["iv"])
cipher = base64.b64decode(data["cipher"])
h_recv = data["hash"]

# Integrity check
if SHA512.new(iv+cipher).hexdigest() != h_recv:
    print("[!] Sai tính toàn vẹn"); sys.exit(1)

# (Optional) Verify signature here using metadata and sig

# Decrypt AES-CBC
aes = AES.new(session_key, AES.MODE_CBC, iv)
plain = aes.decrypt(cipher)
pad = plain[-1]; plain = plain[:-pad]
with open('medical_record_decrypted.txt','wb') as f:
    f.write(plain)

print("[+] Đã giải mã và lưu medical_record_decrypted.txt")
conn.close()