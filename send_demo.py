import socket, time, json, base64, hashlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA512, SHA256
from Crypto import Random

# Load keys
with open('keys/sender_priv.pem','rb') as f:
    sender_priv = RSA.import_key(f.read())
with open('keys/receiver_pub.pem','rb') as f:
    recv_pub = RSA.import_key(f.read())

# Handshake
s = socket.create_connection(('127.0.0.1', 9999))
s.sendall(b"Hello!")
assert s.recv(5) == b"Ready!"

# Create SessionKey and IV
session_key = Random.get_random_bytes(16)
iv = Random.get_random_bytes(16)

# Sign metadata (filename|timestamp|ID)
metadata = f"medical_record.txt|{int(time.time())}|RECORD123"
h_meta = SHA512.new(metadata.encode())
signature = pss.new(sender_priv).sign(h_meta)
sig_b64 = base64.b64encode(signature).decode()

# Encrypt session_key with RSA-OAEP
cipher_rsa = PKCS1_OAEP.new(recv_pub, hashAlgo=SHA512)
enc_key = base64.b64encode(cipher_rsa.encrypt(session_key)).decode()

# Hash password
pwd = "matkhau123"
pwd_hash = SHA256.new(pwd.encode()).hexdigest()

# Send header JSON
header = json.dumps({
    "enc_key": enc_key,
    "sig": sig_b64,
    "pwd": pwd_hash
}).encode()
s.sendall(len(header).to_bytes(4,'big') + header)

# Encrypt file and compute integrity hash
with open('medical_record.txt','rb') as f: data=f.read()
pad_len = 16 - len(data)%16
data += bytes([pad_len])*pad_len
aes = AES.new(session_key, AES.MODE_CBC, iv)
cipher = aes.encrypt(data)
h_all = SHA512.new(iv + cipher).hexdigest()

# Send payload JSON
payload = json.dumps({
    "iv": base64.b64encode(iv).decode(),
    "cipher": base64.b64encode(cipher).decode(),
    "hash": h_all
}).encode()
s.sendall(len(payload).to_bytes(4,'big') + payload)

s.close()
print("[+] Gửi thành công.")