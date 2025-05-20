import socket
import struct
import os
import threading
from Crypto.Cipher import AES

# --- Cấu hình ---
LISTEN_PORT = 6000
REMOTE_IP = '172.16.0.69'  # Thay bằng IP của bên kia
REMOTE_PORT = 6000

# --- Padding / Unpadding ---
def pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len

def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]

# --- Nhận tin nhắn ---
def receive_messages():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', LISTEN_PORT))
        s.listen(1)
        print(f"[+] Đang lắng nghe tại cổng {LISTEN_PORT}...")
        while True:
            conn, addr = s.accept()
            with conn:
                try:
                    header = conn.recv(36)
                    key = header[:16]
                    iv = header[16:32]
                    length = struct.unpack('!I', header[32:])[0]
                    ciphertext = conn.recv(length)
                    aes = AES.new(key, AES.MODE_CBC, iv)
                    plaintext = unpad(aes.decrypt(ciphertext))
                    print(f"\n[Nhận từ {addr[0]}] {plaintext.decode('utf-8')}")
                except Exception as e:
                    print("[!] Lỗi giải mã:", e)

# --- Gửi tin nhắn ---
def send_messages():
    while True:
        plain = input("[Gửi] > ").strip().encode('utf-8')
        key = os.urandom(16)
        iv = os.urandom(16)
        aes = AES.new(key, AES.MODE_CBC, iv)
        cipher_bytes = aes.encrypt(pad(plain))
        packet = key + iv + struct.pack('!I', len(cipher_bytes)) + cipher_bytes
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((REMOTE_IP, REMOTE_PORT))
                s.sendall(packet)
        except Exception as e:
            print("[!] Không gửi được:", e)

# --- Khởi động ---
if __name__ == '__main__':
    threading.Thread(target=receive_messages, daemon=True).start()
    send_messages()
