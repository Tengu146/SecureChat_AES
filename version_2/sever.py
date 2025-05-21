
import asyncio
import websockets
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

clients = set()

def pad(s):
    pad_len = 16 - (len(s) % 16)
    return s + chr(pad_len) * pad_len

def unpad(s):
    return s[:-ord(s[-1])]

def aes_encrypt(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext).encode('utf-8'))
    return base64.b64encode(ct).decode()

def aes_decrypt(key, iv, ciphertext_b64):
    ct = base64.b64decode(ciphertext_b64)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct).decode('utf-8')
    return unpad(pt)

key = get_random_bytes(16)
iv = get_random_bytes(16)

async def handler(websocket):
    clients.add(websocket)
    print("Client connected.")
    try:
        async for msg in websocket:
            data = json.loads(msg)
            plain = data["message"]
            cipher = aes_encrypt(key, iv, plain)

            for client in clients:
                await client.send(json.dumps({
                    "cipher": cipher,
                    "iv": base64.b64encode(iv).decode(),
                    "key": base64.b64encode(key).decode(),
                    "sender": data["sender"]
                }))
    except Exception as e:
        print("Error:", e)
    finally:
        clients.remove(websocket)
        print("Client disconnected.")

async def main():
    async with websockets.serve(handler, "0.0.0.0", 8765):
        print("Server running on ws://0.0.0.0:8765")
        await asyncio.Future()

asyncio.run(main())
