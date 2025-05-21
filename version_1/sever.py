import asyncio
import websockets
import json
import base64
from Crypto.Cipher import AES
import http

# Khóa AES cứng (32 byte)
AES_KEY = bytes([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
])

# Giải mã AES (AES-256-CBC)
def aes_decrypt(key, iv, ciphertext):
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv=base64.b64decode(iv))
        pt = cipher.decrypt(base64.b64decode(ciphertext))
        padding_len = pt[-1]
        if padding_len < 1 or padding_len > 16:
            raise ValueError("Padding không hợp lệ")
        return pt[:-padding_len].decode('utf-8')
    except Exception as e:
        print(f"Lỗi giải mã AES: {e}")
        raise ValueError(f"Lỗi giải mã: {e}")

# Tập hợp các client đang kết nối
connected_clients = set()

# Xử lý các yêu cầu HTTP không hợp lệ
async def process_request(path, request_headers):
    if path == "/favicon.ico":
        return http.HTTPStatus.NOT_FOUND, [], b"Not Found"
    # Truy cập header Connection qua request_headers.headers
    connection = request_headers.headers.get("Connection", "").lower()
    if "upgrade" not in connection:
        return http.HTTPStatus.BAD_REQUEST, [], b"This is a WebSocket server. Please use a WebSocket client."
    return None

# Xử lý kết nối WebSocket
async def handler(websocket):
    connected_clients.add(websocket)
    try:
        async for message in websocket:
            print(f"Nhận tin nhắn gốc: {message}")
            try:
                # Phân tích tin nhắn JSON
                message_data = json.loads(message)
                if 'iv' not in message_data or 'cipher' not in message_data:
                    raise ValueError("Tin nhắn thiếu trường 'iv' hoặc 'cipher'")
                
                iv = message_data['iv']
                encrypted_message = message_data['cipher']
                
                # Giải mã tin nhắn (chỉ để ghi log)
                decrypted_message = aes_decrypt(AES_KEY, iv, encrypted_message)
                print(f"Tin nhắn giải mã: {decrypted_message}")
                
                # Chuyển tiếp tin nhắn đến các client khác
                for client in connected_clients:
                    if client != websocket:
                        try:
                            await client.send(message)
                        except websockets.exceptions.ConnectionClosed:
                            print("Client đã ngắt kết nối, bỏ qua...")
            except json.JSONDecodeError as e:
                print(f"Lỗi phân tích JSON: {e}")
            except ValueError as e:
                print(f"Lỗi dữ liệu: {e}")
            except Exception as e:
                print(f"Lỗi xử lý tin nhắn: {e}")
    except websockets.exceptions.ConnectionClosed as e:
        print(f"Client ngắt kết nối: {e}")
    finally:
        connected_clients.remove(websocket)

# Khởi động server WebSocket
async def start_server():
    server = await websockets.serve(handler, "localhost", 8765, process_request=process_request)
    print("Server khởi động tại ws://localhost:8765")
    await server.wait_closed()

# Chạy server
if __name__ == "__main__":
    asyncio.run(start_server())