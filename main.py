import json, asyncio, socket, os
from tun import RealInterface
from protocol import build_frame, parse_frame, FRAME_TYPE_DATA
from crypto_stack import encrypt_message, decrypt_message
import time

CONFIG_FILE = "config.json"

def load_config():
    with open(CONFIG_FILE) as f:
        return json.load(f)


async def send_loop(sock, config, server_url, tun):
    last_send = time.monotonic()
    while True:
        packet = tun.consume()
        now = time.monotonic()

        # Heartbeat
        if not packet and now - last_send > 5.0:
            frame = build_frame(FRAME_TYPE_DATA, b'\x00PING')
            sock.sendto(frame, (config['server_ip'], config['server_udp_ports'][0]))
            print("Отправлен heartbeat (PING)")
            last_send = now
            await asyncio.sleep(1.0)
            continue

        if not packet:
            await asyncio.sleep(0.1)
            continue

        encrypted = await encrypt_message(packet, server_url)
        frame = build_frame(FRAME_TYPE_DATA, encrypted)

        for port in config['server_udp_ports']:
            sock.sendto(frame, (config['server_ip'], port))
            print(f"Отправлен фрейм ({len(frame)} байт) на порт {port}")
        last_send = now

async def recv_loop(sock, tun, server_url):
    loop = asyncio.get_running_loop()
    while True:
        try:
            data, _ = await loop.sock_recvfrom(sock, 4096)
        except ConnectionResetError as e:
            print("Соединение сброшено сервером:", e)
            await asyncio.sleep(1.0)
            continue

        print(f"← Получен пакет: {len(data)} байт")
        try:
            frame_type, payload = parse_frame(data)
            if frame_type == FRAME_TYPE_DATA:
                decrypted = await decrypt_message(payload, server_url)
                tun.inject(decrypted)
        except Exception as e:
            print("Ошибка при обработке входящего пакета:", e)

async def main():
    config = load_config()
    tun = RealInterface()
    server_url = f"http://{config['server_ip']}:{config['server_http_port']}"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', 0))
    sock.setblocking(False)

    await asyncio.gather(
        send_loop(sock, config, server_url, tun),
        recv_loop(sock, tun, server_url)
    )

if __name__ == "__main__":
    asyncio.run(main())
