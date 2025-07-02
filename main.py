import json
import asyncio
import socket
import os
from protocol import *
from crypto_stack import encrypt_message, decrypt_message
from tun import RealInterfaceStub  # или FakeTun
from concurrent.futures import ThreadPoolExecutor

CONFIG_FILE = "config.json"

DEFAULT_CONFIG = {
    "server_ip": "127.0.0.1",
    "server_http_port": 8000,
    "server_udp_ports": [9000, 9001],
    "protocol": "custom",
    "ethertype": 2054,
    "buffer_size": 2048,
    "outbound_target": "8.8.8.8",
    "outbound_port": 53
}

def load_or_create_config():
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        print("[*] Конфигурация создана: config.json")
    with open(CONFIG_FILE) as f:
        return json.load(f)

async def send_loop(sock, config, server_url, tun):
    print(f"[DEBUG] send_loop tun id = {id(tun)}")
    print("[SEND_LOOP] Запущен")
    while True:
        data = tun.consume()
        if not data:
            print("[SEND_LOOP] Жду данных...")
            await asyncio.sleep(10)
            continue

        print(f"[📝] Данные от tun.consume(): {data}")

        encrypted = await encrypt_message(data.decode('utf-8', errors='ignore'), server_url)
        print(f"[🔐] Зашифровано: {encrypted[:20].hex()}... длина: {len(encrypted)}")

        frame = build_frame(FRAME_TYPE_DATA, encrypted)
        print(f"[📦] Построен фрейм: {frame[:20].hex()}... длина: {len(frame)}")

        for port in config['server_udp_ports']:
            target = (config['server_ip'], port)
            sock.sendto(frame, target)
            print(f"[🚀] Отправлено на {target}")

async def recv_loop(sock, tun, server_url):
    loop = asyncio.get_running_loop()
    while True:
        try:
            data, addr = await loop.sock_recvfrom(sock, 4096)
            print(f"[📥] Получено от {addr}, длина: {len(data)} байт")

            frame_type, payload = parse_frame(data)
            print(f"[📖] Фрейм: тип {frame_type}, полезная нагрузка {len(payload)} байт")

            if frame_type == FRAME_TYPE_DATA:
                decrypted = await decrypt_message(payload, server_url)
                print(f"[🔓] Расшифровка: {decrypted}")
                tun.inject(decrypted.encode('utf-8'))

        except Exception as e:
            print(f"[!] Ошибка получения: {e}")

def blocking_input():
    return input(">>> ").strip()

async def input_loop(tun):
    loop = asyncio.get_running_loop()
    executor = ThreadPoolExecutor(1)

    while True:
        msg = await loop.run_in_executor(executor, blocking_input)
        if msg:
            print(f"[⌨️] Ввод: {msg}")
            tun.write(msg.encode('utf-8'))
            
async def main():
    config = load_or_create_config()
    server_url = f"http://{config['server_ip']}:{config['server_http_port']}"
    tun = RealInterfaceStub()  # ← один и только один объект
    print(f"[DEBUG] tun id = {id(tun)}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', 0))
    sock.setblocking(False)

    print(f"[🌐] Клиент запускается. Сервер: {server_url}, UDP: {config['server_udp_ports']}")
    await asyncio.gather(
        send_loop(sock, config, server_url, tun),   # ← передаём тот же tun
        recv_loop(sock, tun, server_url),
        input_loop(tun)
    )

if __name__ == "__main__":
    asyncio.run(main())
