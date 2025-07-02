import json
import socket
import asyncio
import os
from protocol import *
from crypto_stack import decrypt_message, encrypt_message

CONFIG_FILE = "config.json"

DEFAULT_CONFIG = {
    "server_ip": "127.0.0.1",
    "server_http_port": 8000,
    "server_udp_ports": [9000, 9001],
    "protocol": "arp",
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

async def forward_and_respond(payload: bytes, config):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        s.bind(('127.0.0.1', 9999))
        while True:
            try:
                s.sendto(payload, (config['outbound_target'], config['outbound_port']))
                print(f"[→] Переслано в {config['outbound_target']}:{config['outbound_port']}: {payload}")
                break
            except socket.error as e:
                print(f"[!] Ошибка отправки: {e}, повторная попытка...")
                await asyncio.sleep(1)
        s.sendto(payload, (config['outbound_target'], config['outbound_port']))
        print(f"[→] Переслано в {config['outbound_target']}:{config['outbound_port']}: {payload}")
        resp, _ = s.recvfrom(config['buffer_size'])
        print(f"[←] Ответ получен: {resp}")
        return resp
    except Exception as e:
        print(f"[!] Ошибка форвардинга: {e}")
        return b''

async def handle_packet(sock, config, server_url):
    while True:
        data, addr = sock.recvfrom(4096)
        frame_type, payload = parse_frame(data)

        print(f"[📥] Пакет от {addr}, тип: {frame_type}, длина: {len(payload)} байт")

        if frame_type == FRAME_TYPE_DATA:
            try:
                decrypted = await decrypt_message(payload, server_url)
                print(f"[🔓] Расшифровано: {decrypted.encode('utf-8', 'ignore')}")

                response = await forward_and_respond(decrypted.encode('utf-8'), config)

                if response:
                    encrypted = await encrypt_message(response.decode('utf-8', errors='ignore'), server_url)
                    reply = build_frame(FRAME_TYPE_DATA, encrypted)
                    sock.sendto(reply, addr)
                    print(f"[📤] Ответ отправлен клиенту: {addr} (длина {len(reply)} байт)")

            except Exception as e:
                print(f"[!] Ошибка обработки пакета от {addr}: {e}")
        else:
            print(f"[!] Неизвестный тип фрейма: {frame_type} от {addr}")

async def main():
    config = load_or_create_config()
    server_url = f"http://{config['server_ip']}:{config['server_http_port']}"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", config['server_udp_ports'][0]))

    print(f"[🔌] Сервер слушает на UDP {config['server_udp_ports'][0]}")
    print(f"[🌐] API resolver: {server_url}")
    await handle_packet(sock, config, server_url)


if __name__ == "__main__":
    asyncio.run(main())
