import json, socket, asyncio, os
from tun import RealInterface
from protocol import build_frame, parse_frame, FRAME_TYPE_DATA
from crypto_stack import decrypt_message, encrypt_message

CONFIG_FILE = "config.json"

def load_config():
    with open(CONFIG_FILE) as f:
        return json.load(f)

async def handle_packet(sock, config, tun, server_url):
    while True:
        data, addr = sock.recvfrom(4096)
        frame_type, payload = parse_frame(data)

        if frame_type == FRAME_TYPE_DATA:
            decrypted = await decrypt_message(payload, server_url)
            tun.inject(decrypted)

            # ждём ответ
            response = None
            for _ in range(100):
                response = tun.consume()
                if response:
                    break
                await asyncio.sleep(0.01)

            if response:
                encrypted = await encrypt_message(response, server_url)
                reply = build_frame(FRAME_TYPE_DATA, encrypted)
                sock.sendto(reply, addr)

async def main():
    config = load_config()
    tun = RealInterface(iface_hint=config.get("server_iface", None))
    server_url = f"http://{config['server_ip']}:{config['server_http_port']}"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", config['server_udp_ports'][0]))

    await handle_packet(sock, config, tun, server_url)

if __name__ == "__main__":
    asyncio.run(main())
