# main.py (VPN Client через Wintun с фильтрацией по интерфейсу)
import json, asyncio, socket, os, time, base64, platform, getpass
from crypto_stack import encrypt_message, decrypt_message
from protocol import build_frame, parse_frame, FRAME_TYPE_DATA
import paramiko
from tun import RealInterface

CLIENT_CONFIG = "client_config.json"
SERVER_CONFIG = "server_config.json"


def get_platform_settings(config):
    system = platform.system().lower()
    platform_settings = config.get('platform_settings', {}).get(system, {})
    
    if system == 'windows':
        return {
            'adapter_name': platform_settings.get('adapter_name', 'vpn-l2')
        }
    elif system == 'linux':
        return {
            'interface_name': platform_settings.get('interface_name', 'vpn0')
        }
    else:
        raise RuntimeError(f"Unsupported platform: {platform.system()}")


def generate_config_and_send_to_vps():
    if os.path.exists(CLIENT_CONFIG):
        return

    print("Конфиг не найден. Генерирую...")
    secret_key = base64.b64encode(os.urandom(32)).decode()
    server_ip = input("Введите IP-адрес VPS-сервера: ").strip()
    ssh_port = input("Введите SSH-порт (Enter для 22): ").strip()
    ssh_port = int(ssh_port) if ssh_port else 22
    ssh_user = input("Имя пользователя на VPS: ").strip()
    ssh_password = getpass.getpass("Введите пароль от VPS: ").strip()
    server_http_port = 8000
    server_udp_ports = [5555]

    # Add platform-specific settings
    platform_settings = {
        'windows': {
            'adapter_name': 'vpn-l2'
        },
        'linux': {
            'interface_name': 'vpn0'
        }
    }

    client_config = {
        "server_ip": server_ip,
        "server_http_port": server_http_port,
        "server_udp_ports": server_udp_ports,
        "secret_key": secret_key,
        "platform_settings": platform_settings
    }

    server_config = {
        "server_ip": "0.0.0.0",
        "server_http_port": server_http_port,
        "server_udp_ports": server_udp_ports,
        "secret_key": secret_key,
        "platform_settings": platform_settings
    }

    with open(CLIENT_CONFIG, "w") as f:
        json.dump(client_config, f, indent=2)
    with open(SERVER_CONFIG, "w") as f:
        json.dump(server_config, f, indent=2)

    print("Отправка server_config.json на VPS...")
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(server_ip, port=ssh_port, username=ssh_user, password=ssh_password)
        sftp = ssh.open_sftp()
        sftp.put(SERVER_CONFIG, "server_config.json")
        sftp.close()
        ssh.close()
        print("server_config.json успешно отправлен.")
    except Exception as e:
        print("Ошибка при отправке на VPS:", e)
        exit(1)


def load_config():
    with open(CLIENT_CONFIG) as f:
        return json.load(f)


# Используем Wintun для создания виртуального интерфейса
async def send_loop(interface, sock, config, server_url):
    while True:
        try:
            packet = interface.consume()
            if not packet:
                await asyncio.sleep(0.1)
                continue

            encrypted = await encrypt_message(packet, server_url)
            frame = build_frame(FRAME_TYPE_DATA, encrypted)
            sock.sendto(frame, (config["server_ip"], config["server_udp_ports"][0]))
            print(f"→ Отправлен VPN-фрейм {len(frame)} байт")
        except Exception as e:
            print("Ошибка send_loop:", e)
            await asyncio.sleep(0.1)


async def recv_loop(interface, sock, config, server_url):
    loop = asyncio.get_running_loop()
    while True:
        try:
            data, _ = await loop.sock_recvfrom(sock, 4096)
            frame_type, payload = parse_frame(data)
            if frame_type != FRAME_TYPE_DATA:
                continue

            decrypted = await decrypt_message(payload, server_url)
            if decrypted:
                interface.inject(decrypted)
                print(f"← Иньекция ответа: {len(decrypted)} байт")
        except Exception as e:
            print("Ошибка recv_loop:", e)
            await asyncio.sleep(0.1)


async def main():
    generate_config_and_send_to_vps()
    config = load_config()
    server_url = f"http://{config['server_ip']}:{config['server_http_port']}"
    
    platform_settings = get_platform_settings(config)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', 0))
    sock.setblocking(False)

    print(f"Запуск VPN клиента на {platform.system()}")
    interface = RealInterface(
        iface_hint=platform_settings.get('interface_name') or platform_settings.get('adapter_name'),
        is_client=True
    )
    
    try:
        await asyncio.gather(
            send_loop(interface, sock, config, server_url),
            recv_loop(interface, sock, config, server_url)
        )
    finally:
        del interface

if __name__ == "__main__":
    asyncio.run(main())
