# server_main.py (Wintun-only через указанный интерфейс)
import json, socket, asyncio, os, threading, time, random, hashlib, hmac, base64, platform, sys, subprocess, atexit
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from protocol import build_frame, parse_frame, FRAME_TYPE_DATA
from crypto_stack import decrypt_message, encrypt_message
import uvicorn

# Import platform-specific interfaces
if platform.system() == 'Windows':
    from iface_win import RealInterface as WindowsInterface
elif platform.system() == 'Linux':
    from iface_linux import RealInterface as LinuxInterface
else:
    raise RuntimeError(f"Unsupported platform: {platform.system()}")

CONFIG_FILE = os.path.join(os.path.dirname(sys.executable), "server_config.json")

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

class Snapshot(BaseModel):
    tick: int
    seed: int
    timestamp: int
    signature: str

class HandshakeRequest(BaseModel):
    hash: str

state = {"tick": 0, "seed": random.randint(1, 1 << 30), "authenticated_hashes": set()}


def load_config():
    if not os.path.exists(CONFIG_FILE):
        print(f"\u274c {CONFIG_FILE} не найден. Завершение.")
        exit(1)
    with open(CONFIG_FILE) as f:
        config = json.load(f)
    if "secret_key" not in config:
        print("\u274c Нет ключа 'secret_key' в конфиге.")
        exit(1)
    return config


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


config = load_config()
SECRET_KEY = base64.b64decode(config["secret_key"])


def sign_snapshot(tick: int, seed: int, timestamp: int) -> str:
    message = f"{tick}|{seed}|{timestamp}".encode()
    sig = hmac.new(SECRET_KEY, message, hashlib.sha256).digest()
    return base64.b64encode(sig).decode()


@app.post("/handshake")
async def handshake(req: HandshakeRequest):
    h = req.hash.lower()
    if not h or len(h) != 32:
        return {"status": "invalid"}
    state["authenticated_hashes"].add(h)
    return {"status": "ok"}


@app.get("/snapshot")
async def get_snapshot(request: Request):
    timestamp = int(time.time())
    tick = state["tick"]
    seed = state["seed"]
    signature = sign_snapshot(tick, seed, timestamp)
    return Snapshot(tick=tick, seed=seed, timestamp=timestamp, signature=signature)


def start_tick_thread():
    def update_tick():
        while True:
            state["tick"] = (state["tick"] + 1) % (1 << 31)
            time.sleep(1.0)
    threading.Thread(target=update_tick, daemon=True).start()


def setup_routing(interface_ip):
    if platform.system() == "Windows":
        # Удалим старый маршрут (если есть)
        subprocess.call([
            "powershell", "-Command",
            f"$route = Get-NetRoute -DestinationPrefix 0.0.0.0/0 -InterfaceAlias 'vpn-l2' -ErrorAction SilentlyContinue; "
            f"if ($route) {{ Remove-NetRoute -DestinationPrefix 0.0.0.0/0 -InterfaceAlias 'vpn-l2' -Confirm:$false }}"
        ])

        # Удалим старый IP (если есть), чтобы не было дубликатов
        subprocess.call([
            "powershell", "-Command",
            f"$ip = Get-NetIPAddress -InterfaceAlias 'vpn-l2' -AddressFamily IPv4 -ErrorAction SilentlyContinue; "
            f"if ($ip) {{ $ip | Remove-NetIPAddress -Confirm:$false }}"
        ])

        # Назначим IP
        subprocess.call([
            "powershell", "-Command",
            f"New-NetIPAddress -InterfaceAlias 'vpn-l2' -IPAddress {interface_ip} -PrefixLength 16 -SkipAsSource $true"
        ])

        # Добавим маршрут
        subprocess.call([
            "powershell", "-Command",
            f"New-NetRoute -DestinationPrefix 0.0.0.0/0 -InterfaceAlias 'vpn-l2' -NextHop 0.0.0.0 -Publish Yes"
        ])

        # Удалим маршрут при завершении
        atexit.register(lambda: subprocess.call([
            "powershell", "-Command",
            f"Remove-NetRoute -DestinationPrefix 0.0.0.0/0 -InterfaceAlias 'vpn-l2' -Confirm:$false"
        ]))

    elif platform.system() == "Linux":
        subprocess.call(["ip", "addr", "flush", "dev", "vpn0"])
        subprocess.call(["ip", "addr", "add", f"{interface_ip}/16", "dev", "vpn0"])
        subprocess.call(["ip", "link", "set", "vpn0", "up"])
        subprocess.call(["ip", "route", "add", "default", "dev", "vpn0"])
        atexit.register(lambda: subprocess.call(["ip", "route", "del", "default", "dev", "vpn0"]))

def setup_nat_and_forwarding():
    system = platform.system()
    if system == "Windows":
        try:
            # Включаем IP маршрутизацию в реестре
            subprocess.call([
                "powershell", "-Command",
                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -Name 'IPEnableRouter' -Value 1"
            ])
            # Включаем IP forwarding через интерфейс
            subprocess.call([
                "powershell", "-Command",
                "Set-NetIPInterface -InterfaceAlias 'vpn-l2' -Forwarding Enabled"
            ])

            # Создаём NAT для подсети 10.0.0.0/24
            subprocess.call([
                "powershell", "-Command",
                "if (-not (Get-NetNat | Where-Object { $_.Name -eq 'VpnNat' })) { "
                "New-NetNat -Name 'VpnNat' -InternalIPInterfaceAddressPrefix '10.0.0.0/24' }"
            ])
            print("[+] NAT и IP маршрутизация настроены (Windows)")
        except Exception as e:
            print(f"[!] Ошибка NAT/forwarding (Windows): {e}")
    elif system == "Linux":
        try:
            # Включаем IP forwarding
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
            # Добавляем iptables правило для NAT
            subprocess.call(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE"])
            print("[+] NAT и IP маршрутизация настроены (Linux)")
        except Exception as e:
            print(f"[!] Ошибка NAT/forwarding (Linux): {e}")



async def packet_processor(sock, config):
    platform_settings = get_platform_settings(config)
    system = platform.system()

    if system == 'Windows':
        interface = WindowsInterface(iface_hint=platform_settings['adapter_name'], is_client=False)
    elif system == 'Linux':
        interface = LinuxInterface(iface_hint=platform_settings['interface_name'], is_client=False)

    print(f"VPN сервер работает на {system}")
    print(f"Используется интерфейс: {platform_settings.get('interface_name') or platform_settings.get('adapter_name')}")

    setup_routing("10.0.0.1")
    setup_nat_and_forwarding()

    try:
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                print("Пакет от", addr, "размер:", len(data))
                frame_type, payload = parse_frame(data)
                if frame_type != FRAME_TYPE_DATA or len(payload) < 32:
                    continue

                server_url = f"http://localhost:{config['server_http_port']}"
                decrypted = await decrypt_message(payload, server_url)
                if decrypted == b'PING':
                    print(f"Heartbeat от {addr}")
                    continue

                try:
                    interface.inject(decrypted)
                    print(f"Инъекция {len(decrypted)} байт")
                except Exception as e:
                    print(f"⚠ Ошибка инъекции: {e}")

                for _ in range(20):
                    response = interface.consume()
                    if response:
                        encrypted = await encrypt_message(response, server_url)
                        reply = build_frame(FRAME_TYPE_DATA, encrypted)
                        sock.sendto(reply, addr)
                        print(f"Ответ отправлен клиенту {addr}")
                        break
                    await asyncio.sleep(0.1)
            except Exception as e:
                print("Ошибка обработки:", e)
                await asyncio.sleep(0.1)
    finally:
        del interface


def run_packet_processor():
    async def _run():
        config = load_config()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**20)
        sock.bind(("0.0.0.0", config['server_udp_ports'][0]))
        await packet_processor(sock, config)

    asyncio.run(_run())


if __name__ == "__main__":
    try:
        config = load_config()
        print(f"Starting FastAPI server on port {config['server_http_port']}")

        start_tick_thread()
        processor_thread = threading.Thread(target=run_packet_processor, daemon=True)
        processor_thread.start()

        uvicorn.run(
            app,
            host="0.0.0.0",
            port=config["server_http_port"],
            log_level="info"
        )
    except KeyboardInterrupt:
        print("\nShutting down server...")
