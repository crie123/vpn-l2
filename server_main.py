# server_main.py - Server implementation with teeth-gnashing crypto library
import json, socket, asyncio, os, threading, time, base64, platform, sys, subprocess, atexit
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from protocol import build_frame, parse_frame, FRAME_TYPE_DATA, fragment_payload
import uvicorn

# Import teeth-gnashing server components
try:
    from teeth_gnashing.server import ServerConfig, ServerState, sign_snapshot, load_config, state, config
    from teeth_gnashing.server import app as teeth_app
except ImportError:
    # Fallback: Import and create app manually
    print("Warning: Could not import teeth-gnashing server components directly")
    print("Creating FastAPI server manually...")
    
    teeth_app = None

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

class HandshakeRequest(BaseModel):
    hash: str

def load_server_config(config_path: str = "server_config.json") -> dict:
    """Load server configuration from JSON file."""
    if not os.path.exists(config_path):
        print(f"❌ {config_path} не найден. Завершение.")
        exit(1)
    with open(config_path) as f:
        config_data = json.load(f)
    if "secret_key" not in config_data:
        print("❌ Нет ключа 'secret_key' в конфиге.")
        exit(1)
    return config_data

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


server_config = load_server_config(CONFIG_FILE)
SECRET_KEY = base64.b64decode(server_config["secret_key"])

# Shared state for server
class ServerStateManager:
    def __init__(self):
        self.tick = 0
        self.seed = int(time.time()) % (1 << 30)
        self.authenticated_hashes = set()
        self._lock = threading.Lock()
    
    def increment_tick(self):
        with self._lock:
            self.tick = (self.tick + 1) % (1 << 31)
            if self.tick % 100 == 0:
                self.seed = int(time.time()) % (1 << 30)
    
    def add_hash(self, hash_value: str):
        with self._lock:
            self.authenticated_hashes.add(hash_value)

server_state = ServerStateManager()

def sign_snapshot_local(tick: int, seed: int, timestamp: int) -> str:
    """Sign snapshot with HMAC-SHA256."""
    import hmac
    import hashlib
    message = f"{tick}|{seed}|{timestamp}".encode()
    sig = hmac.new(SECRET_KEY, message, hashlib.sha256).digest()
    return base64.b64encode(sig).decode()

@app.post("/handshake")
async def handshake(req: HandshakeRequest):
    h = req.hash.lower()
    if not h or len(h) != 64:
        return {"status": "invalid"}
    try:
        bytes.fromhex(h)
        server_state.add_hash(h)
        return {"status": "ok"}
    except ValueError:
        return {"status": "invalid"}

@app.get("/snapshot")
async def get_snapshot():
    timestamp = int(time.time())
    signature = sign_snapshot_local(server_state.tick, server_state.seed, timestamp)
    return {
        "tick": server_state.tick,
        "seed": server_state.seed,
        "timestamp": timestamp,
        "signature": signature
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": int(time.time()),
        "tick": server_state.tick,
        "authenticated_clients": len(server_state.authenticated_hashes)
    }

def start_tick_thread():
    def update_tick():
        while True:
            server_state.increment_tick()
            time.sleep(server_config.get('tick_interval', 1.0))
    threading.Thread(target=update_tick, daemon=True).start()


def setup_routing(interface_ip):
    if platform.system() == "Windows":
        # Delete old route if exists
        subprocess.call([
            "powershell", "-Command",
            f"$route = Get-NetRoute -DestinationPrefix 0.0.0.0/0 -InterfaceAlias 'vpn-l2' -ErrorAction SilentlyContinue; "
            f"if ($route) {{ Remove-NetRoute -DestinationPrefix 0.0.0.0/0 -InterfaceAlias 'vpn-l2' -Confirm:$false }}"
        ])

        # Delete old IP if exists
        subprocess.call([
            "powershell", "-Command",
            f"$ip = Get-NetIPAddress -InterfaceAlias 'vpn-l2' -AddressFamily IPv4 -ErrorAction SilentlyContinue; "
            f"if ($ip) {{ $ip | Remove-NetIPAddress -Confirm:$false }}"
        ])

        # Assign new IP address
        subprocess.call([
            "powershell", "-Command",
            f"New-NetIPAddress -InterfaceAlias 'vpn-l2' -IPAddress {interface_ip} -PrefixLength 16 -SkipAsSource $true"
        ])

        # Add default route
        subprocess.call([
            "powershell", "-Command",
            f"New-NetRoute -DestinationPrefix 0.0.0.0/0 -InterfaceAlias 'vpn-l2' -NextHop 0.0.0.0 -Publish Yes"
        ])

        # Delete old route on exit
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
            # Turn on IP forwarding in registry
            subprocess.call([
                "powershell", "-Command",
                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -Name 'IPEnableRouter' -Value 1"
            ])
            # Turn on IP forwarding for the interface
            subprocess.call([
                "powershell", "-Command",
                "Set-NetIPInterface -InterfaceAlias 'vpn-l2' -Forwarding Enabled"
            ])

            # Create NAT if it doesn't exist
            subprocess.call([
                "powershell", "-Command",
                "if (-not (Get-NetNat | Where-Object { $_.Name -eq 'VpnNat' })) { "
                "New-NetNat -Name 'VpnNat' -InternalIPInterfaceAddressPrefix '10.0.0.0/24' }"
            ])
            print("NAT и IP маршрутизация настроены (Windows)")
        except Exception as e:
            print(f"Ошибка NAT/forwarding (Windows): {e}")
    elif system == "Linux":
        try:
            # Turn on IP forwarding
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
            # Add NAT rule
            subprocess.call(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE"])
            print("NAT и IP маршрутизация настроены (Linux)")
        except Exception as e:
            print(f"Ошибка NAT/forwarding (Linux): {e}")



async def packet_processor(sock, config):
    """Main packet processing loop."""
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

                # For now, we're just forwarding packets
                # In a full implementation, you'd decrypt using teeth-gnashing client
                try:
                    interface.inject(payload)
                    print(f"Инъекция {len(payload)} байт")
                except Exception as e:
                    print(f"Ошибка инъекции: {e}")

                for _ in range(20):
                    response = interface.consume()
                    if response:
                        for part in fragment_payload(response):
                            reply = build_frame(FRAME_TYPE_DATA, part)
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
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**20)
        sock.bind(("0.0.0.0", server_config['server_udp_ports'][0]))
        await packet_processor(sock, server_config)

    asyncio.run(_run())


if __name__ == "__main__":
    try:
        print(f"Starting FastAPI server on port {server_config['server_http_port']}")

        start_tick_thread()
        processor_thread = threading.Thread(target=run_packet_processor, daemon=True)
        processor_thread.start()

        uvicorn.run(
            app,
            host="0.0.0.0",
            port=server_config["server_http_port"],
            log_level="info"
        )
    except KeyboardInterrupt:
        print("\nShutting down server...")
