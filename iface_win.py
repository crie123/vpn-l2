# === iface_win.py (обёртка для Wintun под Windows) ===
import ctypes
import threading
import queue
import time
import os
import sys
from ctypes import wintypes, c_void_p, POINTER, c_wchar_p, c_byte, Structure
import pydivert
import subprocess
from ipaddress import ip_address
import json


# Define GUID structure
class GUID(Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]


# Wintun constants from wintun.h
WINTUN_MIN_RING_CAPACITY = 0x20000  # 128kiB
WINTUN_MAX_RING_CAPACITY = 0x4000000  # 64MiB
WINTUN_MAX_IP_PACKET_SIZE = 0xFFFF


class WintunAdapter:
    def __init__(self, dll_path):
        self.wintun = ctypes.WinDLL(dll_path)

        # Define function prototypes
        self.wintun.WintunCreateAdapter.argtypes = [c_wchar_p, c_wchar_p, POINTER(GUID)]
        self.wintun.WintunCreateAdapter.restype = c_void_p

        self.wintun.WintunStartSession.argtypes = [c_void_p, wintypes.DWORD]
        self.wintun.WintunStartSession.restype = c_void_p

        self.wintun.WintunEndSession.argtypes = [c_void_p]
        self.wintun.WintunEndSession.restype = None

        self.wintun.WintunCloseAdapter.argtypes = [c_void_p]
        self.wintun.WintunCloseAdapter.restype = None

        self.wintun.WintunReceivePacket.argtypes = [c_void_p, POINTER(wintypes.DWORD)]
        self.wintun.WintunReceivePacket.restype = POINTER(c_byte)

        self.wintun.WintunReleaseReceivePacket.argtypes = [c_void_p, POINTER(c_byte)]
        self.wintun.WintunReleaseReceivePacket.restype = None

        self.wintun.WintunAllocateSendPacket.argtypes = [c_void_p, wintypes.DWORD]
        self.wintun.WintunAllocateSendPacket.restype = POINTER(c_byte)

        self.wintun.WintunSendPacket.argtypes = [c_void_p, POINTER(c_byte)]
        self.wintun.WintunSendPacket.restype = None

        self.wintun.WintunGetReadWaitEvent.argtypes = [c_void_p]
        self.wintun.WintunGetReadWaitEvent.restype = wintypes.HANDLE


class RealInterface:
    def __init__(self, iface_hint=None, is_client=False):
        self.packet_queue = queue.Queue()
        self.running = True
        self.is_client = is_client

        try:
            # Load Wintun DLL
            dll_path = os.path.join(os.path.dirname(sys.executable), "wintun.dll")
            self.lib = ctypes.WinDLL(dll_path)
            if not os.path.exists(dll_path):
                raise FileNotFoundError(
                    "wintun.dll не найден. Пожалуйста, скачайте его с https://www.wintun.net"
                )

            self.wintun = WintunAdapter(dll_path)

            # Create adapter
            guid = GUID()
            ctypes.windll.ole32.CoCreateGuid(ctypes.byref(guid))

            self.adapter = self.wintun.wintun.WintunCreateAdapter(
                "vpn-l2", "vpn-l2", ctypes.byref(guid)
            )
            if not self.adapter:
                raise WindowsError(
                    f"Не удалось создать Wintun адаптер: {ctypes.get_last_error()}"
                )

            # Start session with 1MB ring buffer
            self.session = self.wintun.wintun.WintunStartSession(
                self.adapter, WINTUN_MIN_RING_CAPACITY
            )
            if not self.session:
                self.wintun.wintun.WintunCloseAdapter(self.adapter)
                raise WindowsError(
                    f"Не удалось запустить сессию Wintun: {ctypes.get_last_error()}"
                )

            # Get read wait event
            self.read_event = self.wintun.wintun.WintunGetReadWaitEvent(self.session)

            # Initialize WinDivert only for client
            if self.is_client:
                self.windivert = pydivert.WinDivert(
                    "outbound and ip",  # Simplified filter
                    priority=0,
                    layer=pydivert.Layer.NETWORK,
                )
                self.windivert.open()
                print("WinDivert инициализирован для перехвата исходящего трафика")

            print("Wintun адаптер создан успешно")
        except Exception as e:
            print(f"Ошибка создания Wintun адаптера: {e}")
            raise

        # Start packet capture thread
        self.capture_thread = threading.Thread(target=self._capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()

        # Start divert thread only for client
        if self.is_client:
            self.divert_thread = threading.Thread(target=self._divert_packets)
            self.divert_thread.daemon = True
            self.divert_thread.start()

    def _divert_packets(self):
        if not self.is_client:
            return

        while self.running:
            try:
                # Get outbound packets from applications
                packet = self.windivert.recv()
                if packet:
                    # Forward the original packet
                    self.windivert.send(packet)
                    # Also send a copy through our VPN tunnel
                    raw_packet = packet.raw.tobytes()
                    self.packet_queue.put(raw_packet)
            except Exception as e:
                print(f"Ошибка перехвата пакета: {e}")
                time.sleep(0.1)

    def _capture_packets(self):
        packet_size = wintypes.DWORD()

        while self.running:
            try:
                # Wait for data from Wintun adapter
                if (
                    ctypes.windll.kernel32.WaitForSingleObject(self.read_event, 100)
                    == 0
                ):
                    # Read packet from Wintun
                    packet = self.wintun.wintun.WintunReceivePacket(
                        self.session, ctypes.byref(packet_size)
                    )
                    if packet:
                        try:
                            buffer = (c_byte * packet_size.value).from_address(
                                ctypes.cast(packet, ctypes.c_void_p).value
                            )
                            data = bytes(buffer)
                            # Only process incoming VPN packets
                            if data and data[0] & 0xF0 == 0x40:  # IPv4 packet
                                self.packet_queue.put(data)
                        finally:
                            self.wintun.wintun.WintunReleaseReceivePacket(
                                self.session, packet
                            )
            except Exception as e:
                print(f"Ошибка при получении пакета: {e}")
                time.sleep(0.1)

    def inject(self, packet_bytes: bytes):
        try:
            size = len(packet_bytes)
            if size > WINTUN_MAX_IP_PACKET_SIZE:
                raise ValueError(
                    f"Размер пакета {size} превышает максимально допустимый {WINTUN_MAX_IP_PACKET_SIZE}"
                )

            # Allocate packet
            packet = self.wintun.wintun.WintunAllocateSendPacket(self.session, size)
            if packet:
                try:
                    # Copy data to packet buffer
                    ctypes.memmove(packet, packet_bytes, size)
                    # Send packet
                    self.wintun.wintun.WintunSendPacket(self.session, packet)
                    print(f"→ Инжектировано {size} байт в Wintun")
                except Exception as e:
                    # Make sure to release the packet if anything goes wrong
                    raise e
            else:
                raise WindowsError(
                    f"Не удалось выделить память для пакета: {ctypes.get_last_error()}"
                )
        except Exception as e:
            print(f"Ошибка при инъекции: {e}")

    def consume(self) -> bytes:
        try:
            packet = self.packet_queue.get_nowait()
            if packet:
                print(f"← Получен {len(packet)} байт из Wintun")
                return packet
        except queue.Empty:
            pass
        except Exception as e:
            print(f"Ошибка при получении: {e}")
        return None

    def __del__(self):
        self.running = False
        if hasattr(self, "windivert"):
            try:
                self.windivert.close()
            except:
                pass
        if hasattr(self, "session") and self.session:
            try:
                self.wintun.wintun.WintunEndSession(self.session)
            except:
                pass
        if hasattr(self, "adapter") and self.adapter:
            try:
                self.wintun.wintun.WintunCloseAdapter(self.adapter)
            except:
                pass

    def get_ip(self, retries=10, delay=1.0):
        """Возвращает IP-адрес интерфейса vpn-l2, ожидая его появления."""
        for attempt in range(retries):
            try:
                output = subprocess.check_output(
                    "powershell -Command \"Get-NetIPAddress -InterfaceAlias 'vpn-l2' -AddressFamily IPv4 | Select-Object -First 1 | ConvertTo-Json\"",
                    shell=True,
            )
                data = json.loads(output)
                ip = data.get("IPAddress")
                if ip:
                    return ip
            except Exception as e:
                pass
            time.sleep(delay)
        print("Не удалось получить IP-адрес интерфейса после ожидания.")
        return None

    def get_index(self):
        """Возвращает индекс интерфейса (InterfaceIndex)."""
        output = subprocess.check_output(
            "powershell -Command \"(Get-NetAdapter -Name 'vpn-l2').ifIndex\"",
            shell=True,
        )
        return int(output.strip())

    @property
    def iface_name(self):
        return "vpn-l2"
