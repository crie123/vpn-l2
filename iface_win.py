from scapy.all import sniff, sendp, get_if_list
import threading

class RealInterface:
    def __init__(self, iface_hint=None):
        interfaces = get_if_list()
        if iface_hint is None:
            self.iface = interfaces[0]
        else:
            self.iface = next((i for i in interfaces if iface_hint in i), None)
        if not self.iface:
            raise Exception(f"Интерфейс '{iface_hint}' не найден")

        print(f"[🎯] Используем интерфейс: {self.iface}")

        self._last_packet = None
        self._lock = threading.Lock()
        self._sniffer_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._sniffer_thread.start()

    def _sniff_loop(self):
        sniff(iface=self.iface, prn=self._handle_packet, store=0)

    def _handle_packet(self, pkt):
        with self._lock:
            self._last_packet = bytes(pkt)

    def consume(self):
        with self._lock:
            pkt = self._last_packet
            self._last_packet = None
            return pkt

    def write(self, data: bytes):
        sendp(data, iface=self.iface, verbose=False)

    def inject(self, data: bytes):
        self.write(data)
