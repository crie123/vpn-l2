import socket
import os
import fcntl
import struct


class RealInterface:
    def __init__(self, iface_hint=None, is_client=False):
        self.is_client = is_client
        self.iface = iface_hint or self._default_iface()

        self.recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        self.recv_sock.bind((self.iface, 0))
        self.recv_sock.setblocking(False)

        self.send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self.send_sock.bind((self.iface, 0))

    def _default_iface(self):
        for iface in os.listdir('/sys/class/net'):
            if iface != 'lo' and not iface.startswith('docker'):
                return iface
        return 'eth0'

    def consume(self):
        try:
            return self.recv_sock.recv(2048)
        except BlockingIOError:
            return None

    def write(self, data: bytes):
        self.send_sock.send(data)

    def inject(self, data: bytes):
        self.write(data)

    def get_ip(self):
        """Возвращает IP-адрес интерфейса."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', self.iface[:15].encode())
        )[20:24])

    def get_index(self):
        """Возвращает индекс интерфейса."""
        return socket.if_nametoindex(self.iface)

    @property
    def iface_name(self):
        return self.iface
