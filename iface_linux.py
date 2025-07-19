import socket
import os

def list_ifaces_linux():
    # through /sys/class/net we can get the list of network interfaces
    return os.listdir('/sys/class/net')

class RealInterface:
    def __init__(self, iface_hint=None, is_client=False):
        if iface_hint is None:
            ifaces = list_ifaces_linux()
            # Look for a suitable interface that is not loopback or docker
            for i in ifaces:
                if i != 'lo' and not i.startswith('docker'):
                    iface_hint = i
                    break
            else:
                iface_hint = 'eth0'  # fallback

        self.iface = iface_hint
        self.is_client = is_client

        self.recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        self.recv_sock.bind((self.iface, 0))
        self.recv_sock.setblocking(False)

        self.send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self.send_sock.bind((self.iface, 0))

    def consume(self):
        try:
            return self.recv_sock.recv(2048)
        except BlockingIOError:
            return None

    def write(self, data: bytes):
        self.send_sock.send(data)

    def inject(self, data: bytes):
        self.write(data)
