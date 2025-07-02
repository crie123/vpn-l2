class RealInterfaceStub:
    def __init__(self):
        self._last = None

    def write(self, data: bytes):
        self._last = data
        print(f"[TUN] 🔼 write: {data}")

    def consume(self):
        if self._last:
            tmp = self._last
            self._last = None
            print(f"[TUN] 🔽 consume: {tmp}")
            return tmp
        print(f"[TUN] 🔽 consume: None")
        return None

    def inject(self, data: bytes):
        print(f"[RECV] ← {data.decode('utf-8', errors='ignore')}")
