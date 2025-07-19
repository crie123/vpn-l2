import platform

if platform.system() == "Windows":
    from iface_win import RealInterface as RealInterfaceImpl
else:
    from iface_linux import RealInterface as RealInterfaceImpl

class RealInterface(RealInterfaceImpl):
    def __init__(self, iface_hint=None, is_client=False):
        # In Linux iface_hint is the network interface name
        # In Windows iface_hint = путь к Wintun.dll
        super().__init__(iface_hint, is_client=is_client)
