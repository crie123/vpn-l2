import platform

if platform.system() == "Windows":
    from iface_win import RealInterface as RealInterfaceImpl
else:
    from iface_linux import RealInterface as RealInterfaceImpl

class RealInterface(RealInterfaceImpl):
    def __init__(self, iface_hint=None):
        # В Linux iface_hint = название интерфейса, например 'eth0'
        # В Windows — часть имени интерфейса, например 'Wi-Fi'
        super().__init__(iface_hint)
