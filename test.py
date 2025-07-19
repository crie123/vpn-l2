from pydivert import WinDivert

with WinDivert("true") as w:
    print("Ожидание трафика...")
    for packet in w:
        print(f"Перехвачен пакет: {packet}")
        break