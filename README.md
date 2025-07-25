# VPN-L2 — UDP VPN на WinDivert/Npcap/Wintun

🛡 Лёгкий пользовательский VPN-клиент с UDP-транспортом и уровнем шифрования. Работает без TAP-интерфейсов, использует `WinDivert` и `Npcap`.  
Поддерживает перехват IP-трафика и отправку через зашифрованные UDP-фреймы. Этот проект использует [Wintun.dll](https://www.wintun.net) от WireGuard (лицензия GPLv2).
DLL не входит в репозиторий. Вы должны загрузить её вручную и поместить рядом с `main.py`. Проект использует Wintun исключительно через API (ctypes), без модификации или встраивания исходного кода. Исходники Wintun: https://git.zx2c4.com/wintun/


---

## Быстрый старт

```bash
git clone https://github.com/yourname/vpn-l2.git
cd vpn-l2
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py

# Сборка клиента
pyinstaller main.py --onefile --name vpn_client.exe

# Сборка сервера
pyinstaller server_main.py --onefile --name vpn_server.exe
```
Конфиг в исполняемый файл не входит(для удобства)