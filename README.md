# VPN-L2 — UDP VPN на WinDivert/Npcap/Wintun

🛡 Лёгкий пользовательский VPN-клиент с UDP-транспортом и уровнем шифрования. Работает без TAP-интерфейсов, использует `WinDivert` и `Npcap`.  
Поддерживает перехват IP-трафика и отправку через зашифрованные UDP-фреймы. Установка `Wintun` обязательна https://www.wintun.net

---

## Быстрый старт

```bash
git clone https://github.com/crie123/vpn-l2.git
cd vpn-l2
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py
