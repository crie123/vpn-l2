# vpn-l2

Коротко: простой L2 VPN-клиент и сервер на Python с Wintun/WinDivert (Windows) и TUN (Linux).

Состав:
- main.py — клиент
- server_main.py — сервер (FastAPI + UDP обработчик)
- crypto_stack.py — шифрование/аутентификация
- protocol.py — фреймы/фрагментация
- iface_win.py, iface_linux.py — платформенные интерфейсы
- tun.py — интерфейс-обёртка
- client_config.json / server_config.json — конфиги
- wintun.dll — Windows Wintun ДЛЛ

Быстрый старт:
1) Установить зависимости: pip install -r requirements.txt
2) На сервере: поместить server_config.json рядом с исполняемым файлом и запустить server_main.py (требуются права администратора/рут).
3) На клиенте: запустить main.py — при первом запуске сгенерируется client_config.json и будет предпринята попытка отправить server_config.json на указанный VPS по SSH.

Примечания:
- Windows: требуется wintun.dll и права администратора для создания адаптера и WinDivert (pydivert). Также может потребоваться PowerShell.
- Linux: требуется доступ к TUN/TAP и правила iptables для NAT, iproute2.
- Файлы конфигурации хранят секрет в base64 (secret_key). Будьте осторожны с распространением.

Лицензия: содержимое репозитория под LICENSE.