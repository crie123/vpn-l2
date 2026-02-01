# Usage Examples - vpn-l2 с teeth-gnashing

Примеры использования VPN клиента и сервера с teeth-gnashing шифрованием.

## 1. Базовый пример: Запуск VPN

### Клиент
```bash
# Первый запуск - генерирует конфиги и отправляет на сервер
python main.py

# При первом запуске ответьте на вопросы:
# Введите IP-адрес VPS-сервера: 192.168.1.100
# Введите SSH-порт (Enter для 22): 22
# Имя пользователя на VPS: ubuntu
# Введите пароль от VPS: ****
```

### Сервер
```bash
# Linux
sudo python server_main.py

# Windows (администратор)
python server_main.py
```

## 2. Проверка подключения

### Health Check
```bash
curl http://localhost:8000/health
```

Ответ:
```json
{
  "status": "healthy",
  "timestamp": 1706794234,
  "tick": 42,
  "authenticated_clients": 1
}
```

## 3. Программное использование

### Шифрование и дешифрование

```python
import asyncio
from crypto_stack import encrypt_message, decrypt_message, close_crypto_client

async def main():
    server_url = "http://localhost:8000"
    
    # Оригинальное сообщение
    original = "Hello, VPN!"
    print(f"Original: {original}")
    
    # Шифрование
    encrypted = await encrypt_message(original, server_url)
    print(f"Encrypted ({len(encrypted)} bytes): {encrypted.hex()[:50]}...")
    
    # Дешифрование
    decrypted = await decrypt_message(encrypted, server_url)
    print(f"Decrypted: {decrypted.decode()}")
    
    # Проверка целостности
    assert decrypted.decode() == original
    print("✓ Успешно!")
    
    # Очистка ресурсов
    await close_crypto_client()

if __name__ == "__main__":
    asyncio.run(main())
```

### Использование Context Manager

```python
import asyncio
from crypto_stack import get_crypto_client
from teeth_gnashing.client import CryptoConfig
import base64

async def main():
    config = CryptoConfig(
        server_url="http://localhost:8000",
        secret_key=base64.b64decode("your_base64_secret_key"),
        max_drift=60,
        handshake_points=8,
        hash_size=32,
        array_size=256
    )
    
    client = get_crypto_client("http://localhost:8000")
    
    # Аутентификация
    await client.authenticate()
    print("✓ Authenticated")
    
    # Множественные операции
    messages = [
        "Message 1",
        "Message 2",
        "Message 3"
    ]
    
    for msg in messages:
        encrypted = await client.encrypt_message(msg)
        decrypted = await client.decrypt_message(encrypted)
        print(f"✓ {msg} -> {decrypted.decode()}")
    
    await client.close()

if __name__ == "__main__":
    asyncio.run(main())
```

## 4. Работа с бинарными данными

```python
import asyncio
from crypto_stack import encrypt_message, decrypt_message

async def main():
    # Бинарные данные (например, изображение)
    binary_data = bytes([0xFF, 0xD8, 0xFF, 0xE0]) + b"JFIF" + bytes(100)
    
    encrypted = await encrypt_message(binary_data, "http://localhost:8000")
    decrypted = await decrypt_message(encrypted, "http://localhost:8000")
    
    assert decrypted == binary_data
    print(f"✓ Binary data encrypted/decrypted successfully ({len(binary_data)} bytes)")

if __name__ == "__main__":
    asyncio.run(main())
```

## 5. Обработка ошибок

```python
import asyncio
from crypto_stack import encrypt_message, decrypt_message
from teeth_gnashing.client import AuthenticationError, SnapshotError, CryptoError

async def main():
    server_url = "http://localhost:8000"
    
    try:
        # Попытка шифрования
        encrypted = await encrypt_message("Test", server_url)
        
    except AuthenticationError as e:
        print(f"❌ Authentication failed: {e}")
        # Проверьте secret_key и сервер
        
    except SnapshotError as e:
        print(f"❌ Snapshot error: {e}")
        # Проверьте синхронизацию времени
        
    except CryptoError as e:
        print(f"❌ Crypto error: {e}")
        # Общая ошибка шифрования
        
    except ConnectionRefusedError:
        print(f"❌ Cannot connect to server at {server_url}")
        # Убедитесь, что сервер запущен

if __name__ == "__main__":
    asyncio.run(main())
```

## 6. Конфигурация под разные сценарии

### Высокопроизводительный режим
```json
{
  "server_ip": "192.168.1.100",
  "server_http_port": 8000,
  "server_udp_ports": [5555],
  "secret_key": "base64_encoded_key",
  "max_drift": 60,
  "handshake_points": 4,
  "hash_size": 16,
  "array_size": 256
}
```

### Высокозащищённый режим
```json
{
  "server_ip": "192.168.1.100",
  "server_http_port": 8000,
  "server_udp_ports": [5555],
  "secret_key": "base64_encoded_key",
  "max_drift": 30,
  "handshake_points": 16,
  "hash_size": 64,
  "array_size": 512
}
```

## 7. Мониторинг и логирование

```python
import asyncio
import logging
from crypto_stack import encrypt_message, decrypt_message

# Настройка логирования
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

async def monitored_encryption(data: str, server_url: str):
    try:
        logger.info(f"Encrypting {len(data)} bytes of data")
        encrypted = await encrypt_message(data, server_url)
        logger.info(f"Encrypted successfully ({len(encrypted)} bytes)")
        return encrypted
    except Exception as e:
        logger.error(f"Encryption failed: {e}", exc_info=True)
        raise

async def monitored_decryption(encrypted: bytes, server_url: str):
    try:
        logger.info(f"Decrypting {len(encrypted)} bytes of data")
        decrypted = await decrypt_message(encrypted, server_url)
        logger.info(f"Decrypted successfully ({len(decrypted)} bytes)")
        return decrypted
    except Exception as e:
        logger.error(f"Decryption failed: {e}", exc_info=True)
        raise

async def main():
    server_url = "http://localhost:8000"
    data = "Sensitive information"
    
    encrypted = await monitored_encryption(data, server_url)
    decrypted = await monitored_decryption(encrypted, server_url)
    
    print(f"Original: {data}")
    print(f"Decrypted: {decrypted.decode()}")

if __name__ == "__main__":
    asyncio.run(main())
```

## 8. Тестирование и верификация

```python
import asyncio
from crypto_stack import encrypt_message, decrypt_message
import time

async def performance_test():
    """Тест производительности"""
    server_url = "http://localhost:8000"
    data = "X" * 1000  # 1KB данных
    iterations = 10
    
    start = time.time()
    for i in range(iterations):
        encrypted = await encrypt_message(data, server_url)
        decrypted = await decrypt_message(encrypted, server_url)
        assert decrypted.decode() == data
    
    elapsed = time.time() - start
    print(f"✓ {iterations} iterations in {elapsed:.2f}s ({elapsed/iterations:.3f}s per op)")

async def integrity_test():
    """Тест целостности данных"""
    server_url = "http://localhost:8000"
    
    test_cases = [
        "",
        "A",
        "Hello, World!",
        "Спецсимволы: @#$%^&*()",
        bytes(range(256)).decode('latin-1'),
    ]
    
    for test_data in test_cases:
        encrypted = await encrypt_message(test_data, server_url)
        decrypted = await decrypt_message(encrypted, server_url)
        
        if isinstance(test_data, str):
            assert decrypted.decode() == test_data
        else:
            assert decrypted == test_data.encode()
        
        print(f"✓ Integrity test passed for: {repr(test_data[:20])}")

if __name__ == "__main__":
    asyncio.run(performance_test())
    asyncio.run(integrity_test())
```

## 9. Интеграция с VPN пакетами

```python
import asyncio
from crypto_stack import encrypt_message, decrypt_message
from protocol import build_frame, parse_frame, FRAME_TYPE_DATA

async def send_vpn_packet(packet_data: bytes, server_url: str):
    """Отправить VPN пакет"""
    # Шифрование
    encrypted = await encrypt_message(packet_data, server_url)
    
    # Построение фрейма
    frame = build_frame(FRAME_TYPE_DATA, encrypted)
    
    return frame

async def receive_vpn_packet(frame: bytes, server_url: str):
    """Получить VPN пакет"""
    # Парсинг фрейма
    frame_type, payload = parse_frame(frame)
    
    if frame_type != FRAME_TYPE_DATA:
        raise ValueError("Invalid frame type")
    
    # Дешифрование
    packet_data = await decrypt_message(payload, server_url)
    
    return packet_data

async def main():
    server_url = "http://localhost:8000"
    
    # Симуляция IP пакета
    ip_packet = bytes([0x45, 0x00, 0x00, 0x3c]) + b"test packet"
    
    # Отправка
    frame = await send_vpn_packet(ip_packet, server_url)
    print(f"Frame size: {len(frame)} bytes")
    
    # Получение
    received = await receive_vpn_packet(frame, server_url)
    assert received == ip_packet
    print("✓ VPN packet transmitted successfully")

if __name__ == "__main__":
    asyncio.run(main())
```

## 10. Troubleshooting примеры

### Проблема: Синхронизация времени
```python
import asyncio
from crypto_stack import encrypt_message
from teeth_gnashing.client import SnapshotError
import time

async def check_time_sync():
    """Проверить синхронизацию времени"""
    try:
        await encrypt_message("test", "http://localhost:8000")
        print("✓ Time synchronized")
    except SnapshotError as e:
        if "expired" in str(e).lower():
            print("❌ Time mismatch detected!")
            print("Solution: Synchronize system time with NTP")
            import subprocess
            # Linux
            subprocess.run(["ntpdate", "-s", "time.nist.gov"])
        else:
            raise

asyncio.run(check_time_sync())
```

### Проблема: Соединение с сервером
```python
import asyncio
from crypto_stack import encrypt_message
import socket

async def check_server_connection(host: str, port: int):
    """Проверить доступность сервера"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            print(f"✓ Server {host}:{port} is accessible")
            return True
        else:
            print(f"❌ Cannot connect to {host}:{port}")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

# Использование
import asyncio
asyncio.run(check_server_connection("localhost", 8000))
```

## Ссылки

- Основная документация: [README.md](./README.md)
- Миграция с прототипа: [MIGRATION_GUIDE.md](./MIGRATION_GUIDE.md)
- teeth-gnashing PyPI: https://pypi.org/project/teeth-gnashing/
