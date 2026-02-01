# Migration Guide: Prototype to teeth-gnashing Release

## Обзор изменений

Проект успешно обновлён с использования прототипа teeth-gnashing на официальную релиз-версию **1.0.0** с PyPI.

## Основные изменения

### 1. Замена crypto_stack.py

**Было:**
- Кастомная реализация с собственным алгоритмом шифрования
- Прямое использование hashlib, hmac, random

**Стало:**
- Использование production-grade библиотеки `teeth-gnashing`
- Гарантированная криптографическая стойкость
- Поддержка ChaCha20 для генерации ключей
- Улучшенная генерация энтропии

### 2. API Изменения

#### Старый API
```python
from crypto_stack import encrypt_message, decrypt_message, get_secret_key

# Требовал передачи snapshot вручную
async def encrypt_message(message: str, server_url: str) -> bytes:
    snapshot = await get_snapshot(server_url)
    # ... manual encryption ...
```

#### Новый API
```python
from crypto_stack import encrypt_message, decrypt_message, close_crypto_client

# Автоматическое управление snapshots и сессиями
async def encrypt_message(message: Union[str, bytes], server_url: str, 
                         config_path: str = "client_config.json") -> bytes:
    # Все операции автоматические
```

### 3. Конфигурация

Добавлены новые параметры в `client_config.json`:

```json
{
  "max_drift": 60,           // NEW: максимальное смещение времени
  "handshake_points": 8,     // NEW: количество точек аутентификации
  "hash_size": 32,           // NEW: размер хеша
  "array_size": 256          // NEW: размер массива ключей
}
```

### 4. Формат зашифрованных данных

**Старый формат:**
```
[16 bytes hash][16 bytes salt][encrypted data]
```

**Новый формат:**
```
[32 bytes hash][32 bytes salt][encrypted data]
```

- Увеличенный размер хеша (16→32 байта) для большей стойкости
- Увеличенный размер соли (16→32 байта) для улучшенной энтропии
- Использование BLAKE2b вместо BLAKE2s

## Миграция существующих данных

### ⚠️ Важно: Несовместимость

Данные, зашифрованные старым прототипом, **не могут** быть расшифрованы с новой версией.

Если у вас есть:
1. **Текущие соединения VPN**: Перезапустите клиент и сервер
2. **Сохранённые зашифрованные данные**: Необходимо пересоздать с новой версией
3. **Старые конфиги**: Обновите с новыми параметрами

### Процесс обновления

1. **Backup старых конфигов** (опционально):
   ```bash
   cp client_config.json client_config.json.backup
   cp server_config.json server_config.json.backup
   ```

2. **Остановить старые сервисы**:
   ```bash
   # Остановить server_main.py
   # Остановить main.py (клиент)
   ```

3. **Обновить код**:
   ```bash
   git pull  # или скопировать новые файлы
   pip install -r requirements.txt
   ```

4. **Удалить старые конфиги**:
   ```bash
   rm client_config.json server_config.json
   ```

5. **Запустить клиент** (это создаст новые конфиги):
   ```bash
   python main.py
   ```

6. **Запустить сервер**:
   ```bash
   python server_main.py
   ```

## Преимущества новой версии

✅ **Криптографическая стойкость**
- Использование tested production-grade компонентов
- ChaCha20 вместо кустарных алгоритмов
- Профессиональная проверка безопасности

✅ **Производительность**
- Оптимизированная генерация ключей
- Лучшее использование памяти
- Параллельная обработка где возможно

✅ **Поддержка и обновления**
- Регулярные обновления безопасности на PyPI
- Багфиксы от команды разработчиков
- Сообщество пользователей

✅ **Расширяемость**
- Чистый API для интеграции
- Context managers для управления ресурсами
- Обработка ошибок через custom exceptions

## Обратная совместимость

**Не поддерживается.**

Это преднамеренное изменение для обеспечения лучшей безопасности. 

Если нужна совместимость со старой версией:
1. Сохраните старый код в отдельной ветке
2. Используйте Docker containers с разными версиями
3. Настройте миграцию данных постепенно

## Примеры использования

### Простой пример шифрования

**Старый способ:**
```python
# Требовал много ручной работы
secret = get_secret_key("client_config.json")
snapshot = await get_snapshot(server_url)
salt = os.urandom(8) + int(time.time()).to_bytes(8, 'little')
tick_key = derive_key_from_snapshot(snapshot, salt)
encrypted = encrypt_stream(data, tick_key, salt)
```

**Новый способ:**
```python
# Одна строка!
encrypted = await encrypt_message(data, server_url)
```

### Context Manager

```python
from crypto_stack import get_crypto_client

async with get_crypto_client("http://localhost:8000") as client:
    await client.authenticate()
    encrypted = await client.encrypt_message("Hello")
    decrypted = await client.decrypt_message(encrypted)
```

## Проверка совместимости

### Проверить версию teeth-gnashing
```bash
pip show teeth-gnashing
```

Должно быть версия **1.0.0** или выше.

### Проверить импорты
```bash
python -c "from teeth_gnashing.client import CryptoClient; print('OK')"
```

### Проверить конфиги
```bash
python -c "
import json
with open('client_config.json') as f:
    config = json.load(f)
    required = ['server_ip', 'secret_key', 'hash_size', 'array_size']
    if all(k in config for k in required):
        print('Config OK')
    else:
        print('Missing keys:', [k for k in required if k not in config])
"
```

## Troubleshooting

### Ошибка: "ImportError: cannot import name 'CryptoClient'"

**Причина:** teeth-gnashing не установлена или установлена неправильная версия

**Решение:**
```bash
pip install --upgrade teeth-gnashing>=1.0.0
```

### Ошибка: "Array size must be multiple of 64"

**Причина:** В конфиге `array_size` не кратна 64

**Решение:** Измените в `client_config.json`:
```json
{
  "array_size": 256  // 256, 320, 384, 448, 512, ...
}
```

### Ошибка: "Snapshot expired or too far in future"

**Причина:** Время на клиенте и сервере сильно расходится

**Решение:**
1. Синхронизируйте время (NTP)
2. Увеличьте `max_drift` в конфиге (не рекомендуется)
3. Проверьте часы системы

### Hash mismatch после обновления

**Причина:** Старые зашифрованные данные несовместимы

**Решение:** Пересоздайте зашифрованные данные с новой версией

## Дополнительные ресурсы

- [teeth-gnashing на PyPI](https://pypi.org/project/teeth-gnashing/)
- [teeth-gnashing GitHub](https://github.com/kirill-nikitenko/teeth-gnashing)
- [Основной README](./README.md)

## Поддержка

Если у вас есть вопросы по миграции:
1. Проверьте этот документ
2. Посмотрите в README.md
3. Создайте Issue в репозитории
4. Свяжитесь с автором
