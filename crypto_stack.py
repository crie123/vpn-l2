import aiohttp
import os
import time
import hashlib
import random
import hmac
import base64
from math import gcd
import json

# Client-Side Constants

def get_secret_key(config_path="client_config.json"):
    if not os.path.exists(config_path):
        raise RuntimeError(f"Secret key config not found: {config_path}")
    
    with open(config_path, "r") as f:
        config = json.load(f)
    
    return base64.b64decode(config["secret_key"])

MAX_DRIFT = 60  # seconds

# Snapshot + Tick Key

def generate_function_points(n=8):
    return [(random.uniform(-1, 1), random.uniform(-1, 1), random.uniform(-1, 1), random.uniform(0, 1)) for _ in range(n)]

def hash_function_points(points):
    flat = b"".join([
        float(x).hex().encode() + float(y).hex().encode() + float(z).hex().encode() + float(v).hex().encode()
        for x, y, z, v in points
    ])
    return hashlib.blake2s(flat, digest_size=16).digest()

async def authenticate_with_function(session, server_url):
    points = generate_function_points()
    func_hash = hash_function_points(points)
    payload = {"hash": func_hash.hex()}
    async with session.post(f"{server_url}/handshake", json=payload) as resp:
        if resp.status != 200:
            raise Exception("Authentication failed")
        return points

def verify_snapshot_signature(tick, seed, timestamp, signature):
    msg = f"{tick}|{seed}|{timestamp}".encode()
    expected = hmac.new(get_secret_key(), msg, hashlib.sha256).digest()
    return base64.b64encode(expected).decode() == signature

async def get_snapshot(server_url):
    async with aiohttp.ClientSession() as session:
        await authenticate_with_function(session, server_url)
        async with session.get(f"{server_url}/snapshot") as response:
            snap = await response.json()
            now = int(time.time())
            if abs(now - snap["timestamp"]) > MAX_DRIFT:
                raise ValueError("Snapshot expired or too far in future")
            if not verify_snapshot_signature(snap["tick"], snap["seed"], snap["timestamp"], snap["signature"]):
                raise ValueError("Invalid snapshot signature")
            return snap

def derive_key_from_snapshot(snapshot, salt: bytes):
    seed = snapshot['seed']
    tick = snapshot['tick'] ^ int.from_bytes(salt[:4], 'little')

    arr = [[[0 for _ in range(4)] for _ in range(4)] for _ in range(4)]
    value = seed
    for i in range(64):
        z, y, x = i // 16, (i % 16) // 4, i % 4
        arr[z][y][x] = value
        value += 1 if z < 2 else -1

    tick_bytes = []
    for i in range(64):
        z, y, x = i // 16, (i % 16) // 4, i % 4
        tick_val = arr[z][y][x]
        pos_val = ((z << 4) | (y << 2) | x) & 0xFF
        raw = (pos_val ^ (tick_val & 0xFF) ^ salt[i % len(salt)]) & 0xFF
        tick_b = raw if raw != 0 else 1

        # Ensure tick_b is invertible mod 256
        attempts = 0
        while gcd(tick_b, 256) != 1:
            tick_b = (tick_b + 1) % 256 or 1
            attempts += 1
            if attempts > 256:
                raise RuntimeError("Failed to generate invertible tick byte")

        tick_bytes.append(tick_b)

    return tick_bytes

def encrypt_stream(byte_stream, tick_key, salt):
    result = bytearray(salt)
    for i, b in enumerate(byte_stream):
        t = tick_key[i % 64]
        result.append((b * t) % 256)
    return result

def decrypt_stream(encrypted_stream, tick_key):
    result = bytearray()
    for i, b in enumerate(encrypted_stream):
        t = tick_key[i % 64]
        if gcd(t, 256) != 1:
            raise ValueError(f"tick_key[{i % 64}] = {t} is not invertible mod 256")
        t_inv = pow(t, -1, 256)
        result.append((b * t_inv) % 256)
    return result

def fast_hash(data: bytes, digest_size=16):
    return hashlib.blake2s(data, digest_size=digest_size).digest()

async def encrypt_message(message: str, server_url: str) -> bytes:
    snapshot = await get_snapshot(server_url)
    salt = int(time.time()).to_bytes(8, 'little') + os.urandom(8)
    tick_key = derive_key_from_snapshot(snapshot, salt)

    input_bytes = bytearray(message.encode('utf-8')) if isinstance(message, str) else bytearray(message)
    encrypted = encrypt_stream(input_bytes, tick_key, salt)
    hashed = fast_hash(encrypted)
    return hashed + encrypted

async def decrypt_message(encrypted: bytes, server_url: str) -> bytes:
    if len(encrypted) < 32:
        raise ValueError("Encrypted stream too short")

    snapshot = await get_snapshot(server_url)
    recv_hash = encrypted[:16]
    salt = encrypted[16:32]
    payload = encrypted[32:]

    tick_key = derive_key_from_snapshot(snapshot, salt)
    decrypted = decrypt_stream(payload, tick_key)

    actual_hash = fast_hash(encrypted[16:])
    if recv_hash != actual_hash:
        raise ValueError("Hash mismatch! Possible tampering or corruption.")

    return bytes(decrypted)
