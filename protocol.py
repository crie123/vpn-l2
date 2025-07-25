import struct
import random

ETHERTYPE_CUSTOM = 0x88B5
ETHERTYPE_ARP = 0x0806
ETHERTYPE_LLDP = 0x88CC

FRAME_TYPE_DATA = 0x01
MAX_PAYLOAD_SIZE = 1300

def build_frame(frame_type, payload: bytes) -> bytes:
    return bytes([frame_type]) + len(payload).to_bytes(2, 'big') + payload

def parse_frame(frame: bytes):
    if len(frame) < 3:
        return None, b''
    return frame[0], frame[3:3+int.from_bytes(frame[1:3], 'big')]

ETHERTYPE_MAP = {
    "CUSTOM": 0x88B5,
    "ARP": 0x0806,
    "LLDP": 0x88CC
}

def get_ethertype(name: str) -> int:
    return ETHERTYPE_MAP.get(name.upper(), 0x88B5)  # по умолчанию CUSTOM

FRAGMENT_HEADER = struct.Struct("!IHH")  # id, index, total
fragment_cache = {}

def fragment_payload(payload: bytes, max_size=1300):
    if len(payload) <= max_size:
        return [payload]

    parts = []
    total = (len(payload) + max_size - 1) // max_size
    fragment_id = random.randint(0, 0xFFFFFFFF)
    for index in range(total):
        chunk = payload[index * max_size : (index + 1) * max_size]
        header = FRAGMENT_HEADER.pack(fragment_id, index, total)
        parts.append(header + chunk)
    return parts

def defragment(payload: bytes):
    if len(payload) < FRAGMENT_HEADER.size:
        return payload  # not a fragment

    try:
        header = payload[:FRAGMENT_HEADER.size]
        data = payload[FRAGMENT_HEADER.size:]
        fragment_id, index, total = FRAGMENT_HEADER.unpack(header)
    except:
        return payload  # corrupted or not a fragment

    cache = fragment_cache.setdefault(fragment_id, [None] * total)
    cache[index] = data

    if all(part is not None for part in cache):
        full = b''.join(cache)
        del fragment_cache[fragment_id]
        return full

    return None  # not yet complete