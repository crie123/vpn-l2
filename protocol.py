ETHERTYPE_CUSTOM = 0x88B5
ETHERTYPE_ARP = 0x0806
ETHERTYPE_LLDP = 0x88CC

FRAME_TYPE_DATA = 0x01
MAX_PAYLOAD_SIZE = 1400

def build_frame(frame_type, payload: bytes) -> bytes:
    return bytes([frame_type]) + len(payload).to_bytes(2, 'big') + payload

def parse_frame(frame: bytes):
    if len(frame) < 3:
        return None, b''
    return frame[0], frame[3:3+int.from_bytes(frame[1:3], 'big')]