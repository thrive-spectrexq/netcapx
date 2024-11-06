def format_packet_hex(packet):
    raw_data = bytes(packet)
    hex_str = ' '.join(f"{byte:02x}" for byte in raw_data)
    ascii_str = ''.join((chr(byte) if 32 <= byte <= 126 else '.') for byte in raw_data)
    return hex_str, ascii_str
