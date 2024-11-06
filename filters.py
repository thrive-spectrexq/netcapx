import re

def filter_packets(packets, pattern):
    regex = re.compile(pattern)
    return [pkt for pkt in packets if regex.search(str(pkt))]
