from scapy.all import conf

def get_default_interface():
    """
    Retrieve the default network interface.
    """
    return conf.iface  # Get the default interface Scapy uses
