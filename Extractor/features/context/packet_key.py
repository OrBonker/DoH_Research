from extractor.features.context import packet_direction

def get_packet_flow_key(packet, direction) -> tuple:
    """
    Creates a key signature for a packet so it can be assigned to a flow.

    Args:
        packet: A network packet
        direction: The direction of a packet

    Returns:
        tuple: (dest_ip , src_ip , src_port , dest_port)

    Raises:
        Exception: If the packet does not contain TCP or UDP protocol data.
    """

    if 'TCP' in packet:
        protocol = 'TCP'
    elif 'UDP' in packet:
        protocol = 'UDP'
    else:
        raise Exception('Only TCP protocols are supported.')

    if direction == packet_direction.FORWARD:
        dest_ip = packet['IP'].dst
        src_ip = packet['IP'].src
        src_port = packet[protocol].sport
        dest_port = packet[protocol].dport
    else:
        dest_ip = packet['IP'].src
        src_ip = packet['IP'].dst
        src_port = packet[protocol].dport
        dest_port = packet[protocol].sport
        
    return dest_ip, src_ip, src_port, dest_port

