from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

import sys
projectroot = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(projectroot)
from features.context.packet_direction import PacketDirection
from features.packet_time import PacketTime

class FlowBytes:
    """Extracts features from the traffic related to the bytes in a flow"""

    def __init__(self, feature):
        self.feature = feature

    def direction_list(self) -> list:
        """ Returns a list of the directions of the first 50 packets in a flow. """
        feat = self.feature
        direction_list = [direction.name for (i, (packet, direction)) in enumerate(feat) if i < 50]
        return direction_list

    def get_bytes_sent(self) -> int:
        """ Calculates the total number of bytes sent in the forward direction. """
        feat = self.feature
        return sum(len(packet) for packet, direction in feat if direction == PacketDirection.FORWARD)

    def get_sent_rate(self) -> float:
        """ Calculates the rate of bytes being sent in bytes per second. """
        sent = self.get_bytes_sent()
        packets = PacketList([packet for packet, direction in self.feature])
        duration = PacketTime(packets).get_duration()
        if duration == 0:
            rate = -1
        else:
            rate = sent / duration
        return rate

    def get_bytes_received(self) -> int:
        """ Calculates the total number of bytes received in the reverse direction. """
        feat = self.feature
        return sum(len(packet) for packet, direction in feat if direction == PacketDirection.REVERSE)

    def get_received_rate(self) -> float:
        """ Calculates the rate of bytes being received in bytes per second. """
        received = self.get_bytes_received()
        packets = PacketList([packet for packet, direction in self.feature])
        duration = PacketTime(packets).get_duration()
        if duration == 0:
            rate = -1
        else:
            rate = received / duration
        return rate

    def get_forward_header_bytes(self) -> int:
        """ Calculates the total number of header bytes sent in the forward direction. """
        def header_size(packet):
            res = len(Ether()) + len(IP())
            if packet.proto == 6:
                res += len(TCP())
            return res

        feat = self.feature
        return sum(header_size(packet) for packet, direction in feat if direction == PacketDirection.FORWARD)

    def get_forward_rate(self) -> float:
        """ Calculates the rate of header bytes being sent forward in bytes per second. """
        forward = self.get_forward_header_bytes()
        packets = PacketList([packet for packet, direction in self.feature])
        duration = PacketTime(packets).get_duration()
        if duration > 0:
            rate = forward / duration
        else:
            rate = -1
        return rate

    def get_reverse_header_bytes(self) -> int:
        """ Calculates the total number of header bytes sent in the reverse direction. """
        def header_size(packet):
            res = len(Ether()) + len(IP())
            if packet.proto == 6:
                res += len(TCP())
            return res

        feat = self.feature
        return sum(header_size(packet) for packet, direction in feat if direction == PacketDirection.REVERSE)

    def get_reverse_rate(self) -> float:
        """ Calculates the rate of header bytes being sent in reverse in bytes per second. """
        reverse = self.get_reverse_header_bytes()
        packets = PacketList([packet for packet, direction in self.feature])
        duration = PacketTime(packets).get_duration()
        if duration == 0:
            rate = -1
        else:
            rate = reverse / duration
        return rate

    def get_header_in_out_ratio(self) -> float:
        """ Calculates the ratio of forward header bytes to reverse header bytes. """
        reverse_header_bytes = self.get_reverse_header_bytes()
        forward_header_bytes = self.get_forward_header_bytes()
        ratio = -1
        if reverse_header_bytes != 0:
            ratio = forward_header_bytes / reverse_header_bytes
        return ratio

    def get_initial_ttl(self) -> int:
        """ Obtains the initial Time-To-Live (TTL) value from the first packet in the flow. """
        feat = self.feature
        return [packet['IP'].ttl for packet, _ in feat][0]