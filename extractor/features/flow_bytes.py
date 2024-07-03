from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from extractor.features.context.packet_direction import PacketDirection
from extractor.features.packet_time import PacketTime


class FlowBytes:
    """Extracts features from the traffic related to the bytes in a flow"""

    def __init__(self, feature):
        self.feature = feature


    def direction_list(self) -> list:
        """ Returns a list of the directions of the first 50 packets in a flow. """
        feat = self.feature
        direction_list = [(i, direction.name)[1] for (i, (packet, direction)) in enumerate(feat.packets) if i < 50]
        return direction_list


    def get_bytes_sent(self) -> int:
        """ Calculates the total number of bytes sent in the forward direction. """
        feat = self.feature
        return sum(len(packet) for packet, direction in feat.packets if direction == PacketDirection.FORWARD)


    def get_sent_rate(self) -> float:
        """ calculates the rate of bytes being sent in bytes per second. """
        sent = self.get_bytes_sent()
        duration = PacketTime(self.feature).get_duration()
        if duration == 0:
            rate = -1
        else:
            rate = sent / duration
        return rate


    def get_bytes_received(self) -> int:
        """ Calculates the total number of bytes received in the reverse direction. """
        packets = self.feature.packets
        return sum(len(packet) for packet, direction in packets if direction == PacketDirection.REVERSE)


    def get_received_rate(self) -> float:
        """  calculates the rate of bytes being received in bytes per second. """
        received = self.get_bytes_received()
        duration = PacketTime(self.feature).get_duration()
        if duration == 0:
            rate = -1
        else:
            rate = received / duration
        return rate
    

    def get_forward_header_bytes(self) -> int:
        """ calculates the total number of header bytes sent in the forward. """
        def header_size(packet):
            res = len(Ether()) + len(IP())
            if packet.proto == 6:
                res += len(TCP())
            return res
        packets = self.feature.packets
        return sum(header_size(packet) for packet, direction in packets if direction == PacketDirection.FORWARD)


    def get_forward_rate(self) -> int:
        """ Calculates the rate of header bytes being sent forward in bytes per second. """
        forward = self.get_forward_header_bytes()
        duration = PacketTime(self.feature).get_duration()
        if duration > 0:
            rate = forward / duration
        else:
            rate = -1
        return rate


    def get_reverse_header_bytes(self) -> int:
        """ calculates the total number of header bytes sent in the reverse direction. """
        def header_size(packet):
            res = len(Ether()) + len(IP())
            if packet.proto == 6:
                res += len(TCP())
            return res
        packets = self.feature.packets
        return sum(header_size(packet) for packet, direction in packets if direction == PacketDirection.REVERSE)


    def get_reverse_rate(self) -> int:
        """ calculates the rate of header bytes being sent in reverse in bytes per second. """
        reverse = self.get_reverse_header_bytes()
        duration = PacketTime(self.feature).get_duration()
        if duration == 0:
            rate = -1
        else:
            rate = reverse / duration
        return rate


    def get_header_in_out_ratio(self) -> float:
        """ calculates the ratio of forward header bytes to reverse header bytes. """
        reverse_header_bytes = self.get_reverse_header_bytes()
        forward_header_bytes = self.get_forward_header_bytes()
        ratio = -1
        if reverse_header_bytes != 0:
            ratio = forward_header_bytes / reverse_header_bytes
        return ratio


    def get_initial_ttl(self) -> int:
        """ obtains the initial Time-To-Live (TTL) value from the first packet in the flow. """
        feat = self.feature
        return [packet['IP'].ttl for packet, _ in feat.packets][0]
