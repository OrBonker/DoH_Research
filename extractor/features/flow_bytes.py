from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
import os
import sys
projectroot = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(projectroot)
from features.context.packet_direction import PacketDirection
from features.packet_time import PacketTime
from scapy.plist import PacketList

class FlowBytes:
    """Extracts features from the traffic related to the bytes in a flow"""

    def __init__(self, packets: PacketList, directions: list):
        if not isinstance(packets, PacketList):
            raise ValueError("Expected a PacketList object from Scapy.")
        if len(packets) != len(directions):
            raise ValueError("Packets and directions lists must be of the same length.")
        self.packets = packets
        self.directions = directions

    def direction_list(self) -> list:
        """ Returns a list of the directions of the first 50 packets in a flow. """
        return [direction.name for (i, direction) in enumerate(self.directions) if i < 50]

    def get_bytes_sent(self) -> int:
        """ Calculates the total number of bytes sent in the forward direction. """
        return sum(len(packet) for packet, direction in zip(self.packets, self.directions) if direction == PacketDirection.FORWARD)

    def get_sent_rate(self) -> float:
        """ Calculates the rate of bytes being sent in bytes per second. """
        sent = self.get_bytes_sent()
        duration = PacketTime(self.packets).get_duration()
        if duration == 0:
            return -1
        return sent / duration

    def get_bytes_received(self) -> int:
        """ Calculates the total number of bytes received in the reverse direction. """
        return sum(len(packet) for packet, direction in zip(self.packets, self.directions) if direction == PacketDirection.REVERSE)

    def get_received_rate(self) -> float:
        """ Calculates the rate of bytes being received in bytes per second. """
        received = self.get_bytes_received()
        duration = PacketTime(self.packets).get_duration()
        if duration == 0:
            return -1
        return received / duration

    def get_forward_header_bytes(self) -> int:
        """ Calculates the total number of header bytes sent in the forward direction. """
        def header_size(packet):
            res = len(Ether()) + len(IP())
            if packet.haslayer(TCP):
                res += len(TCP())
            return res

        return sum(header_size(packet) for packet, direction in zip(self.packets, self.directions) if direction == PacketDirection.FORWARD)

    def get_forward_rate(self) -> float:
        """ Calculates the rate of header bytes being sent forward in bytes per second. """
        forward = self.get_forward_header_bytes()
        duration = PacketTime(self.packets).get_duration()
        if duration > 0:
            return forward / duration
        return -1

    def get_reverse_header_bytes(self) -> int:
        """ Calculates the total number of header bytes sent in the reverse direction. """
        def header_size(packet):
            res = len(Ether()) + len(IP())
            if packet.haslayer(TCP):
                res += len(TCP())
            return res

        return sum(header_size(packet) for packet, direction in zip(self.packets, self.directions) if direction == PacketDirection.REVERSE)

    def get_reverse_rate(self) -> float:
        """ Calculates the rate of header bytes being sent in reverse in bytes per second. """
        reverse = self.get_reverse_header_bytes()
        duration = PacketTime(self.packets).get_duration()
        if duration == 0:
            return -1
        return reverse / duration

    def get_header_in_out_ratio(self) -> float:
        """ Calculates the ratio of forward header bytes to reverse header bytes. """
        reverse_header_bytes = self.get_reverse_header_bytes()
        forward_header_bytes = self.get_forward_header_bytes()
        if reverse_header_bytes != 0:
            return forward_header_bytes / reverse_header_bytes
        return -1

    def get_initial_ttl(self) -> int:
        """ Obtains the initial Time-To-Live (TTL) value from the first packet in the flow. """
        return self.packets[0].getlayer(IP).ttl if self.packets else -1
