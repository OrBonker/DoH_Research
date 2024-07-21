import os
import sys
from scapy.plist import PacketList
from scapy.layers.tls.record import TLSApplicationData

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)

from constants import DOH_IPS
from features.context import packet_key
from features.flow_bytes import FlowBytes
from features.packet_length import PacketLength
from features.packet_time import PacketTime
from features.response_time import ResponseTime

from enum import Enum
from typing import Any, List

# Define Flow class
from scapy.plist import PacketList
from scapy.all import Packet

class Flow:
    """This class summarizes the values of the features of the network flows"""

    def __init__(self, packet: Packet, direction: Enum):
        """Initializes an object from the Flow class.
            Args:
                packet (Packet): A packet from the network.
                direction (Enum): The direction the packet is going over the wire.
        """
        self.dest_ip, self.src_ip, self.src_port, self.dest_port = packet_key.get_packet_flow_key(packet, direction)
        self.packets: PacketList = PacketList()  
        self.directions: List[Enum] = []  # Add a list to store directions
        self.latest_timestamp = 0
        self.start_timestamp = 0

    def add_packet(self, packet: Packet, direction: Enum) -> None:
        """Adds a packet to the current list of packets."""
        self.packets.append(packet)
        self.directions.append(direction)  # Store direction
        self.latest_timestamp = max([packet.time, self.latest_timestamp])
        if self.start_timestamp == 0:
            self.start_timestamp = packet.time

    def get_data(self) -> dict:
        """Obtains the values of the features extracted from each flow."""
        print(f"Number of packets: {len(self.packets)}, Number of directions: {len(self.directions)}")
        flow_bytes = FlowBytes(self.packets, self.directions)  # Pass both PacketList and directions
        packet_length = PacketLength(self.packets)  # Pass PacketList
        packet_time = PacketTime(self.packets)  # Pass PacketList
        response = ResponseTime(self.packets)  # Pass PacketList
        data = {
            'SourceIP': self.src_ip,
            'DestinationIP': self.dest_ip,
            'SourcePort': self.src_port,
            'DestinationPort': self.dest_port,
            'TimeStamp': packet_time.get_time_stamp(),
            'Duration': packet_time.get_duration(),
            'FlowBytesSent': flow_bytes.get_bytes_sent(),
            'FlowSentRate': flow_bytes.get_sent_rate(),
            'FlowBytesReceived': flow_bytes.get_bytes_received(),
            'FlowReceivedRate': flow_bytes.get_received_rate(),
            'PacketLengthVariance': packet_length.get_var(),
            'PacketLengthStandardDeviation': packet_length.get_std(),
            'PacketLengthMean': packet_length.get_avg(),
            'PacketLengthMedian': packet_length.get_median(),
            'PacketLengthMode': packet_length.get_mode(),
            'PacketLengthSkewFromMedian': packet_length.get_skew_avg_median(),
            'PacketLengthSkewFromMode': packet_length.get_skew_avg_mode(),
            'PacketLengthCoefficientofVariation': packet_length.get_cov(),
            'PacketTimeVariance': packet_time.get_var(),
            'PacketTimeStandardDeviation': packet_time.get_std(),
            'PacketTimeMean': packet_time.get_avg(),
            'PacketTimeMedian': packet_time.get_median(),
            'PacketTimeMode': packet_time.get_mode(),
            'PacketTimeSkewFromMedian': packet_time.get_skew_avg_median(),
            'PacketTimeSkewFromMode': packet_time.get_skew_avg_mode(),
            'PacketTimeCoefficientofVariation': packet_time.get_cov(),
            'ResponseTimeVariance': response.get_var(),
            'ResponseTimeStandardDeviation': response.get_std(),
            'ResponseTimeMean': response.get_avg(),
            'ResponseTimeMedian': response.get_median(),
            'ResponseTimeMode': response.get_mode(),
            'ResponseTimeSkewFromMedian': response.get_skew_avg_median(),
            'ResponseTimeSkewFromMode': response.get_skew_avg_mode(),
            'ResponseTimeCoefficientofVariation': response.get_cov(),
            'DoH': self.is_doh(),
        }
        return data

    def is_doh(self) -> bool:
        """Checks if the source or destination IP of the flow is in the list of DoH IPs."""
        return self.src_ip in DOH_IPS or self.dest_ip in DOH_IPS

    @property
    def duration(self) -> float:
        """Computes the duration of the flow as the difference between the latest and start timestamps."""
        return self.latest_timestamp - self.start_timestamp


