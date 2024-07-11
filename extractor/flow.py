from enum import Enum
from typing import Any

from extractor import constants
from extractor.features.context import packet_key
from extractor.features.flow_bytes import FlowBytes
from extractor.features.packet_length import PacketLength
from extractor.features.packet_time import PacketTime
from extractor.features.response_time import ResponseTime


class Flow:
    """This class summarizes the values of the features of the network flows"""

    def __init__(self, packet: Any, direction: Enum):
        """This method initializes an object from the Flow class.
            Args:
                packet (Any): A packet from the network.
                direction (Enum): The direction the packet is going over the wire.
        """
        self.dest_ip, self.src_ip, self.src_port, self.dest_port = packet_key.get_packet_flow_key(packet, direction)
        self.packets = []
        self.latest_timestamp = 0
        self.start_timestamp = 0


    def get_data(self) -> dict:
        """This method obtains the values of the features extracted from each flow.
        
            Note:
                Only some of the network data plays well together in this list.
                Time-to-live values, window values, and flags cause the data to separate out too
                much.

            Returns:
            list: returns a List of values to be outputted into a csv file.
        """
        flow_bytes = FlowBytes(self)
        packet_length = PacketLength(self)
        packet_time = PacketTime(self)
        response = ResponseTime(self)
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
            'PacketLengthMean': packet_length.get_mean(),
            'PacketLengthMedian': packet_length.get_median(),
            'PacketLengthMode': packet_length.get_mode(),
            'PacketLengthSkewFromMedian': packet_length.get_skew_avg_median(),
            'PacketLengthSkewFromMode': packet_length.get_skew_avg_mode(),
            'PacketLengthCoefficientofVariation': packet_length.get_cov(),
            'PacketTimeVariance': packet_time.get_var(),
            'PacketTimeStandardDeviation': packet_time.get_std(),
            'PacketTimeMean': packet_time.get_mean(),
            'PacketTimeMedian': packet_time.get_median(),
            'PacketTimeMode': packet_time.get_mode(),
            'PacketTimeSkewFromMedian': packet_time.get_skew_avg_median(),
            'PacketTimeSkewFromMode': packet_time.get_skew_avg_mode(),
            'PacketTimeCoefficientofVariation': packet_time.get_cov(),
            'ResponseTimeTimeVariance': response.get_var(),
            'ResponseTimeTimeStandardDeviation': response.get_std(),
            'ResponseTimeTimeMean': response.get_mean(),
            'ResponseTimeTimeMedian': response.get_median(),
            'ResponseTimeTimeMode': response.get_mode(),
            'ResponseTimeTimeSkewFromMedian': response.get_skew_avg_median(),
            'ResponseTimeTimeSkewFromMode': response.get_skew_avg_mode(),
            'ResponseTimeTimeCoefficientofVariation': response.get_cov(),
            'DoH': self.is_doh(),
        }

        return data

    def add_packet(self, packet, direction) -> None:
        """ Adds a packet to the current list of packets. """
        self.packets.append((packet, direction))
        self.latest_timestamp = max([packet.time, self.latest_timestamp])
        if self.start_timestamp == 0:
            self.start_timestamp = packet.time

    def is_doh(self) -> bool:
        """ Checks if the source or destination IP of the flow is in the list of DoH IPs. """
        return self.src_ip in constants.DOH_IPS or self.dest_ip in constants.DOH_IPS

    @property
    def duration(self):
        """ Computes the duration of the flow as the difference between the latest and start timestamps. """
        return self.latest_timestamp - self.start_timestamp
