import numpy
from scipy import stats as stat
from scapy.plist import PacketList
import numpy as np

class PacketLength:
    """This class extracts features related to the Packet Lengths."""

    def __init__(self, packets: PacketList):
        if isinstance(packets, PacketList):
            self.packets = packets
        else:
            raise ValueError("Expected a PacketList object from Scapy.")
        
    def get_packet_length(self) -> list:
        """Creates a list of packet lengths."""
        return [len(packet) for packet in self.packets]

    def first_fifty(self) -> list:
        """Creates a list of the sizes of the first 50 packets."""
        return self.get_packet_length()[:50]
    
    def get_var(self) -> float:
        """Calculates the variation of packet lengths in a network flow."""
        lengths = self.get_packet_length()
        return np.var(lengths)
    
    def get_std(self) -> float:
        """Calculates and returns the standard deviation of packet lengths."""
        return np.std(self.get_packet_length())
    
    def get_avg(self) -> float:
        """Calculates and returns the mean of the packet lengths."""
        return np.mean(self.get_packet_length())
    
    def get_median(self) -> float:
        """Calculates the median of packet lengths in a network flow."""
        return np.median(self.get_packet_length())
    
    def get_mode(self) -> float:
        """The mode of packet lengths in a network flow."""
        return int(stat.mode(self.get_packet_length())[0])
    
    def get_skew_avg_median(self) -> float:
        """Calculates skewness of packet lengths using average and median."""
        mean = self.get_avg()
        median = self.get_median()
        std = self.get_std()
        return 3 * (mean - median) / std if std != 0 else 0.0

    def get_skew_avg_mode(self) -> float:
        """Calculates skewness of packet lengths using average and mode."""
        avg = self.get_avg()
        mode = self.get_mode()
        std = self.get_std()
        return (avg - mode) / std if std != 0 else 0.0

    def get_cov(self) -> float:
        """Calculates coefficient of variation of packet lengths."""
        avg = self.get_avg()
        std = self.get_std()
        return std / avg if avg != 0 else 0.0

