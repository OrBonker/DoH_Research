import numpy
from scipy import stats as stat


class PacketLength:
    """This class extracts features related to the Packet Lengths.
    Attributes:
        avg_count (int): The row number.
        grand_total (float): The cumulative total of the means.
    """

    avg_count = 0
    grand_total = 0

    def __init__(self, feature):
        self.feature = feature

    def get_packet_length(self) -> list:
        """ Creates a list of packet lengths. """
        if isinstance(self.feature, list):
            # Case when self.feature is a list of packets
            return [len(packet) for packet in self.feature]
        else:
            # Case when self.feature is directly a packet (e.g., result of rdpcap)
            return [len(self.feature)]

    def first_fifty(self) -> list:
        """ Creates a list of the sizes of the first 50 packets """
        return self.get_packet_length()[:50]
    
    def get_var(self) -> float:
        """ Calculates the variation of packet lengths in a network flow. """
        lengths = self.get_packet_length()
        if len(lengths) > 0:
            return numpy.var(lengths)
        else:
            return 0.0
    
    def get_std(self) -> float:
        """ calculates and returns the standard deviation of packet lengths. """
        var = self.get_var()
        if var > 0:
            return numpy.sqrt(var)
        else:
            return 0.0

    def get_avg(self) -> float:
        """ calculates and returns the mean of the packet lengths """
        lengths = self.get_packet_length()
        if len(lengths) > 0:
            return numpy.mean(lengths)
        else:
            return 0.0

    def get_median(self) -> float:
        """ Calculates the median of packet lengths in a network flow. """
        lengths = self.get_packet_length()
        if len(lengths) > 0:
            return numpy.median(lengths)
        else:
            return 0.0

    def get_mode(self) -> float:
        """ The mode of packet lengths in a network flow. """
        lengths = self.get_packet_length()
        if len(lengths) > 0:
            return int(stat.mode(lengths)[0])
        else:
            return -1
    
    def get_skew_avg_median(self) -> float:
        """ Calculates skewness of packet lengths using average and median. """
        mean = self.get_avg()
        median = self.get_median()
        std = self.get_std()
        if std > 0:
            return 3 * (mean - median) / std
        else:
            return 0.0

    def get_skew_avg_mode(self) -> float:
        """ Calculates skewness of packet lengths using average and mode. """
        avg = self.get_avg()
        mode = self.get_mode()
        std = self.get_std()
        if std > 0:
            return (avg - mode) / std
        else:
            return 0.0

    def get_cov(self) -> float:
        """ Calculates coefficient of variation of packet lengths. """
        avg = self.get_avg()
        std = self.get_std()
        if avg > 0:
            return std / avg
        else:
            return 0.0


