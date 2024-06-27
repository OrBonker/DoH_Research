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
        return [len(packet) for packet, _ in self.feature.packets]

    def first_fifty(self) -> list:
        """ Creates a list of the sizes of the first 50 packets """
        return self.get_packet_length()[:50]
    
    def get_var(self) -> float:
        """ Calculates the variation of packet lengths in a network flow. """
        return numpy.var(self.get_packet_length())
    
    def get_std(self) -> float:
        """ calculates and returns the standard deviation of packet lengths. """
        return numpy.sqrt(self.get_var())


    def get_avg(self) -> float:
        """ calculates and returns the mean of the packet lengths """
        avg = 0
        if self.get_packet_length() != 0:
            avg = numpy.mean(self.get_packet_length())
        return avg

    def get_median(self) -> float:
        """ Calculates the median of packet lengths in a network flow. """
        return numpy.median(self.get_packet_length())

    def get_mode(self) -> float:
        """ The mode of packet lengts in a network flow. """
        mode = -1
        if len(self.get_packet_length()) != 0:
            mode = int(stat.mode(self.get_packet_length())[0])
        return mode
    
    def get_skew_avg_median(self) -> float:
        """ Calculates skewness of packet lengths using average and median. """
        mean = self.get_avg()
        median = self.get_median()
        dif = 3 * (mean - median)
        std = self.get_std()
        skew = -10
        if std != 0:
            skew = dif / std
        return skew

    def get_skew_avg_mode(self) -> float:
        """ Calculates skewness of packet lenghts using average and mode. """
        avg = self.get_avg()
        mode = self.get_mode()
        dif = (avg - mode)
        std = self.get_std()
        skew = -10
        if std != 0:
            skew = dif / std
        return skew

    def get_co_var(self) -> float:
        """ Calculates coefficient of variation of packet lengths. """
        co_var = -1
        if self.get_avg() != 0:
            co_var = self.get_std() / self.get_avg()
        return co_var


