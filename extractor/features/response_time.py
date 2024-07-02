import numpy
from scipy import stats as stat

from extractor.features.context.packet_direction import PacketDirection

class ResponseTime:
    """ A summary of features based on the time difference
        between an outgoing packet and the following response. """

    def __init__(self, feature):
        self.feature = feature


    def get_dif(self) -> list:
        """Calculates the time difference in seconds between an outgoing packet 
           and the following response packet.
           return a list of time differences. """
        time_diff = []
        temp_packet = None
        temp_direction = None
        for packet, direction in self.feature.packets:
            if temp_direction == PacketDirection.FORWARD and direction == PacketDirection.REVERSE:
                time_diff.append(packet.time - temp_packet.time)
            temp_packet = packet
            temp_direction = direction
        return time_diff
    

    def get_var(self) -> float:
        """ calculates the variance of the time differences. """
        var = -1
        if len(self.get_dif()) != 0:
            var = numpy.var(self.get_dif())
        return var


    def get_avg(self) -> float:
        """ calculates the mean of the time differences. """
        avg = -1
        if len(self.get_dif()) != 0:
            avg = numpy.mean(self.get_dif())
        return avg


    def get_median(self) -> float:
        """ calculates the median of the time differences. """
        return numpy.median(self.get_dif())
    
    def get_mode(self) -> float:
        """ calculates the mode of the time differences. """
        mode = -1
        if len(self.get_dif()) != 0:
            mode = float(stat.mode(self.get_dif())[0])
        return mode


    def get_std(self) -> float:
        """ Calculates the standard deviation of the list of time differences. """
        std = -1
        if len(self.get_dif()) != 0:
            std = numpy.sqrt(self.get_var())
        return std


    def get_skew_avg_median(self) -> float:
        """ Calculates skewness of the time differences using average and median. """
        avg = self.get_avg()
        median = self.get_median()
        dif = 3 * (avg - median)
        std = self.get_std()
        skew = -10
        if std != 0:
            skew = dif / std
        return skew
    

    def get_skew_avg_mode(self) -> float:
        """ Calculates skewness of the time differences using average and mode. """
        avg = self.get_avg()
        mode = self.get_mode()
        dif = (float(avg) - mode)
        std = self.get_std()
        skew2 = -10
        if std != 0:
            skew2 = dif / float(std)
        return skew2


    def get_cov(self) -> float:
        """ calculates the coefficient of variance (COV) of the time differences """
        cov = -1
        if self.get_avg() != 0:
            cov = self.get_std() / self.get_avg()
        return cov


