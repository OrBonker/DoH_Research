import numpy as np
from scipy import stats as stat
import os
import sys

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)

from features.context.packet_direction import PacketDirection

class ResponseTime:
    """ A summary of features based on the time difference
        between an outgoing packet and the following response. """

    def __init__(self, packets):
        self.packets = packets
        self.timestamps = [packet.time for packet in packets]


    def get_dif(self) -> list:
        """Calculates the time difference in seconds between an outgoing packet 
           and the following response packet.
           Returns a list of time differences. """
        time_diff = []
        temp_packet = None
        for packet in self.packets:
            if temp_packet and temp_packet.direction == PacketDirection.FORWARD and packet.direction == PacketDirection.REVERSE:
                time_diff.append(float(packet.time - temp_packet.time))
            temp_packet = packet
        return time_diff

    def get_var(self) -> float:
        """ Calculates the variance of the time differences. """
        diffs = self.get_dif()
        return np.var(diffs) if diffs else 0.0

    def get_avg(self) -> float:
        """ Calculates the mean of the time differences. """
        diffs = self.get_dif()
        return np.mean(diffs) if diffs else 0.0

    def get_median(self) -> float:
        """ Calculates the median of the time differences. """
        diffs = self.get_dif()
        return np.median(diffs) if diffs else 0.0
    
    def get_mode(self) -> float:
        """ Calculates the mode of the time differences. """
        diffs = self.get_dif()
        return float(stat.mode(diffs).mode[0]) if diffs else 0.0

    def get_std(self) -> float:
        """ Calculates the standard deviation of the list of time differences. """
        return np.sqrt(self.get_var())

    def get_skew_avg_median(self) -> float:
        """ Calculates skewness of the time differences using average and median. """
        avg = self.get_avg()
        median = self.get_median()
        dif = 3 * (avg - median)
        std = self.get_std()
        return dif / std if std != 0 else 0.0

    def get_skew_avg_mode(self) -> float:
        """ Calculates skewness of the time differences using average and mode. """
        avg = self.get_avg()
        mode = self.get_mode()
        dif = avg - mode
        std = self.get_std()
        return dif / std if std != 0 else 0.0

    def get_cov(self) -> float:
        """ Calculates the coefficient of variance (COV) of the time differences. """
        avg = self.get_avg()
        return self.get_std() / avg if avg != 0 else 0.0
