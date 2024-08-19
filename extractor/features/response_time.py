import numpy as np
from scipy import stats as stat
from collections import deque
from context.packet_direction import PacketDirection

class ResponseTime:
    """ A summary of features based on the time difference
        between an outgoing packet and the following response. """

    def __init__(self, packets, directions):
        self.packets = packets
        self.directions = directions
        self.timestamps = [packet.time for packet in packets]

        # Debugging output to check the packets and directions
       # for i, packet in enumerate(self.packets):
        #    print(f"Packet: {packet.summary()}, Direction: {self.directions[i]}")

    def get_dif(self) -> list:
        """Calculate time differences between FORWARD and REVERSE packets."""
        forward_times = []
        time_diffs = []

        for packet, direction in zip(self.packets, self.directions):
            if direction.value == PacketDirection.FORWARD.value:
                forward_times.append(packet.time)
            elif direction.value == PacketDirection.REVERSE.value and forward_times:
                # Pair the first forward packet with the first reverse packet
                forward_time = forward_times.pop(0)
                time_diff = packet.time - forward_time
                time_diffs.append(float(time_diff))

        return time_diffs

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
