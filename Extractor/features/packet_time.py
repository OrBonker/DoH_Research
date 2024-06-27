from datetime import datetime
import numpy
from scipy import stats as stat

class PacketTime:
    """This class extracts features related to the Packet Times."""
    count = 0

    def __init__(self, flow):
        self.flow = flow
        PacketTime.count += 1
        self.packet_times = None
    

    def get_packet_times(self) -> list: 
        """
        Gets a list of the times of the packets on a flow
        Returns: A list of the packet times.
        """
        if self.packet_times is not None:
            return self.packet_times
        first_packet_time = self.flow.packets[0][0].time
        packet_times = [packet.time - first_packet_time for packet, _ in self.flow.packets]
        return packet_times
    
    def relative_time_list(self) -> list:
        ''' Generates a list of relative times between consecutive packets. '''
        relative_time_list = []
        packet_times = self.get_packet_times()
        for index, time in enumerate(packet_times):
            if index == 0:
                relative_time_list.append(0)
            elif index < len(packet_times):
                relative_time_list.append(float(time - packet_times[index - 1]))
            elif index < 50:
                relative_time_list.append(0)
            else:
                break
        return relative_time_list
    
    def get_time_stamp(self) -> str:
        """ Returns the date and time in a human readeable format. """
        time = self.flow.packets[0][0].time
        date_time = datetime.fromtimestamp(time).strftime('%Y-%m-%d %H:%M:%S')
        return date_time
    
    def get_duration(self) -> float:
        """ Calculates the duration of a network flow. """
        return max(self.get_packet_times()) - min(self.get_packet_times())
    
    def get_var(self) -> float:
        """ Calculates the variation of packet times in a network flow. """
        return numpy.var(self.get_packet_times())

    def get_std(self) -> float:
        """ Calculates the standard deviation of packet times in a network flow. """
        return numpy.sqrt(self.get_var())
    
    def get_avg(self) -> float:
        """ Calculates the average packet times in a network flow. """
        avg = 0
        if self.get_packet_times() != 0:
            avg = numpy.mean(self.get_packet_times())
        return avg
    
    def get_median(self) -> float:
        """ Calculates the median of packet times in a network flow. """
        return numpy.median(self.get_packet_times())
    
    def get_mode(self) -> float:
        """ The mode of packet times in a network flow. """
        mode = -1
        if len(self.get_packet_times()) != 0:
            mode = float(stat.mode(self.get_packet_times())[0])
        return mode

    def get_skew_avg_median(self) -> float:
        """ Calculates skewness of packet times using average and median. """
        avg = self.get_avg()
        median = self.get_median()
        dif = 3 * (avg - median)
        std = self.get_std()
        skew = -10
        if std != 0:
            skew = dif / std
        return skew
    
    def get_skew_avg_mode(self) -> float:
        """ Calculates skewness of packet times using average and mode. """
        avg = self.get_avg()
        mode = self.get_mode()
        dif = (float(avg) - mode)
        std = self.get_std()
        skew = -10
        if std != 0:
            skew = dif / float(std)
        return skew

    def get_co_var(self) -> float:
        """ Calculates coefficient of variation of packet times. """
        co_var = -1
        if self.get_avg() != 0:
            co_var = self.get_std() / self.get_avg()
        return co_var



