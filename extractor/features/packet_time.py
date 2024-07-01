import numpy
from datetime import datetime
from scipy import stats as stat
from scapy.all import rdpcap, PacketList

class PacketTime:
    """This class extracts features related to the Packet Times."""

    def __init__(self, packets):
        if isinstance(packets, PacketList):
            self.packets = packets
        else:
            raise ValueError("Expected a PacketList object from Scapy.")

        self.packet_times = None
    
    def get_packet_times(self) -> list:
        """
        Gets a list of the times of the packets in the flow.
        Returns: A list of the packet times.
        """
        if self.packet_times is not None:
            return self.packet_times
        first_packet_time = self.packets[0].time
        packet_times = [packet.time - first_packet_time for packet in self.packets]
        self.packet_times = packet_times
        return packet_times
    
    def relative_time_list(self) -> list:
        """ Generates a list of relative times between consecutive packets. """
        relative_time_list = []
        packet_times = self.get_packet_times()
        for index, time in enumerate(packet_times):
            if index == 0:
                relative_time_list.append(0)
            else:
                relative_time_list.append(float(time - packet_times[index - 1]))
        return relative_time_list
    
    def get_time_stamp(self) -> str:
        """ Returns the date and time in a human-readable format. """
        time = self.packets[0].time
        date_time = datetime.fromtimestamp(time).strftime('%Y-%m-%d %H:%M:%S')
        return date_time
    
    def get_duration(self) -> float:
        """ Calculates the duration of the network flow. """
        packet_times = self.get_packet_times()
        return max(packet_times) - min(packet_times)
    
    def get_var(self) -> float:
        """ Calculates the variation of packet times in the network flow. """
        packet_times = numpy.array(self.get_packet_times(), dtype=numpy.float64)
        return numpy.var(packet_times)

    def get_std(self) -> float:
        """ Calculates the standard deviation of packet times in the network flow. """
        return numpy.sqrt(self.get_var())
    
    def get_avg(self) -> float:
        """ Calculates the average packet time in the network flow. """
        packet_times = numpy.array(self.get_packet_times(), dtype=numpy.float64)
        return numpy.mean(packet_times)
    
    def get_median(self) -> float:
        """ Calculates the median of packet times in the network flow. """
        packet_times = numpy.array(self.get_packet_times(), dtype=numpy.float64)
        return numpy.median(packet_times)
    
    def get_mode(self) -> float:
        """ The mode of packet times in the network flow. """
        packet_times = numpy.array(self.get_packet_times(), dtype=numpy.float64)
        mode = -1
        if len(packet_times) != 0:
            mode = float(stat.mode(packet_times)[0])
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
        avg = self.get_avg()
        std = self.get_std()
        if avg != 0:
            co_var = std / avg
        return co_var

if __name__ == "__main__":
    # Replace 'your_pcap_file.pcap' with your actual pcap file path
    pcap_file = '/workspaces/DoH_Research/extractor/dump_00002_20200114114901.pcap'
    packets = rdpcap(pcap_file)

    # Create an instance of PacketTime with the loaded packets
    packet_time_analysis = PacketTime(packets)
    

    # Example of using the methods in PacketTime
    print("skew_avg_median:", packet_time_analysis.get_skew_avg_median())
    print("skew_avg_mode:", packet_time_analysis.get_skew_avg_mode())
