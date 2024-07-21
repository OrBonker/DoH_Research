import os
import zipfile
import json
import sys
from scapy.all import rdpcap
from scapy.layers.tls.record import TLSApplicationData
from scapy.layers.inet import IP, TCP

# Add project root to sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)

from features.context.packet_direction import PacketDirection
from constants import CLUMP_TIMEOUT

class Clump:
    """ The Clump class represents a group of packets traveling in the same direction, 
        where the time between successive packets is very short (a "clump").
    """

    def __init__(self, direction):
        self.direction = direction
        self.packets = 0
        self.size = 0
        self.first_timestamp = 0
        self.latest_timestamp = 0   
     
    def add_packet(self, packet):
        """ Adds a packet to the clump. """
        if self.first_timestamp == 0:
            self.first_timestamp = packet.time
        self.packets += 1
        if TLSApplicationData in packet:
            self.size += len(packet[TLSApplicationData])
        self.latest_timestamp = packet.time

    def accepts(self, packet, direction):
        """ Determines whether a packet can be added to the current clump """
        if direction != self.direction:
            return False
        if self.latest_timestamp != 0 and packet.time - self.latest_timestamp > CLUMP_TIMEOUT:
            return False
        return True
    
    def duration(self):
        """ Calculates the duration of the clump. """
        return self.latest_timestamp - self.first_timestamp


class FlowClumpsContainer:
    """ Class represents a sequence of Clump objects within a network flow."""

    def __init__(self, flow, clumps):
        self.flow = flow
        self.clumps = clumps

    def output(self):
        """ Generates a summary of the clumps
            Returns the results (list of lists, each representing a clump) and the count of clumps. """
        results = []
        latest_clump_end_timestamp = None
        count = 0
        for c in self.clumps:
            if latest_clump_end_timestamp is None:
                latest_clump_end_timestamp = c.first_timestamp
            count += 1
            results.append([
                float(c.first_timestamp - latest_clump_end_timestamp),  # inter-arrival duration
                float(c.duration()),
                c.size,
                c.packets,
                1 if c.direction == PacketDirection.FORWARD else -1
            ])
            latest_clump_end_timestamp = c.latest_timestamp
        return results, count

    def to_json_file(self, directory):
        """ Saves the clump data to a JSON file. """
        preferred_name = '{}_{}-{}_{}.json'.format(self.flow['src'], self.flow['sport'],
                                                   self.flow['dst'], self.flow['dport'])
        file_path = os.path.join(directory, preferred_name)
        print(f"Saving JSON to: {file_path}")
        output, count = self.output()
        # Temporarily removing the clump count check for debugging
        # if count < 5:
        #     print("Clump count is less than 5, not saving the file.")
        #     return
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                contents = json.load(f)
                contents.append(output)
        else:
            contents = [output]
        with open(file_path, 'w') as f:
            json.dump(contents, f, indent=2)
        print(f"File saved: {file_path}")



