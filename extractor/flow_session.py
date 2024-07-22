import csv
import os
import sys
from collections import defaultdict

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)

from scapy.layers.tls.record import TLS, TLSApplicationData
from scapy.sessions import DefaultSession

from features.context.packet_direction import PacketDirection
from features.context.packet_key import get_packet_flow_key
from flow import Flow
from time_series.processor import Processor

EXPIRED_UPDATE = 40

class FlowSession(DefaultSession):
    """Creates a list of network flows."""

    def __init__(self, prn=None, store=False, *args, **kwargs):
        self.flows = {}
        self.csv_line = 0
        if self.output_mode == 'flow':
            output = open(self.output_file, 'w')
            self.csv_writer = csv.writer(output)
        self.packets_count = 0
        self.clumped_flows_per_label = defaultdict(list)
        super(FlowSession, self).__init__(prn, store, *args, **kwargs)


    def toPacketList(self):
        """ Calls garbage_collect before returning the packet list from the parent class. """
        self.garbage_collect(None)
        return super(FlowSession, self).toPacketList()


    def on_packet_received(self, packet):
        """ Handles packets as they are received. """

        count = 0
        direction = PacketDirection.FORWARD

        if self.output_mode != 'flow':
            if TLS not in packet:
                return
            if TLSApplicationData not in packet:
                return
            if len(packet[TLSApplicationData]) < 40:
                # PING frame (len = 34) or other useless frames
                return

        self.packets_count += 1
        # Creates a key variable to check
        packet_flow_key = get_packet_flow_key(packet, direction)
        flow = self.flows.get((packet_flow_key, count))

        # If there is no forward flow with a count of 0
        if flow is None:
            # There might be one of it in reverse
            direction = PacketDirection.REVERSE
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))
            if flow is None:
                # If no flow exists create a new flow
                direction = PacketDirection.FORWARD
                flow = Flow(packet, direction)
                packet_flow_key = get_packet_flow_key(packet, direction)
                self.flows[(packet_flow_key, count)] = flow

            elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
                # If the packet exists in the flow but the packet is sent
                # after too much of a delay than it is a part of a new flow.
                expired = EXPIRED_UPDATE
                while (packet.time - flow.latest_timestamp) > expired:
                    count += 1
                    expired += EXPIRED_UPDATE
                    flow = self.flows.get((packet_flow_key, count))
                    if flow is None:
                        flow = Flow(packet, direction)
                        self.flows[(packet_flow_key, count)] = flow
                        break

        elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
            expired = EXPIRED_UPDATE
            while (packet.time - flow.latest_timestamp) > expired:
                count += 1
                expired += EXPIRED_UPDATE
                flow = self.flows.get((packet_flow_key, count))
                if flow is None:
                    flow = Flow(packet, direction)
                    self.flows[(packet_flow_key, count)] = flow
                    break

        flow.add_packet(packet, direction)
        if self.packets_count % 10000 == 0 or (flow.duration > 120 and self.output_mode == 'flow'):
            print('Packet count: {}'.format(self.packets_count))
            self.garbage_collect(packet.time)


    def get_flows(self) -> list:
        """ Returns the list of current flows. """
        return self.flows.values()
    

    def garbage_collect(self, latest_time) -> None:
        """ Cleans up old or expired flows.
            Writes flow data and deletes flows that have been processed. """
        
        print('Garbage Collection Began. Flows = {}'.format(len(self.flows)))
        keys = list(self.flows.keys())
        for k in keys:
            flow = self.flows.get(k)
            if self.output_mode == 'flow':
                if latest_time is None or latest_time - flow.latest_timestamp > EXPIRED_UPDATE or flow.duration > 90:
                    data = flow.get_data()
                    if self.csv_line == 0:
                        self.csv_writer.writerow(data.keys())
                    self.csv_writer.writerow(data.values())
                    self.csv_line += 1
                    del self.flows[k]
            else:
                if latest_time is None or latest_time - flow.latest_timestamp > EXPIRED_UPDATE:
                    output_dir = os.path.join(self.output_file, 'doh' if flow.is_doh() else 'ndoh')
                    os.makedirs(output_dir, exist_ok=True)
                    proc = Processor(flow)
                    flow_clumps = proc.create_flow_clumps_container()
                    flow_clumps.to_json_file(output_dir)
                    del self.flows[k]
        print('Garbage Collection Finished. Flows = {}'.format(len(self.flows)))


    def generate_session_class(output_mode, output_file):
        """ Generates a new session class with specified output_mode and output_file. """
        return type('NewFlowSession', (FlowSession,), {
            'output_mode': output_mode,
            'output_file': output_file,
        })
    

    