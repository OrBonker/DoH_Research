import csv
import os
from collections import defaultdict, Counter
from scapy.layers.tls.record import TLS, TLSApplicationData
from scapy.sessions import DefaultSession
from scapy.all import IP
from features.context.packet_direction import PacketDirection
from features.context.packet_key import get_packet_flow_key
from flow import Flow
from time_series.processor import Processor

EXPIRED_UPDATE = 40

# List of server IPs
server_ips = {'141.95.67.229', '8.8.4.4', '8.8.8.8', '1.0.0.1', '1.1.1.1', '94.140.14.14', '94.140.15.15', '141.95.55.205'}

def get_packet_direction(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if src_ip in server_ips:
            return PacketDirection.REVERSE
        elif dst_ip in server_ips:
            return PacketDirection.FORWARD
    return None

class FlowSession(DefaultSession):
    """Creates a list of network flows."""

    def __init__(self, prn=None, store=False, *args, **kwargs):
        self.flows = {}
        self.csv_line = 0
        self.append = kwargs.pop('append', False)
        if self.output_mode == 'flow':
            output = open(self.output_file, 'a', newline='')
            self.csv_writer = csv.writer(output)
        self.packets_count = 0
        self.clumped_flows_per_label = defaultdict(list)
        super(FlowSession, self).__init__(prn, store, *args, **kwargs)
        
    def toPacketList(self):
        """ Calls garbage_collect before returning the packet list from the parent class. """
        self.garbage_collect(None)
        return super(FlowSession, self).toPacketList()



    def on_packet_received(self, packet):
        """Handles packets as they are received."""
        
        # Drop packets not connected to the specified server IPs
        if IP not in packet or (packet[IP].src not in server_ips and packet[IP].dst not in server_ips):
            return
        
        # Determine packet direction based on the identified server IPs
        direction = get_packet_direction(packet)
        
        # Proceed with processing if direction is determined
        if direction is None:
            return

        # Skip non-TCP packets
        if not packet.haslayer('TCP'):
            return

        if self.output_mode != 'flow':
            if TLS not in packet or TLSApplicationData not in packet or len(packet[TLSApplicationData]) < 40:
                return

        self.packets_count += 1

        packet_flow_key = get_packet_flow_key(packet, direction)
        flow = self.flows.get((packet_flow_key, 0))

        if flow is None:
            direction = PacketDirection.REVERSE if direction == PacketDirection.FORWARD else PacketDirection.FORWARD
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, 0))
            if flow is None:
                flow = Flow(packet, direction)
                packet_flow_key = get_packet_flow_key(packet, direction)
                self.flows[(packet_flow_key, 0)] = flow
            elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
                expired = EXPIRED_UPDATE
                count = 0
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
            count = 0
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

    import csv

    def garbage_collect(self, latest_time) -> None:
        """ Cleans up old or expired flows. """
        
        print('Garbage Collection Began. Flows = {}'.format(len(self.flows)))
        keys = list(self.flows.keys())

        for k in keys:
            flow = self.flows.get(k)

            if self.output_mode == 'flow':
                if latest_time is None or latest_time - flow.latest_timestamp > EXPIRED_UPDATE or flow.duration > 90:
                    print(f"Saving flow data for flow: {flow}")
                    data = flow.get_data()
                    self.csv_writer.writerow(data.values())
                    self.csv_line += 1
                    del self.flows[k]
            else:
                print(f"Processing clumps for flow: {flow}")

                output_dir = 'C:/Users/or26bo/Desktop/DoH_Research/visualizer'
                os.makedirs(output_dir, exist_ok=True)

                # Open a CSV file for writing clump data
                clump_csv_file = os.path.join(output_dir, 'clumps_output.csv')

                with open(clump_csv_file, mode='a', newline='') as csvfile:
                    csv_writer = csv.writer(csvfile)

                    # Process the flow and get the clumps
                    proc = Processor(flow)
                    flow_clumps = proc.create_flow_clumps_container()

                    # Check if clumps are created
                    clumps = list(flow_clumps.clumps)

                    if len(clumps) == 0:
                        continue

                    # Write headers if necessary (only for the first time)
                    csv_writer.writerow(['Clump Interarrival', 'Clump Duration', 'Clump Size', 'Clump Packets', 'Clump Direction'])

                    # Write clump data to the CSV file
                    for clump in clumps:
                        csv_writer.writerow([
                            float(clump.first_timestamp - clump.latest_timestamp),  # Interarrival time
                            float(clump.duration()),  # Duration
                            clump.size,  # Clump size
                            clump.packets,  # Number of packets
                            1 if clump.direction == PacketDirection.FORWARD else -1  # Clump direction
                        ])
                del self.flows[k]

        print('Garbage Collection Finished. Flows = {}'.format(len(self.flows)))

    @staticmethod
    def generate_session_class(output_mode, output_file):
        """ Generates a new session class with specified output_mode and output_file. """
        return type('NewFlowSession', (FlowSession,), {
            'output_mode': output_mode,
            'output_file': output_file,
        })
