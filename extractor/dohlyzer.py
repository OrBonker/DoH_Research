import argparse
import os
import csv
import sys
from scapy.all import load_layer, AsyncSniffer, rdpcap, IP
from flow_session import FlowSession

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)

# Column headers for the CSV file
CSV_HEADERS = [
    'SourceIP', 'DestinationIP', 'SourcePort', 'DestinationPort', 'TimeStamp',
    'Duration', 'FlowBytesSent', 'FlowSentRate', 'FlowBytesReceived',
    'FlowReceivedRate', 'PacketLengthVariance', 'PacketLengthStandardDeviation',
    'PacketLengthMean', 'PacketLengthMedian', 'PacketLengthMode',
    'PacketLengthSkewFromMedian', 'PacketLengthSkewFromMode',
    'PacketLengthCoefficientofVariation', 'PacketTimeVariance',
    'PacketTimeStandardDeviation', 'PacketTimeMean', 'PacketTimeMedian',
    'PacketTimeMode', 'PacketTimeSkewFromMedian', 'PacketTimeSkewFromMode',
    'PacketTimeCoefficientofVariation', 'ResponseTimeVariance',
    'ResponseTimeStandardDeviation', 'ResponseTimeMean', 'ResponseTimeMedian',
    'ResponseTimeMode', 'ResponseTimeSkewFromMedian', 'ResponseTimeSkewFromMode',
    'ResponseTimeCoefficientofVariation', 'DoH'
]

def write_csv_headers(output_file):
    """Write the CSV headers to the output file if it doesn't exist."""
    if not os.path.isfile(output_file):
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(CSV_HEADERS)

def process_pcap_file(input_file, output_mode, output_file, append=False):
    if not append:
        write_csv_headers(output_file)
    
    NewFlowSession = FlowSession.generate_session_class(output_mode, output_file)
    session = NewFlowSession(append=append)
    
    packets = rdpcap(input_file)
    for packet in packets:
        if IP in packet:
            session.on_packet_received(packet)

    session.garbage_collect(None)

def process_pcap_folder(input_folder, output_mode, output_file):
    first_file = True
    for file_name in os.listdir(input_folder):
        if file_name.endswith('.pcap') or file_name.endswith('.pcapng'):
            pcap_file_path = os.path.join(input_folder, file_name)
            print(f"Processing file: {pcap_file_path}")
            process_pcap_file(pcap_file_path, output_mode, output_file, append=not first_file)
            first_file = False
            print(f"Finished processing {file_name}")

def create_sniffer(input_file, input_interface, output_mode, output_file):
    assert (input_file is None) ^ (input_interface is None)
    if input_file is not None:
        if os.path.isdir(input_file):
            process_pcap_folder(input_file, output_mode, output_file)
        else:
            process_pcap_file(input_file, output_mode, output_file)
        return None
    else:
        def packet_handler(packet):
            if IP in packet:
                session.on_packet_received(packet)

        NewFlowSession = FlowSession.generate_session_class(output_mode, output_file)
        session = NewFlowSession()
        return AsyncSniffer(iface=input_interface, filter='tcp port 443', prn=packet_handler, store=False)

def main():
    parser = argparse.ArgumentParser()

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-n', '--online', action='store', dest='input_interface',
                             help='capture online data from INPUT_INTERFACE')
    input_group.add_argument('-f', '--offline', action='store', dest='input_file',
                             help='capture offline data from INPUT_FILE or all files in INPUT_FOLDER')

    output_group = parser.add_mutually_exclusive_group(required=True)
    output_group.add_argument('-c', '--csv', action='store_const', const='flow', dest='output_mode',
                              help='output flows as csv')
    output_group.add_argument('-s', '--json', action='store_const', const='sequence', dest='output_mode',
                              help='output flow segments as json')

    parser.add_argument('output', help='output file name (in flow mode) or directory (in sequence mode)')
    args = parser.parse_args()

    load_layer('tls')

    sniffer = create_sniffer(args.input_file, args.input_interface, args.output_mode, args.output)

    if sniffer:
        sniffer.start()
        try:
            sniffer.join()
        except KeyboardInterrupt:
            sniffer.stop()
        finally:
            sniffer.join()

if __name__ == '__main__':
    main()
