import argparse
import os
import sys
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(project_root)
from scapy.all import load_layer, AsyncSniffer , rdpcap
from extractor.flow_session import FlowSession 


def create_sniffer(input_file, input_interface, output_mode, output_file):
    assert (input_file is None) ^ (input_interface is None)
    NewFlowSession = FlowSession.generate_session_class(output_mode, output_file)

    if input_file is not None:
        # Offline mode
        packets = rdpcap(input_file)
        
        # Initialize the session
        session = NewFlowSession()
        
        # Process packets
        for packet in packets:
            session.on_packet_received(packet)
        
        # Final garbage collection
        session.garbage_collect(None)
        return None  # No AsyncSniffer needed for offline mode

    else:
        # Online mode
        def packet_handler(packet):
            session.on_packet_received(packet)

        session = NewFlowSession()
        return AsyncSniffer(iface=input_interface, filter='tcp port 443', prn=packet_handler, store=False)

def main():
    parser = argparse.ArgumentParser()

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-n', '--online', action='store', dest='input_interface',
                             help='capture online data from INPUT_INTERFACE')
    input_group.add_argument('-f', '--offline', action='store', dest='input_file',
                             help='capture offline data from INPUT_FILE')

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