import argparse
from scapy.all import *
from scapy.layers.l2 import Dot3, Ether
from scapy.layers.inet import IP, TCP

from enum import Enum

import dill as pickle
import pandas
import matplotlib.pyplot as pyplot


class PacketDirection(Enum):
    not_defined = 0
    client_to_server = 1
    server_to_client = 2


def pickle_pcap(pickle_file_input, pickle_file_output, client, server):
    print('opening file {}...'.format(pickle_file_input))
    count = 0
    interesting_packets = 0
    client_sequence_offset = None
    server_sequence_offset = None
    reader = RawPcapReader(pickle_file_input)
    packets_for_analysis = []
    client_recieved_window_scale = 0
    server_recieved_window_scale = 0
    (raw_packet, packet_metadata) = reader._read_packet()
    first_packet_index = None
    first_packet_seconds = None
    first_packet_subsecond = None
    while raw_packet is not None:
        # save reader data
        packet_data = Ether(raw_packet)
        metadata = packet_metadata
        # check if we reached end of pcap file
        try:
            (raw_packet, packet_metadata) = reader._read_packet()
        except:
            reader.close()
            break
        count += 1
        # filter LLC frames
        if type(packet_data) is Dot3:
            continue
        if type(packet_data) is Ether:
            # filter non IPv4 packets
            if packet_data.type != 0x0800:
                continue
            ip_packet = packet_data[IP]
            # filter non TCP packets
            if ip_packet.proto != 6:
                continue
            direction = PacketDirection.not_defined
            # check if client and server ip not null
            if (not client is None) and (not server is None):
                tcp_packet = ip_packet[TCP]
                (client_ip, client_port) = client.split(':')
                (server_ip, server_port) = server.split(':')
                # defining packet direction
                if ip_packet.src == client_ip:
                    if tcp_packet.sport != int(client_port):
                        continue
                    if tcp_packet.dport != int(server_port):
                        continue
                    if ip_packet.dst != server_ip:
                        continue
                    # packet source ip must be = to client_ip, 
                    # packet source port = client_port, 
                    # packet destination port = server_port, 
                    # packet destination ip = server_ip
                    direction = PacketDirection.client_to_server
                elif ip_packet.src == server_ip:
                    if ip_packet.sport != int(server_port):
                        continue
                    if ip_packet.dport != int(client_port):
                        continue
                    if ip_packet.dst != client_ip:
                        continue
                    # packet source ip must be = to server_ip, 
                    # packet source port = server_port, 
                    # packet destination port = client_port, 
                    # packet destination ip = client_ip
                    direction = PacketDirection.server_to_client
                else:
                    # packet is not interesting because is not part of the connection between provided client and server
                    continue
        interesting_packets += 1
        # metadata for first packet
        if interesting_packets == 1:
            first_packet_seconds = metadata.sec
            first_packet_subsecond = metadata.usec
            first_packet_index = count
        last_packet_seconds = metadata.sec
        last_packet_subsecond = metadata.usec
        last_packet_index = count
        first_packet_timestamp = first_packet_seconds + (first_packet_subsecond / 1000000)
        last_packet_timestamp = last_packet_seconds + (last_packet_subsecond / 1000000)
        current_packet_relative_timestamp = last_packet_timestamp - first_packet_timestamp
        # define current packet offset based on direction, throws error if direction is not defined
        if direction == PacketDirection.client_to_server:
            if client_sequence_offset is None:
                client_sequence_offset = tcp_packet.seq
            relative_sequence_offset = tcp_packet.seq - client_sequence_offset
        elif direction == PacketDirection.server_to_client:
            if server_sequence_offset is None:
                server_sequence_offset = tcp_packet.seq
            relative_sequence_offset = tcp_packet.seq - server_sequence_offset
        else:
            raise Exception('packet direction not defined')
        # if packet flags don't contain 'A' set acknowledge bit to 0
        if 'A' not in str(tcp_packet.flags):
            relative_offset_ack = 0
        # if packet flags contain 'A', determine current packet ack number
        else:
            if direction == PacketDirection.client_to_server:
                relative_offset_ack = tcp_packet.ack - server_sequence_offset
            else:
                relative_offset_ack = tcp_packet.ack - client_sequence_offset
        if (ip_packet.flags == 'MF') or (ip_packet.frag != 0):
            print('fragmented packet detected')
            break
        # determine packet data length, ihl = number of 4 byte blocks in header, dataofs = number of 4 byte blocks where data starts
        packet_payload_length = ip_packet.len - (ip_packet.ihl * 4) - (tcp_packet.dataofs * 4)
        if 'S' in str(tcp_packet.flags):
            for (option_name, option_value) in tcp_packet.options:
                if option_name == 'WScale':
                    if direction == PacketDirection.client_to_server:
                        client_recieved_window_scale = option_value
                    else:
                        server_recieved_window_scale = option_value
                    break

        packet_info = {}
        packet_info['direction'] = direction
        packet_info['index'] = last_packet_index
        packet_info['relative_timestamp'] = current_packet_relative_timestamp
        packet_info['tcp_flags'] = str(tcp_packet.flags)
        packet_info['sequence'] = relative_sequence_offset
        packet_info['ackno'] = relative_offset_ack
        packet_info['payload_length'] = packet_payload_length
        if direction == PacketDirection.client_to_server:
            packet_info['window'] = tcp_packet.window << client_recieved_window_scale
        else:
            packet_info['window'] = tcp_packet.window << server_recieved_window_scale
        packets_for_analysis.append(packet_info)
    print('{} contains {} packets and {} interesting packets'.format(pickle_file_input, count, interesting_packets))
    print('first interesting packet in connection: Packet #{}, {}'.format(first_packet_index,
                                                                          formatted_timestamp(first_packet_seconds,
                                                                                              first_packet_subsecond)))
    print('last interesting packet in connection: Packet #{}, {}'.format(last_packet_index,
                                                                         formatted_timestamp(last_packet_seconds,
                                                                                             last_packet_subsecond)))
    print('writing to pickle file {}...'.format(pickle_file_output), end='')
    with open(pickle_file_output, 'wb') as pickle_file:
        pickle.dump(client, pickle_file)
        pickle.dump(server, pickle_file)
        pickle.dump(packets_for_analysis, pickle_file)
    print('done')


def analyze_pickle(pickle_input_file):
    packets_for_analysis = []
    with open(pickle_input_file, 'rb') as pickle_file:
        client_address_port = pickle.load(pickle_file)
        server_address_port = pickle.load(pickle_file)
        packets_for_analysis = pickle.load(pickle_file)

    print('$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$')
    print('TCP session between client {} and server {}'.format(client_address_port, server_address_port))
    print('$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$')
    unformatted_packet_info = '[{ordinal:>5}]{timestamp:>10.6f}s flags={flags:<3s} sequence={sequence:<9d} \
    ack={ack:<9d} length={length:<6d} window={window:<9d}'
    for packet_info in packets_for_analysis:
        direction = packet_info['direction']
        if direction == PacketDirection.client_to_server:
            print('{}'.format('-->'), end='')
        else:
            print('{:>60}'.format('<--'), end='')
        print(unformatted_packet_info.format(ordinal=packet_info['index'],
                                             timestamp=packet_info['relative_timestamp'],
                                             flags=packet_info['tcp_flags'],
                                             sequence=packet_info['sequence'],
                                             ack=packet_info['ackno'],
                                             length=packet_info['payload_length'],
                                             window=packet_info['window']))


def plot(pickle_input_file):
    packets_for_analysis = []
    with open(pickle_input_file, 'rb') as pickle_file:
        client_address_port = pickle.load(pickle_file)
        server_address_port = pickle.load(pickle_file)
        packets_for_analysis = pickle.load(pickle_file)
    client_packets = []
    for packet_info in packets_for_analysis:
        if packet_info['direction'] == PacketDirection.server_to_client:
            continue
        if 'S' in packet_info['tcp_flags']:
            continue
        client_packets.append({'Time': packet_info['relative_timestamp'],
                               'Client window size': packet_info['window'],
                               'Client ack no': packet_info['ackno']})
    data_frame = pandas.DataFrame(data=client_packets)
    figure, ax1 = pyplot.subplots()
    ax2 = ax1.twinx()
    data_frame.plot(x='Time', y='Client window size', color='r', ax=ax1)
    data_frame.plot(x='Time', y='Client ack no', color='b', ax=ax2)
    ax1.tick_params('y', colors='r')
    ax2.tick_params('y', colors='b')
    pyplot.show()
    pyplot.close()


def formatted_timestamp(seconds, subsecond):
    timestamp_seconds_string = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(seconds))
    return '{} and {} microseconds'.format(timestamp_seconds_string, subsecond)


# opening pcap file should be done in the main script
if __name__ == '__main__':
    # creating arguments for pcap file
    parser = argparse.ArgumentParser(description='pcap reader')
    parser.add_argument('script_type', metavar='pickle/analyze script', help='script type (pickle/analyze)')
    parser.add_argument('--pcap', metavar='pcap file name', help='pcap file to parse', required=False)
    parser.add_argument('--out', metavar='output file', help='file in which packets are stored', required=False)
    parser.add_argument('--input', metavar='input file', help='file from which packets are read', required=False)
    parser.add_argument('--client', metavar='client ip', help='client ip', required=False)
    parser.add_argument('--server', metavar='server ip', help='server ip', required=False)
    args = parser.parse_args()
    script_type = args.script_type
    input_file = args.pcap
    output_file = args.out
    pickle_input_file = args.input
    client = args.client
    server = args.server
    # check if entered file name is valid
    if script_type == 'pickle':
        if not os.path.isfile(input_file):
            print('{} is not a valid file.'.format(input_file))
            sys.exit(-1)
        if output_file is not None:
            pickle_pcap(input_file, output_file, client, server)
        else:
            print('output file not provided')
            sys.exit(-1)
    elif script_type == 'analyze':
        if pickle_input_file is not None:
            analyze_pickle(pickle_input_file)
        else:
            print('input file not provided')
            sys.exit(-1)
    elif script_type == 'plot':
        if pickle_input_file is not None:
            plot(pickle_input_file)
        else:
            print('input file not provided')
            sys.exit(-1)
    sys.exit(0)
