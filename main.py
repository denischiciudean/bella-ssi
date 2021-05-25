from scapy.all import *
from pprint import pprint
import sys

from scapy.layers.inet import TCP, IP, ICMP

FLAGS = {
    'F': 'FIN',
    'S': 'SYN',
    'R': 'RST',
    'P': 'PSH',
    'A': 'ACK',
    'U': 'URG',
    'E': 'ECE',
    'C': 'CWR',
}


def parse_packet(packet):
    ip_layer = packet[IP]
    tcp_layer = None
    icmp_layer = None
    try:
        tcp_layer = packet[TCP]
    except Exception as e:
        pass

    try:
        icmp_layer = packet[ICMP]
    except Exception as e:
        pass

    pac = [FLAGS[x] for x in packet.sprintf('%TCP.flags%')] if TCP in packet else []

    return {
        'has_tcp': True if tcp_layer else False,
        'has_icmp': True if icmp_layer else False,
        'src': ip_layer.src,
        'dst': ip_layer.dst,
        'sport': tcp_layer.sport if tcp_layer else None,
        'dport': tcp_layer.dport if tcp_layer else None,
        'tcp_flags': f",".join(pac)
    }


def get_packet_signature(packet, fields=[]):
    return f"{packet['src']}->({packet['dst']}:{packet['dport']}):{1 if packet['has_tcp'] else 0}:({packet['tcp_flags']})"


if __name__ == '__main__':
    # GET THE FILE FROM COMMAND LINE
    file = sys.argv[1]
    print(F"reading file {file}")
    # READ THE FILE USING SCAPY
    data = rdpcap(file)

    # pprint(data.make_table(lambda x: (x[IP].dst if IP in x else None, x[TCP].dport if TCP in x else None,
    #                                   x[TCP].sprintf("%flags%") if TCP in x else None)))
    # exit()

    # PARSE EACH FILE AND GET THE RELEVANT DATA WE WANT TO SCAN
    parsed_packets = [parse_packet(packet) for packet in data[TCP]]

    requests = []

    for signature in set([get_packet_signature(packet) for packet in parsed_packets]):
        packets = [packet for packet in parsed_packets if get_packet_signature(packet) == signature]

        requests.append({
            'signature': signature,
            'total': len(packets)
        })

    pprint(requests)
