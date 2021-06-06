from scapy.all import *
from pprint import pprint
import sys
import matplotlib.pyplot as plt

from scapy.layers.inet import TCP, IP, ICMP

FILE_DUMP = ''

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
        'tcp_flags': f",".join(pac),
        'psize': len(packet),
        'timestamp': round(packet.time - 0.25)
    }


def create_file_dump(packets):
    pass


def get_packet_signature(packet, fields=[]):
    return f"{packet['src']}:{packet['sport']}->({packet['dst']}:{packet['dport']}):{1 if packet['has_tcp'] else 0}:({packet['tcp_flags']}):[{packet['psize']}]"


if __name__ == '__main__':
    # GET THE FILE FROM COMMAND LINE
    file = sys.argv[1]
    print(F"reading file {file}")

    # READ THE FILE USING SCAPY
    data = rdpcap(file)

    # PARSE EACH FILE AND GET THE RELEVANT DATA WE WANT TO SCAN
    parsed_packets = [parse_packet(packet) for packet in data[TCP]]

    requests = []

    # for signature in set([get_packet_signature(packet) for packet in parsed_packets]):
    #     packets = [packet for packet in parsed_packets if get_packet_signature(packet) == signature]
    #
    #     requests.append({
    #         'signature': signature,
    #         'total': len(packets)
    #     })

    # UNIQUE IPS
    unique_ips = set([p['src'] for p in parsed_packets])

    outbound = {}

    FILE_DUMP = FILE_DUMP + "UNIQUE SOURCE IPS \n"

    for ip in unique_ips:
        outbound[ip] = {}
        total = 0
        pa = [p for p in parsed_packets if p['src'] == ip]
        pa = sorted(pa, key=lambda x: x['timestamp'])

        outbound[ip]['destination_ips'] = set([p['dst'] for p in pa])
        outbound[ip]['total'] = len(pa)
        outbound[ip]['first_packet'] = pa[0]['timestamp']
        outbound[ip]['last_packet'] = pa[len(pa) - 1]['timestamp']
        FILE_DUMP = FILE_DUMP + F"{ip} with a total of {outbound[ip]['total']} packets sent | {outbound[ip]['first_packet']} -> {outbound[ip]['last_packet']}\n"

    with open('res.txt', 'w') as file:
        file.write(FILE_DUMP)

    timestamps = [pa['timestamp'] for pa in parsed_packets]
    counts = {}
    psizes = []
    # for ip in unique_ips:
    #     counts[ip] = []
    for t in timestamps:
        # counts[ip].append(len([pa for pa in parsed_packets if pa['timestamp'] == t and pa['src'] == ip]))
        psizes.append(sum([pa['psize'] for pa in parsed_packets if pa['timestamp'] == t]))

    # fig, ax = plt.subplots()
    # for count in counts.items():
    #     ax.plot(timestamps, count[1], label=F"IP : {count[0]}")
    #
    # ax.set(xlabel='time (s)', ylabel='Total Packets Sent',
    #        title='Packets sent per second')
    # ax.grid()
    #
    # plt.savefig('res.jpg')
    # plt.legend(loc='best')
    # plt.show()

    fig, ax = plt.subplots()
    ax.plot(range(0, len(parsed_packets)), [p['psize'] for p in sorted(parsed_packets, key=lambda x: x['timestamp'])],
            label=F"Total Data Transfer")

    ax.set(xlabel='time (s)', ylabel='Bytes Sent',
           title='Bytes Sent Per Second')
    ax.grid()

    # plt.savefig('res.jpg')
    plt.legend(loc='best')
    plt.show()
