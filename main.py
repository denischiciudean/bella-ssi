from scapy.all import *
import sys
import matplotlib.pyplot as plt
from tabulate import tabulate

from scapy.layers.inet import TCP, IP, ICMP

FILE_DUMP = ''

# FLAGURIILE POSIBILE PENTRU
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


# PARSARE DE PACHETE INTR-UN MOD MAI USOR INTELIGBIL
def parse_packet(packet):
    # LUAM DATE DOAR DESPRE TCP
    ip_layer = packet[IP]

    tcp_layer = None
    icmp_layer = None

    # DACA PACHETUL NU CONTINE TCP IGNORAM PACHETU
    try:
        tcp_layer = packet[TCP]
    except Exception as e:
        pass

    # INCERCAM SA EXTRAGEM DATE SI DE PE ICMP
    # try:
    #     icmp_layer = packet[ICMP]
    # except Exception as e:
    #     pass

    # EXTRAGEM FLAGURIILE
    pac = [FLAGS[x] for x in packet.sprintf('%TCP.flags%')] if TCP in packet else []

    # RETURNAM UN DICTIONAR CU DATELE NECESARE
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

    #AICI BAZAT PE UN PACHET, CREEM O SEMNATURA UNICA REPREZENTATIVA
def get_packet_signature(packet, fields=[]):
    return f"{packet['src']}:{packet['sport']}->({packet['dst']}:{packet['dport']}):{1 if packet['has_tcp'] else 0}:({packet['tcp_flags']}):[{packet['psize']}]"


def generate_graphs(folder_name, parsed_packets):
    timestamps = [pa['timestamp'] for pa in parsed_packets]
    counts = {}
    psizes = []
    for ip in unique_ips:
        counts[ip] = []
        for t in timestamps:
            counts[ip].append(len([pa for pa in parsed_packets if pa['timestamp'] == t and pa['src'] == ip]))
            psizes.append(sum([pa['psize'] for pa in parsed_packets if pa['timestamp'] == t]))

    # CREEM PRIMUL GRAFIC

    fig, ax = plt.subplots()
    for count in counts.items():
        ax.plot(timestamps, count[1], label=F"IP : {count[0]}")

    ax.set(xlabel='time (s)', ylabel='Total Packets Sent',
           title='Packets sent per second')

    ax.grid()
    plt.savefig(F'{folder_name}/packets_per_second.jpg')
    plt.legend(loc='best')

    # RESETAM GRAFICUL PENTRU A CREA ALTUL

    fig, ax = plt.subplots()
    ax.plot(range(0, len(parsed_packets)), [p['psize'] for p in sorted(parsed_packets, key=lambda x: x['timestamp'])],
            label=F"Total Data Transfer")
    ax.set(xlabel='time (s)', ylabel='Bytes Sent',
           title='Bytes Sent Per Second')
    ax.grid()
    plt.savefig(f'{folder_name}/bytes_per_second.jpg')
    plt.legend(loc='best')

    #GENERAM FOOTRPINT-UL
def generate_path(ips, parsed):
    # LUAM SURSA SI DESTINATIA
    source, destination = ips
    # NE UITAM DE LA INCIPIT
    first_packet_timestamp = parsed[0]['timestamp']
    data = [['DIRECTIA', 'SURSA', 'DESTINATIE', 'MARIME PACHET', 'FLAGS', 'TIME DELTA (SINCE BEGIN) ms']]
    # EXTRAGEM DATELE PACHET CU PACHET
    for packet in parsed:
        direction = "---->" if packet['src'] == source else "<----"
        data.append(
            [direction, F"{packet['src']}:{packet['sport']}", F"{packet['dst']}:{packet['dport']}", packet['psize'],
             packet['tcp_flags'],
             packet['timestamp'] - first_packet_timestamp])
    # FOLOSIND METODA TABULATE CREEM UN TABLE
    return tabulate(data)


if __name__ == '__main__':
    # GET THE FILE FROM COMMAND LINE
    file = sys.argv[1]
    print(F"reading file {file}")
    # IA NUMELE FISIERULUI PENTRU A CREA UN FOLDER UNDE SA PUNEM REZULTATELE
    output_folder = os.path.basename(file).split('.')[0]
    # DACA FOLDERUL NU EXISTA, CREAZA-L
    if not os.path.isdir(output_folder): os.mkdir(output_folder)

    # STRING CE VINE IN FISIERUL OUTPUT
    FILE_DUMP = FILE_DUMP + F"\n####################### {file} #######################\n"

    # CITIM FISIERUL PCAP
    data = rdpcap(file)

    # PARSAM TOATE PACHETELE SI LE PUNEM INTR-UN FORMAT MAI USOR DE LUCRAT, TOTODATA FILTRAND DOAR PACHETELE DE PE TCP
    parsed_packets = [parse_packet(packet) for packet in data[TCP]]
    # TOTODATA, NE ASIGURAM CA PACHETE SUNT ORDONATE DUPA TIMESTAMP, ADICA IN ORDINE CRONOLOGICA
    parsed_packets = sorted(parsed_packets, key=lambda x: x['timestamp'])

    # ADAUGAM NISTE TEXT IN FISIERUL DE OUTPUT
    FILE_DUMP = F"{FILE_DUMP}\n" \
                F"TOTAL BYTES TRANSFERRED : {sum([p['psize'] for p in parsed_packets])} \n" \
                F"TOTAL PACKETS TRANSFERRED : {len(parsed_packets)} \n"

    # LUAM SURSA PRIMULUI PACHET
    source = parsed_packets[0]['src']
    # LUAM DESTINATIA PRIMULUI PACHET
    destination = parsed_packets[0]['dst']

    # GENERA UN FOOTPRINT PENTRU COMUNICATIILE DIN FISIER, ADICA O CRONOLOGIE A PACHETELOR SI DATE DESPRE ELE
    footprint = generate_path((source, destination), parsed_packets)

    requests = []

    # LUAM UN SET CU TOATE IPURIILE UNICE
    unique_ips = set([p['src'] for p in parsed_packets])

    outbound = {}

    # MAI MULT TEXT IN FISIERUL DE OUTPUT
    FILE_DUMP = FILE_DUMP + "\n#######################\n"
    FILE_DUMP = FILE_DUMP + "UNIQUE SOURCE IPS \n"

    # PENTRU FIECARE IP UNIC VREM SA CREEM NISTE STATISTICI
    for ip in unique_ips:
        outbound[ip] = {}
        total = 0
        # NUMARAM TOTALUL DE PACHETE TRIMISE
        pa = [p for p in parsed_packets if p['src'] == ip]
        pa = sorted(pa, key=lambda x: x['timestamp'])

        # EXTRAGEM NISTE DATE DESPRE ELE, MAI EXACT DESTINATIA CATRE ACEST IP A TRIMIS PACHETE
        outbound[ip]['destination_ips'] = set([p['dst'] for p in pa])
        # NUMARUL TOTAL DE PACKETE
        outbound[ip]['total'] = len(pa)
        # CAND A TRIMIS PRIMUL PACHET
        outbound[ip]['first_packet'] = pa[0]['timestamp']
        # CAND A TRIMIS ULTIMUL PACHET
        outbound[ip]['last_packet'] = pa[len(pa) - 1]['timestamp']

        # ADAUGAM TEXTUL IN FISIEURL DE OUTPUT
        FILE_DUMP = FILE_DUMP + F"{ip} with a total of {outbound[ip]['total']} packets sent | {outbound[ip]['first_packet']} -> {outbound[ip]['last_packet']}\n"

    # SCRIEM IN FISIERUL DE OUTPUT TEXTUL
    with open(f'{output_folder}/overview.txt', 'w') as file:
        file.write(FILE_DUMP)

    # SCRIEM IN FISIERUL DE FOOTPRINT TEXTUL
    with open(f'{output_folder}/footprint.txt', 'w') as file:
        file.write(footprint)

    # GENERAM GRAFICE SI LE SALVAM
    generate_graphs(output_folder, parsed_packets)
