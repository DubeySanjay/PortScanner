from datetime import datetime
from functools import cmp_to_key
import matplotlib.pyplot as plt
import numpy as np
import dpkt, socket, sys
# =FUNCTIONS===================================================================#

def tcpFlags(tcp):
    """Returns a list of the set flags in this TCP packet."""
    ret = list()

    if tcp.flags & dpkt.tcp.TH_FIN != 0:
        ret.append('FIN')
    if tcp.flags & dpkt.tcp.TH_SYN != 0:
        ret.append('SYN')
    if tcp.flags & dpkt.tcp.TH_RST != 0:
        ret.append('RST')
    if tcp.flags & dpkt.tcp.TH_PUSH != 0:
        ret.append('PSH')
    if tcp.flags & dpkt.tcp.TH_ACK != 0:
        ret.append('ACK')
    if tcp.flags & dpkt.tcp.TH_URG != 0:
        ret.append('URG')
    if tcp.flags & dpkt.tcp.TH_ECE != 0:
        ret.append('ECE')
    if tcp.flags & dpkt.tcp.TH_CWR != 0:
        ret.append('CWR')

    return ret


def compare_IPs(ip1, ip2):
    """
    Return negative if ip1 < ip2, 0 if they are equal, positive if ip1 > ip2.
    """
    return sum(map(int, ip1.split('.'))) - sum(map(int, ip2.split('.')))

# =ARG PARSING=================================================================#

# Must include a pcap to read from.
if len(sys.argv) <= 1:
    print(f"{0}: needs a filepath to a PCAP file".format(sys.argv[0]))
    sys.exit(-1)

# Try to open the pcap file and create a pcap.Reader object.
try:
    f = open(sys.argv[1], 'rb')
    pcap = dpkt.pcap.Reader(f)
except (IOError, KeyError):
    print(f"Cannot open file: {0}".format(sys.argv[1]))
    sys.exit(-1)
# =MAIN========================================================================#

suspects = dict()  # Dictionary of suspects. suspect's IP: {# SYNs, # SYN-ACKs}
curPacket = 0  # Current packet number.

# Analyze captured packets.
for ts, buf in pcap:
    curPacket += 1

    # Ignore malformed packets
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except (dpkt.dpkt.UnpackError, IndexError):
        continue

    # Packet must include IP protocol to get TCP
    ip = eth.data
    if not ip:
        continue

    # Skip packets that are not TCP
    tcp = ip.data
    if type(tcp) != dpkt.tcp.TCP:
        continue

    # Get all of the set flags in this TCP packet
    tcpFlag = tcpFlags(tcp)

    srcIP = socket.inet_ntoa(ip.src)
    dstIP = socket.inet_ntoa(ip.dst)

    # test if the packet is icmp (ping)
    if isinstance(ip.data, dpkt.icmp.ICMP):
        if srcIP not in suspects:
            suspects[srcIP] = {'SYN': 0, 'SYN-ACK': 0, 'RST': 0, 'ACK': 0, 'ICMP': 0, 'PORT_LIST': set(), 'TIMESTAMP_LIST': [(ts, 'ICMP')], 'SCAN_TYPE': "PING", 'SCAN_PHASE':"PING", 'SCAN_START': ts, 'SCAN_STOP':ts}
        suspects[srcIP]['ICMP'] += 1

    # Fingerprint possible suspects.
    if {'SYN'} == set(tcpFlag):  # A 'SYN' request.
        if srcIP not in suspects:
            suspects[srcIP] = {'SYN': 0, 'SYN-ACK': 0, 'RST': 0, 'ACK': 0, 'ICMP': 0, 'PORT_LIST': set(), 'TIMESTAMP_LIST': [(ts, 'SYN')], 'SCAN_TYPE': "TCP SYN", 'SCAN_PHASE':"SYN", 'SCAN_START': ts, 'SCAN_STOP':ts}
        suspects[srcIP]['SYN'] += 1
        suspects[srcIP]['PORT_LIST'].add(tcp.dport)
        suspects[srcIP]['TIMESTAMP_LIST'].append((ts, 'SYN'))
        suspects[srcIP]['SCAN_STOP'] = ts
        suspects[srcIP]['SCAN_PHASE'] = 'SYN'

    elif {'SYN', 'ACK'} == set(tcpFlag):  # A 'SYN-ACK' reply.
        if dstIP not in suspects:
            suspects[dstIP] = {'SYN': 0, 'SYN-ACK': 0, 'RST': 0, 'ACK': 0, 'ICMP': 0, 'PORT_LIST': set(), 'TIMESTAMP_LIST': [(ts, 'SYN-ACK')], 'SCAN_TYPE': "", 'SCAN_PHASE':"SYN-ACK", 'SCAN_START': ts, 'SCAN_STOP':ts}
        suspects[dstIP]['SYN-ACK'] += 1
        suspects[dstIP]['SCAN_STOP'] = ts
        if suspects[dstIP]['SCAN_PHASE'] == "SYN":
            suspects[dstIP]['SCAN_TYPE'] = "TCP SYN"
        suspects[dstIP]['SCAN_PHASE'] = "SYN-ACK"

    elif {'ACK'} == set(tcpFlag):
        if srcIP not in suspects:
            suspects[srcIP] = {'SYN': 0, 'SYN-ACK': 0, 'RST': 0, 'ACK': 0, 'ICMP': 0, 'PORT_LIST': set(), 'TIMESTAMP_LIST': [(ts, 'ACK')], 'SCAN_TYPE': "", 'SCAN_PHASE':"ACK", 'SCAN_START': ts, 'SCAN_STOP':ts}
        suspects[srcIP]['ACK'] += 1
        suspects[srcIP]['PORT_LIST'].add(tcp.dport)
        suspects[srcIP]['TIMESTAMP_LIST'].append((ts, 'ACK'))
        suspects[srcIP]['SCAN_STOP'] = ts
        if suspects[srcIP]['SCAN_PHASE'] == "SYN-ACK":
            suspects[srcIP]['SCAN_TYPE'] = "TCP CONNECT SCAN"
        else:
            suspects[srcIP]['SCAN_TYPE'] = "ACK SCAN"
        suspects[srcIP]['SCAN_PHASE'] = "ACK"

    # elif {'RST'} == set(tcpFlag):
    #     suspects[srcIP]['RST'] += 1
    #     suspects[srcIP]['SCAN_STOP'] = ts
    #
    #     if suspects[srcIP]['SCAN_PHASE'] == "ACK":
    #         suspects[srcIP]['SCAN_TYPE'] = "TCP SYN"


# Output results.
print("Analyzed", curPacket, "packets:")

if not suspects:
    print('no suspicious packets detected...')

for s in sorted(suspects.keys(), key=cmp_to_key(compare_IPs)):
    syns = suspects[s]['SYN']
    synacks = suspects[s]['SYN-ACK']
    acks = suspects[s]['ACK']
    rsts = suspects[s]['RST']
    icmps = suspects[s]['ICMP']
    scan_type = suspects[s]['SCAN_TYPE']
    ports = ', '.join(str(x) for x in suspects[s]['PORT_LIST'])
    duration = datetime.utcfromtimestamp(suspects[s]['SCAN_STOP']) - datetime.utcfromtimestamp(suspects[s]['SCAN_START'])
    duration_in_s = duration.total_seconds()
    # ports.sort()
    timestamps = suspects[s]['TIMESTAMP_LIST']


    if syns + synacks + acks + icmps < 20:
        continue

#  plotting
    data = {'SYN': syns, 'SYN-ACK': synacks, 'ACK': acks,
            'PING': icmps}
    signals = list(data.keys())
    signal_count = list(data.values())

    fig = plt.figure(figsize=(10, 5))

    # creating the bar plot
    plt.bar(signals, signal_count, color='maroon',
            width=0.4)

    plt.xlabel("Signals")
    plt.ylabel("No. of signals")
    plt.title(s + " - " + scan_type)
    plt.show()

    # printing with timestamps
    # print("{0:15} had SYNs {1} SYN-ACKs {2} ACKs {3} RSTs {4} ICMPs {5} \nPORTS SCANNED = {6}\nTIMESTAMPS = {7}\n"
    #       "=======================================================================\n"
    #       .format(s, syns, synacks, acks, rsts, icmps, ports, timestamps))

    # printing without timestamps
    print("{0:15} had SYNs {1} SYN-ACKs {2} ACKs {3} ICMPs {4} \nSCAN TYPE = {5} \nScan duration {6} \n"
          "PORTS SCANNED = {7}\n"
          "=======================================================================\n"
          .format(s, syns, synacks, acks, icmps,scan_type,duration_in_s,  ports))


