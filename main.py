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

