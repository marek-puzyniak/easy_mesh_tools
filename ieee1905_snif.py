from scapy.all import *
from pyieee1905.multiap_tlv import *
from pyieee1905.multiap_msg import *
import os
import sys


def is_ether_frame(frame):
    return frame[Ether].type == 0x800

def is_ieee1905_frame(frame):
    return frame[Ether].type == 0x893a

def get_eth_frame_type(frame):
    print(f'eth frame type:{hex(frame[Ether].type)}')


def gen_ap_autoconfig_search_frame():
    msg = MultiAP_Message()
    msg.msg_type = "AP_AUTOCONFIGURATION_SEARCH_MESSAGE"
    msg.msg_id = int.from_bytes(os.urandom(2), sys.byteorder)
    msg.flag_last_frag_ind = 1
    msg.flag_relay_ind = 1
    tlv1 = SupportedService()
    tlv1.service_cnt = 1
    tlv1.service_list = 1
    tlv1.len = 2

    tlv2 = SearchedService()
    tlv2.service_cnt = 1
    tlv2.service_list = 0
    tlv2.len = 2

    tlv3 = MultiAPProfile()
    tlv3.multi_ap_profile = 0x03
    tlv3.len = 1

    return Ether(type=0x893a, dst=IEEE1905_MCAST)/msg/tlv1/tlv2/tlv3/b"\x00\x00\x00"


def sniffer():
    sniff(count=10, lfilter=is_ieee1905_frame, prn=get_eth_frame_type)


frame = gen_ap_autoconfig_search_frame()

frame.show2()