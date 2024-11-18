from scapy.all import *
from pyieee1905.multiap_tlv import *
from pyieee1905.multiap_msg import *
import os
import sys

# Setup MultiAP message
msg = MultiAP_Message()
msg.msg_type = "TOPOLOGY_NOTIFICATION_MESSAGE"
msg.msg_id = int.from_bytes(os.urandom(2), sys.byteorder)
msg.flag_last_frag_ind = 1

# Setup TLV
tlv = ClientAssocEvent()
tlv.mac = os.urandom(6)
tlv.bssid = os.urandom(6)
tlv.assoc_flag = 1

# Generate the packet
p = Ether(type=0x893a, dst=IEEE1905_MCAST)/msg/tlv

# Send the packet
sendp(p, iface="vboxnet0")
