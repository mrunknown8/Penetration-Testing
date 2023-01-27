from scapy.all import *  #from scapy all we are importing all functions
from scapy.layers.inet import IP  #importng IP for capturing IP packets
from scapy.layers.http import HTTPRequest, TCP  # importing http for capturing http packets
from colorama import init, Fore  #for coloring output
import argparse

#make an ovject of argparser
args = argparse.ArgumentParser(description="Sniffing Tool", usage="python3 Packet_sniffer.py -iface interface")

#adding arguments
args.add_argument("-iface", "--interface", help="defne the interface you wanna sniff")
args.add_argument("-p", "--port", help="filter port")
args.add_argument("-o", "--output", help="save the output")

#fatching the values of the user
argsss = args.parse_args()

iface = argsss.interface
output  = argsss.output
port = argsss.port

#for colors
init()
red = Fore.RED
green = Fore.GREEN
blue = Fore.BLUE
yellow = Fore.YELLOW
white = Fore.WHITE
reset = Fore.RESET

#definining the main function
def sniff_packets(iface):
    print("Sniffing ....")
    if iface:
        sniff(filter = f"port {port}", prn = process_packets, iface = iface, store = False)
        #prn = process_packets means it will call the function process_packet for processing the captured packets
    else:
        sniff(prn = process_packets, store = False)


#defining the function which is going to process the capured requests
def process_packets(packets):
    #promiscus mode :- jtya blgr unicast packet ata nijr adeptar le aanibo lge thn promiscus mode enable thakibo lge
    #virtual adaptar does it automatically
    if packets.haslayer(TCP): #hashlayer means it will show the packets if it will have the defined layr like TCP
        src_ip = packets[IP].src
        dis_ip = packets[IP].dst
        src_port = packets[TCP].sport
        dst_port = packets[TCP].dport

        print(f"{yellow}Showing sniffed TCP packets")
        print(f"{blue}[+] Souce IP/Port: {src_ip}/{src_port} ---- Destination IP/Port: {dis_ip}/{dst_port}{reset}")


    if packets.haslayer(HTTPRequest):
        print(f"{yellow}Showing sniffed HTTP request")
        url = packets[HTTPRequest].Host.decode() + packets[HTTPRequest].Path.decode() #first we will find the host and than the end point , it will return the value in binaray so we are using decode to convert it into noemal srring
        method = packets[HTTPRequest].Method.decode()
        print(f"{red}[+] HTTP Connection-> Source IP: {src_ip} URL: {url} Method: {method} {reset}")
        print(f"[+]{white} HTTP Data:")
        print(f"{packets[HTTPRequest].show()}")
        if packets.haslayer(Raw):
            print(f"{green}[+] USeFull Raw Data:{reset}{red} {packets[Raw].load.decode()}{reset}")

sniff_packets(iface)