from scapy.all import srp  #srp for sending and receving
from scapy.layers.l2 import ARP, Ether  #importing arp from layer2, ether for mac addresses
import argparse
from colorama import init, Fore
from scapy.all import sr1  #for icmp
import ipaddress #it will give you the ips from target range
from scapy.layers.inet import IP, ICMP  #for icmp

#make an ovject of argparser
args = argparse.ArgumentParser(description="Network Scanner", usage="python3 Network_scanner.py -tR <target_range>")

#adding arguments
args.add_argument("-tR", "--t_range", help="define the target network range")

#fatching the values of the user
argsss = args.parse_args()

target = argsss.t_range

#for colors
init()
red = Fore.RED
blue = Fore.BLUE
white = Fore.WHITE
reset = Fore.RESET

print("\nchoose an option")
print(f"{white}1 - scanning using ARP\n2 - scanning using ICMP{reset}\n")
inn = input(f"{white}{reset}\n")

if (inn=='1') :
    print("[+] Scanning using ARP\n")
    #making layer2 frame
    ether = Ether(dst = 'ff:ff:ff:ff:ff:ff') #ff:ff:ff:ff:ff:ff will broadcast the request
    arp = ARP(pdst = target) #arp request

    prob = ether/arp #stacking the packets ether ke upar arp

    #sending the req
    result = srp(prob, timeout = 3, verbose = 0) #srp will respond like this :-> [ answered , unanswered ] -->> jis bhi host se response nahin aayega wo unanswered pe aayega
    #answered consists of [ sent , received ]

    #answered is in the 0th index of result and received is in the 1st index of answered
    online_connection = []
    answered = result[0]
    for sent,received in answered:
        online_connection.append({'ip' : received.psrc , 'mac' : received.hwsrc})

    print("\n")
    print(f"[+]{blue} available Hosts{reset}")
    print("\n")
    print(f"{white}IP" + " "*22 + f"MAC{reset}")

    for connection in online_connection:
        print(f"{red}")
        print('{}\t\t{}'.format(connection['ip'],connection['mac']))
        print(f"{reset}")

elif (inn=='2'):
    print("[+] Scanning using ICMP")
    print("\n")
    print(f"[+]{blue} available Hosts{reset}")
    ip_list = [str(ip) for ip in ipaddress.IPv4Network(target, False)]

    for ip in  ip_list:
        probe = IP(dst = ip)/ICMP()  #ip ke upar icmp
        result = sr1(probe, timeout = 3, verbose = 0)
        if result :
            print(f"{red}{ip} is online{reset}")

else:
    print("Wrong Choice")