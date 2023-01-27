import socket # scokket is a layer 4 connection using two way communication
import argparse

#make an ovject of argparser
args = argparse.ArgumentParser(description="Port Scanner", usage="python3 port_scanner.py -i <ip> -s <start_port> -e <end_port>")

#adding arguments
args.add_argument("-i", "--ip", help="set the ip address you wanna scan", required= True)
args.add_argument("-s", "--s_port", help="set start port from where you wanna start scanning", required= True)
args.add_argument("-e", "--e_port", help="set end port from where you wanna end scanning", required= True)

#fatching the values of the user
argsss = args.parse_args()

target = argsss.ip
target = argsss.ip
try:
    target = socket.gethostbyname(target)
except:
    print("[-] Can't get the ip from the hostname")
start = int(argsss.s_port)
end = int(argsss.e_port)

print("Scanning ...")

for port in range(start,end + 1):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #AF_INET = ipv4 & SOCK_STREAM = TCP connection
    s.settimeout(1)
    connection = s.connect_ex((target,port))  #connecting to the target thrugh that port
    if connection==0 :
        print(f"[+] Port {port} is open")



