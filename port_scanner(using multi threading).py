import socket # scokket is a layer 4 connection using two way communication
import argparse
import queue  #to use queue
import threading  #to make threads and achive concuency
from colorama import init, Fore

#for colors
init()
red = Fore.RED
green = Fore.GREEN
blue = Fore.BLUE
yellow = Fore.YELLOW
white = Fore.WHITE
reset = Fore.RESET

#make an ovject of argparser
args = argparse.ArgumentParser(description="Port Scanner", usage="python3 port_scanner.py -i <ip> -s <start_port> -e <end_port> -t <thread_no> -o <file_name>")

#adding arguments
args.add_argument("-i", "--ip", help="set the ip address you wanna scan", required= True)
args.add_argument("-s", "--s_port", help="set start port from where you wanna start scanning", required= True)
args.add_argument("-e", "--e_port", help="set end port from where you wanna end scanning", required= True)
args.add_argument("-t", "--thread", help="set the number of threads you wanna run", required= True)
args.add_argument("-o", "--output", help="save the output")

#fatching the values of the user
argsss = args.parse_args()

target = argsss.ip
try:
    target = socket.gethostbyname(target)
except:
    print("[-] Can't get the ip from the hostname")
start = int(argsss.s_port)
end = int(argsss.e_port)
thread = int(argsss.thread)
output = argsss.output

print("\nScanning ...\n")

result = f"{white}[+] Result:\n\n{reset}{blue}PORT\t\tSTATE\n{reset}"

def scan_port(t_no):
    global result
    while not q.empty():
        port = q.get()  #using this it will fatch the port no from queue
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #AF_INET = ipv4 & SOCK_STREAM = TCP connection
            s.settimeout(1)
            connection = s.connect_ex((target,port))  #connecting to the target thrugh that port
            if connection==0 :
                result += f"{red}{port}\t\tOPEN\n{reset}"
            s.close()
        except:
            pass
        q.task_done()

# making the queue
q = queue.Queue()

#filling the queue with ports
for j in range(start,end+1):
    q.put(j)

# making threads
for i in range(thread):
    t = threading.Thread(target=scan_port, args=(i, ),daemon= True)  #daemon means all the threads will run in background it will not block the main thread but the non daemon thread will block the main thread
    # daemon threads will stop when we stop the main thread but we can not kill the non daemon thread normally
    t.start()


q.join()  #it is a blocker method ...queue r sob elements hekh hua pist ha yar aagr execute kribo

print(result)

if output:
    with open(output, 'w') as file :
        file.write(f"{green}Port scan result for target: {target}\n")
        file.write(result)
