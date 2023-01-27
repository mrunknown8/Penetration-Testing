import whois  #used to gather whoai information
import dns.resolver  #used to resolves names ofos stub /etc/resolve,conf
import shodan  #used for shodan info
import requests  #used to make web req using python
import sys  #used for giving arguments in command line
import argparse  #used for giving arguments in command line using options (-p, -w etc)
import socket #we will use this for finding ip from domain
from colorama import init, Fore  #for coloring output

#for colors
init()
red = Fore.RED
green = Fore.GREEN
blue = Fore.BLUE
yellow = Fore.YELLOW
reset = Fore.RESET
#print(sys.argv[0])

#using argparser
#make an ovject of argparser
args = argparse.ArgumentParser(description="INFORMATION GATHERING TOOL", usage="python3 info_gathering.py -d DOMAIN [-s IP]")

#adding arguments
args.add_argument("-d", "--domain", help="Enter the domain name you wanna gather info about")
args.add_argument("-s", "--shodan", help="Enter the ip address you wanna gather info about from shodan.io")
args.add_argument("-o", "--output", help="save the output")

#fatching the values of the user
argsss = args.parse_args()

domain = argsss.domain
ip = argsss.shodan
output  = argsss.output

print("[+] Domain {} IP {}".format(domain, ip))
print("\n")
#getting info grom whois
print("[+] Getting whois info")
whois_results = ' '
#creating objects,making an query
try:
    info = whois.query(domain)
    print("[+] whois info found")
    whois_results += "Name: {}".format(info.name) + '\n' # += means appending
    whois_results += "Registrar: {}".format(info.registrar) + '\n'
    whois_results += "Creation Date: {}".format(info.creation_date) + '\n'
    whois_results += "Expiration Date: {}".format(info.expiration_date) + '\n'
    whois_results += "Registrant: {}".format(info.registrant) + '\n'
    whois_results += "Register Country: {}".format(info.registrant_country) + '\n'
    whois_results += "Admin: {}".format(info.admin) + '\n'
    whois_results += "Emails: {}".format(info.emails) + '\n'
except:
    pass
print(f"{green}{whois_results}{reset}")
print("\n\n")

#getting DNS info
print("[+] Getting DNS info")
dns_results = ''
#using dns resolver from dnspython
try:
    #fetching records
    for a in dns.resolver.resolve(domain,'A'):
        dns_results += "A record {}".format(a.to_text()) + '\n'
    for ns in dns.resolver.resolve(domain, 'NS'):
        dns_results += "NS record {}".format(ns.to_text()) + '\n'
    for mx in dns.resolver.resolve(domain,'MX'):
        dns_results += "MX record {}".format(mx.to_text()) + '\n'
    for txt in dns.resolver.resolve(domain, 'TXT'):
        dns_results += "TXT record {}".format(txt.to_text()) + '\n'
except:
    pass
print(f"{blue}{dns_results}{reset}")
print("\n\n")


#GeoLocation
print("[+] Getting GeoLocation Info")
geo_results = ''
#using requests library
try:
    response = requests.request('GET', "http://geolocation-db.com/json/" + socket.gethostbyname(domain)).json()  #socket.gethostbyname(domain) it will resolve the domain and give us the ip
    geo_results += "Country: {}".format(response['country_name']) + '\n'
    geo_results += "State: {}".format(response['state']) + '\n'
    geo_results += "City: {}".format(response['city']) + '\n'
    geo_results += "Latitude: {}".format(response['latitude']) + '\n'
    geo_results += "Longitude: {}".format(response['longitude']) + '\n'
except:
    pass
print(f"{yellow}{geo_results}{reset}")
print("\n\n")


#shodan info
#must have a api key you can get it by logging in

### ip = socket.gethostbyname(domain) #resolving the domain to ip
if ip:
    print("[+] Getting Shodan Info for IP {}".format(ip))
    shodan_results = ''
    api = shodan.Shodan("DNCrwndGL85v5EgMPQOtigPKstlZ38Ws")
    try:
        resultssss = api.search(ip)
        print("[+] Results found: {}".format(resultssss['total']))
        for result in resultssss['matches']:
            shodan_results += "[+] IP: {}".format(result['ip_str']) + '\n'
            shodan_results += "[+] Data: \n{}".format(result['data']) +'\n'
            print(f"{red}{shodan_results}{reset}")
            print()
    except:
        print("[-] Shodan records not found")

if output:
    with open(output, 'w') as file :
        file.write(whois_results + '\n\n')
        file.write(dns_results + '\n\n')
        file.write(geo_results + '\n\n')
        file.write("SHODAN RESULTS FOR THE IP: {}".format(ip) + '\n')
        file.write(shodan_results + '\n\n')





