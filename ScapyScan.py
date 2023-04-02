from scapy.all import *
from scapy.layers.inet import IP,TCP
import socket
#Hello! This project for me is a playground to get familiar with Scapy. 
#1. Send a SYN packet to a range of IP addresses and port numbers.
#2. Listen for SYN-ACK packets from the target machines, indicating that the port is open
#3. Record the open ports of specific IP and display them to the user.

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        # google DNS server
        s.connect(('8.8.8.8', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


def send_syn_packet():
    choice = int(input("1. Send a SYN packet to a specific IP address and port number \n2. Send a SYN packet to a range of IP addresses and port numbers\n"))
    if choice==1:
        ip = input("Enter the IP address: ")
        port = int(input("Enter the port number: "))
        syn_packet = IP(dst=ip)/TCP(dport=port, flags="S")
        syn_response = sr1(syn_packet, timeout=1, verbose=0)
        print("Response: ",syn_response)
    if choice==2:
        ips=[]
        f = open("ips.txt", "r")
        f= f.read()
        ips = f.split(',')
        port = int(input("Enter the port number: "))
        for ip in ips:
            syn_packet = IP(dst=ip)/TCP(dport=port, flags="S")
            syn_response = sr1(syn_packet, timeout=1, verbose=0)
            print("Response: ",syn_response)

def syn_ack_listener():
    count=int(input("How many packets do you want to sniff? "))
    results = sniff(count,filter="tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn|tcp-ack",prn=lambda x: x.summary())
    packetno=int(input('Would you like to see the details of a specific packet? Enter the packet number or enter 0 to exit: '))
    if packetno!=0:
        return results[packetno-1].show()
    else:
        print("Exiting...")
        return results
def tcp_port_scanner():
    ip = input("Enter the IP address: ")
    ports = list(input("Enter the port numbers divided by ',': ").split(','))
    ports = [int(i) for i in ports]
    for port in ports:
        packet = IP(dst=ip)/TCP(dport=port, flags="S")
        syn_response = sr1(packet, timeout=1, verbose=0)
        if syn_response is None:
            print("[-]",port,"is closed")
        else:
            print("[+]",port,"is open")
tcp_port_scanner()
def menu():
    print("Welcome to the Scapy Project")
    print("1. Send a SYN packet to a specific (or range) IP address and port number")
    print("2. Listen for SYN-ACK packets from the target machines, indicating that the port is open")
    print("3. TCP Port scanner")
    print("4. Exit")
    choice = int(input("Enter your choice: "))
    if choice==1:
        print(send_syn_packet())
    if choice==2:
        print(syn_ack_listener())
    if choice==3:
        tcp_port_scanner()
    if choice==4:
        print("Exiting...")


menu()
