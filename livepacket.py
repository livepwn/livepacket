# protocol_analyzer.py
from scapy.all import sniff, TCP, UDP, Raw, IP
import sys

def packet_callback(packet):
    if packet.haslayer(TCP):
        print("\n[+] TCP Packet Detected")
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")
        print(f"Source Port: {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"Payload: {payload}")
            # Check if it's HTTP traffic (port 80 or 443)
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                print("[!] HTTP Traffic Detected")
                try:
                    print(f"HTTP Data: {payload.decode('utf-8')}")
                except UnicodeDecodeError:
                    print("[!] Could not decode HTTP payload (non-text data)")

    elif packet.haslayer(UDP):
        print("\n[+] UDP Packet Detected")
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")
        print(f"Source Port: {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")

def start_sniffing(protocol, count):
    print(f"[*] Starting protocol analyzer for {protocol}...")
    if protocol == "TCP":
        sniff(filter="tcp", prn=packet_callback, count=count)
    elif protocol == "UDP":
        sniff(filter="udp", prn=packet_callback, count=count)
    elif protocol == "HTTP":
        sniff(filter="tcp port 80", prn=packet_callback, count=count)
    else:
        print("[-] Unsupported protocol. Exiting...")
        sys.exit(1)

def interactive_menu():
    print("=== Protocol Analyzer ===")
    print("1. Analyze TCP Traffic")
    print("2. Analyze UDP Traffic")
    print("3. Analyze HTTP Traffic")
    print("4. Exit")

    choice = input("Enter your choice (1-4): ")
    if choice == "1":
        protocol = "TCP"
    elif choice == "2":
        protocol = "UDP"
    elif choice == "3":
        protocol = "HTTP"
    elif choice == "4":
        print("[*] Exiting...")
        sys.exit(0)
    else:
        print("[-] Invalid choice. Exiting...")
        sys.exit(1)

    count = int(input("Enter the number of packets to capture: "))
    start_sniffing(protocol, count)

if __name__ == "__main__":
    try:
        while True:
            interactive_menu()
            again = input("\nDo you want to analyze another protocol? (y/n): ").lower()
            if again != 'y':
                print("[*] Exiting...")
                break
    except KeyboardInterrupt:
        print("\n[*] Exiting...")
        sys.exit(0)
