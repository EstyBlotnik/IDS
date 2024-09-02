from scapy.all import IP, TCP
from scapy.packet import Raw

from core.packet_capture import analyze_packet

def simulate_sql_injection():
    packet = IP() / TCP() / Raw(load="SELECT * FROM users")
    analyze_packet(packet)

def simulate_command_injection():
    # Creating a packet with a Command Injection payload
    command_injection_payload = "some_command; ls -la"
    packet = IP(src='192.168.1.5', dst='192.168.1.1') / TCP(sport=12345, dport=80) / Raw(load=command_injection_payload)
    analyze_packet(packet)

def simulate_directory_traversal():
    # Creating a packet with a Directory Traversal payload
    directory_traversal_payload = "../etc/passwd"
    packet = IP(src='192.168.1.5', dst='192.168.1.1') / TCP(sport=12345, dport=80) / Raw(load=directory_traversal_payload)
    analyze_packet(packet)

simulate_directory_traversal()
simulate_command_injection()
simulate_sql_injection()