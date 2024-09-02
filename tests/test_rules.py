import unittest
from collections import defaultdict  
from scapy.all import IP, TCP
from scapy.packet import Raw

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


from core.rules import detect_command_injection, detect_directory_traversal, detect_sql_injection
def simulate_command_injection():
    """
    Simulate a Command Injection attack by creating a packet with a command injection payload.
    """
    command_injection_payload = "cmd.exe /c dir"
    packet = IP(src='192.168.1.5', dst='192.168.1.1') / TCP(sport=12345, dport=80) / Raw(load=command_injection_payload)
    return packet

def simulate_directory_traversal():
    """
    Simulate a Directory Traversal attack by creating a packet with a directory traversal payload.
    """
    directory_traversal_payload = "../../../../etc/passwd"
    packet = IP(src='192.168.1.5', dst='192.168.1.1') / TCP(sport=12345, dport=80) / Raw(load=directory_traversal_payload)
    return packet


# יצירת מחלקה לבדיקות
class TestRules(unittest.TestCase):
    """
    Unit test class for testing various security rules.
    """

    def setUp(self):
        """
        Set up the testing environment.

        This method is called before each test case.
        It initializes global variables used for tracking packets and events.
        """
        global syn_tracker, packet_tracker
        syn_tracker = defaultdict(list)
        packet_tracker = defaultdict(list)

    

    def test_sql_injection_detection(self):
        """
        Test the detection of SQL Injection attacks.

        This test checks for the presence of SQL injection patterns
        in packet payloads.
        """
        packet = IP() / TCP() / Raw(load="SELECT * FROM users")
        self.assertTrue(detect_sql_injection(packet))

        packet = IP() / TCP() / Raw(load="Hello World")
        self.assertFalse(detect_sql_injection(packet))

    def test_command_injection_detection(self):
        """
        Test the detection of Command Injection attacks.

        This test checks for the presence of Command Injection patterns
        in packet payloads.
        """
        packet = simulate_command_injection()
        self.assertTrue(detect_command_injection(packet))

        packet = IP() / TCP() / Raw(load="Normal text without command injection")
        self.assertFalse(detect_command_injection(packet))

    def test_directory_traversal_detection(self):
        """
        Test the detection of Directory Traversal attacks.

        This test checks for the presence of Directory Traversal patterns
        in packet payloads.
        """
        packet = simulate_directory_traversal()
        self.assertTrue(detect_directory_traversal(packet))

        packet = IP() / TCP() / Raw(load="Normal text without directory traversal")
        self.assertFalse(detect_directory_traversal(packet))

    
    

if __name__ == "__main__":
    unittest.main()
