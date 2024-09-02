from collections import defaultdict
from datetime import datetime, timedelta
import re

syn_tracker = defaultdict(list)
PORT_SCAN_THRESHOLD = 10  # Number of SYN packets
TIME_WINDOW = timedelta(seconds=3)  # Within 1 second

# Patterns to detect SQL Injection attacks
SQLI_PATTERNS = [
    r"(\bunion\b.*\bselect\b.*\bfrom\b)",  # UNION SELECT FROM pattern
    r"(\bselect\b.*\bfrom\b)",  # Simple SELECT FROM pattern
    r"(\bselect\b.*\bfrom\b.*\bwhere\b)",  # SELECT FROM WHERE pattern with complex conditions
    r"(\bor\b.*=.*\bor\b)",  # OR 1=1 pattern
    r"(sleep\(\d+\))",  # SLEEP function used in SQL injection
    r"(benchmark\(\d+,\s*.*\))"  # BENCHMARK function
]

def detect_sql_injection(packet):
    """
    Detects SQL Injection attacks by analyzing the payload for known SQL injection patterns.

    Args:
        packet (scapy.packet.Packet): The network packet to analyze.

    Returns:
        bool: True if SQL injection patterns are detected, otherwise False.
    """
    if packet.haslayer('Raw'):
        payload = str(packet['Raw'].load).lower()
        for pattern in SQLI_PATTERNS:
            if re.search(pattern, payload):
                return True
    return False

# Patterns to detect Directory Traversal attacks
DIRECTORY_TRAVERSAL_PATTERNS = [
    r"\.\./",  # Parent directory traversal
    r"\.\.\\"  # Windows-style parent directory traversal
]

def detect_directory_traversal(packet):
    """
    Detects Directory Traversal attacks by analyzing the payload for known traversal patterns.

    Args:
        packet (scapy.packet.Packet): The network packet to analyze.

    Returns:
        bool: True if Directory Traversal patterns are detected, otherwise False.
    """
    if packet.haslayer('Raw'):
        payload = str(packet['Raw'].load).lower()
        for pattern in DIRECTORY_TRAVERSAL_PATTERNS:
            if re.search(pattern, payload):
                return True
    return False

def detect_command_injection(packet):
    payload = str(packet.getlayer('Raw').load.decode(errors='ignore')).lower()
    patterns = [
        r';',
        r'&&',
        r'\|\|',
        r'cmd.exe',
        r'exec',
        r'system',
        r'sh',
        r'perl',
        r'/bin/',
        r'/usr/',
        r'/etc/',
    ]
    for pattern in patterns:
        if re.search(pattern, payload):
            return True
    return False


# def detect_command_injection(packet):
#     payload = str(packet.getlayer('Raw').load.decode(errors='ignore')).lower()
#     # Check for common command injection patterns
#     patterns = [
#         r';|\&\&|\|\||\b(?:cmd|exec|system|sh|perl|bash)\b',
#         r'/bin/|/usr/|/etc/',
#     ]
#     for pattern in patterns:
#         if re.search(pattern, payload):
#             return True
#     return False


# def detect_command_injection(packet):
#     payload = packet[Raw].load.decode('utf-8')
#     print(f"Payload received: {payload}")
#     # לוגיקה לזיהוי Command Injection
#     if "cmd.exe" in payload or "sh" in payload:
#         return True
#     return False
