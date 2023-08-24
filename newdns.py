import re
import base64
from scapy.all import *
import subprocess
import urllib.parse
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def dns_packet_handler(packet):
    if packet.haslayer(DNSQR) and packet[DNS].qr == 0:
        qname = packet[DNSQR].qname.decode()
        qtype = packet[DNSQR].qtype
        if qtype == 16:  # TXT record type
            logging.info(f"DNS TXT request: {qname}")
            txt_content = packet[DNSRR].rdata.decode()
            if is_encoded(txt_content):
                decoded_content = decode_content(txt_content)
                logging.info(f"Decoded TXT content: {decoded_content}")
                check_suspicious_code(decoded_content)
            else:
                logging.info(f"TXT content: {txt_content}")
                check_suspicious_code(txt_content)

def is_encoded(txt_content):
    if is_base64_encoded(txt_content) or is_url_encoded(txt_content) or is_hex_encoded(txt_content):
        return True
    return False

def decode_content(txt_content):
    if is_base64_encoded(txt_content):
        return decode_base64(txt_content)
    elif is_url_encoded(txt_content):
        return decode_url(txt_content)
    elif is_hex_encoded(txt_content):
        return decode_hex(txt_content)
    else:
        return txt_content

def is_base64_encoded(txt_content):
    try:
        decoded_content = base64.b64decode(txt_content).decode()
        return True
    except ValueError:
        return False

def decode_base64(txt_content):
    try:
        decoded_content = base64.b64decode(txt_content).decode()
        return decoded_content
    except ValueError:
        return txt_content

def is_url_encoded(txt_content):
    try:
        decoded_content = urllib.parse.unquote(txt_content)
        return True
    except ValueError:
        return False

def decode_url(txt_content):
    try:
        decoded_content = urllib.parse.unquote(txt_content)
        return decoded_content
    except ValueError:
        return txt_content

def is_hex_encoded(txt_content):
    try:
        decoded_content = bytes.fromhex(txt_content).decode()
        return True
    except ValueError:
        return False

def decode_hex(txt_content):
    try:
        decoded_content = bytes.fromhex(txt_content).decode()
        return decoded_content
    except ValueError:
        return txt_content

def check_suspicious_code(txt_content):
    suspicious_patterns = [
        r"eval\(",
        r"exec\(",
        r"import\sos",
        r"system\(",
        r"shell\(",
        r"subprocess\.",
        r"__import__\(",
        r"open\(",
        r"file\(",
        r"input\(",
        r"pickle\.",
        r"marshal\.",
        r"base64\.",
        r"codecs\.",
        r"urllib\.",
        r"requests\.",
        r"socket\.",
        r"paramiko\.",
        r"ftplib\.",
        r"pexpect\.",
        r"shutil\.",
        r"tempfile\.",
        r"os\.",
        r"sys\.",
        r"glob\.",
        r"subprocess\.",
        r"execfile\(",
        r"compile\(",
        r"__builtins__\.",
        r"__class__\.",
        r"__bases__\.",
        r"__subclasses__\.",
        r"__import__\.",
        r"__getattr__\.",
        r"__getattribute__\.",
        r"__setattr__\.",
        r"__delattr__\.",
        r"__call__\.",
        r"__init__\.",
        r"__subclasses__\.",
        r"__bases__\.",
        r"__class__\.",
        r"__import__\.",
        r"__getattr__\.",
        r"__getattribute__\.",
        r"__setattr__\.",
        r"__delattr__\.",
        r"__call__\.",
        r"__init__\."
    ]

    for pattern in suspicious_patterns:
        matches = re.findall(pattern, txt_content)
        if matches:
            logging.warning(f"Suspicious code found: {matches}")

sniff(filter="udp port 53", prn=dns_packet_handler)
