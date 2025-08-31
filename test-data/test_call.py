#!/usr/bin/env python3
"""
Simple SIP client for testing VoIP tracing
"""
import socket
import time
import sys

def create_sip_message(method, to_number, from_number, server_ip, local_ip, branch='z9hG4bK-test'):
    return f"""\
{method} sip:{to_number}@{server_ip} SIP/2.0
Via: SIP/2.0/UDP {local_ip}:5061;branch={branch}
From: <sip:{from_number}@{server_ip}>;tag=test
To: <sip:{to_number}@{server_ip}>
Call-ID: test-call@{local_ip}
CSeq: 1 {method}
Contact: <sip:{from_number}@{local_ip}:5061>
Max-Forwards: 70
User-Agent: Python Test Client
Content-Length: 0

"""

def send_sip_request(sock, message, server_address):
    print("Sending message:")
    print(message)
    sock.sendto(message.encode(), server_address)

def main(from_number, to_number):
    server_ip = '172.18.0.3'
    server_port = 5060
    client_port = 5061

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', client_port))
    sock.settimeout(5)

    server_address = (server_ip, server_port)

    # Get local IP
    local_ip = socket.gethostbyname(socket.gethostname())

    # Send REGISTER
    register_msg = create_sip_message('REGISTER', from_number, from_number, server_ip, local_ip)
    send_sip_request(sock, register_msg, server_address)
    time.sleep(1)

    # Send INVITE
    invite_msg = create_sip_message('INVITE', to_number, from_number, server_ip, local_ip)
    send_sip_request(sock, invite_msg, server_address)

    # Wait for responses
    for _ in range(5):
        try:
            data, addr = sock.recvfrom(4096)
            print(f"\nReceived response from {addr}:")
            print(data.decode())
        except socket.timeout:
            break

    sock.close()

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python test_call.py from_number to_number")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
