#!/usr/bin/env python3
"""
SIP client with authentication support for testing VoIP tracing
"""
import socket
import time
import uuid
import random
import hashlib
import re
from datetime import datetime

class SIPAuthClient:
    def __init__(self, server_ip="localhost", server_port=5060, local_port=None):
        self.server_ip = server_ip
        self.server_port = server_port
        self.local_port = local_port or random.randint(5061, 5099)
        self.sock = None
        self.call_id = str(uuid.uuid4())
        self.tag = f"tag{random.randint(1000, 9999)}"
        self.branch = f"z9hG4bK{random.randint(100000, 999999)}"
        self.cseq = 1
        
    def create_socket(self):
        """Create UDP socket for SIP communication"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind(('0.0.0.0', self.local_port))
            self.sock.settimeout(10.0)  # 10 second timeout
            print(f"✅ SIP client listening on port {self.local_port}")
            return True
        except Exception as e:
            print(f"❌ Failed to create socket: {e}")
            return False

    def _parse_auth_header(self, response):
        """Parse WWW-Authenticate or Proxy-Authenticate header"""
        auth_header = re.search(r'(WWW-Authenticate|Proxy-Authenticate): Digest (.*)', response)
        if not auth_header:
            return None
        
        auth_params = {}
        parts = auth_header.group(2).split(',')
        for part in parts:
            if '=' in part:
                key, value = part.strip().split('=', 1)
                auth_params[key] = value.strip('"')
        return auth_params

    def _generate_auth_response(self, auth_params, username, password, method, uri):
        """Generate digest authentication response"""
        realm = auth_params.get('realm', '')
        nonce = auth_params.get('nonce', '')
        qop = auth_params.get('qop', '')
        
        # Generate cnonce if qop requires it
        cnonce = ''
        nc = '00000001'
        if qop:
            cnonce = hashlib.md5(str(random.random()).encode()).hexdigest()[:8]
        
        # Calculate HA1
        ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
        
        # Calculate HA2
        ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
        
        # Calculate response
        if qop:
            response = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()
        else:
            response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
        
        # Build authorization header
        auth_header = f'Digest username="{username}",realm="{realm}",nonce="{nonce}",uri="{uri}",response="{response}"'
        if qop:
            auth_header += f',qop={qop},nc={nc},cnonce="{cnonce}"'
            
        return auth_header

    def send_register(self, username="1000", password="1234"):
        """Send SIP REGISTER request with authentication support"""
        print(f"📞 Sending SIP REGISTER for user {username}")
        
        uri = f"sip:{self.server_ip}"
        register_message = f"""REGISTER {uri} SIP/2.0
Via: SIP/2.0/UDP 127.0.0.1:{self.local_port};branch={self.branch}
From: <sip:{username}@{self.server_ip}>;tag={self.tag}
To: <sip:{username}@{self.server_ip}>
Call-ID: {self.call_id}@127.0.0.1
CSeq: {self.cseq} REGISTER
Contact: <sip:{username}@127.0.0.1:{self.local_port}>
Max-Forwards: 70
User-Agent: SIPAuthClient/1.0
Expires: 3600
Content-Length: 0

"""
        try:
            # Send initial REGISTER
            self.sock.sendto(register_message.encode(), (self.server_ip, self.server_port))
            print("📤 Initial REGISTER request sent")
            
            # Receive auth challenge
            data, addr = self.sock.recvfrom(4096)
            response = data.decode()
            print(f"📥 Received auth challenge from {addr}")
            
            # Parse auth params
            auth_params = self._parse_auth_header(response)
            if not auth_params:
                print("❌ No authentication challenge found in response")
                return False
                
            # Generate authenticated request
            self.cseq += 1
            auth_header = self._generate_auth_response(auth_params, username, password, "REGISTER", uri)
            
            auth_register_message = f"""REGISTER {uri} SIP/2.0
Via: SIP/2.0/UDP 127.0.0.1:{self.local_port};branch={self.branch}
From: <sip:{username}@{self.server_ip}>;tag={self.tag}
To: <sip:{username}@{self.server_ip}>
Call-ID: {self.call_id}@127.0.0.1
CSeq: {self.cseq} REGISTER
Contact: <sip:{username}@127.0.0.1:{self.local_port}>
Authorization: {auth_header}
Max-Forwards: 70
User-Agent: SIPAuthClient/1.0
Expires: 3600
Content-Length: 0

"""
            # Send authenticated REGISTER
            self.sock.sendto(auth_register_message.encode(), (self.server_ip, self.server_port))
            print("📤 Authenticated REGISTER request sent")
            
            # Receive final response
            data, addr = self.sock.recvfrom(4096)
            response = data.decode()
            print(f"📥 Received final response:")
            if "200 OK" in response:
                print("✅ Successfully registered!")
                return True
            else:
                print("❌ Registration failed")
                print(response[:200] + "..." if len(response) > 200 else response)
                return False
                
        except socket.timeout:
            print("⏰ No response received (timeout)")
            return False
        except Exception as e:
            print(f"❌ Error in registration: {e}")
            return False
    
    def close(self):
        """Close the socket"""
        if self.sock:
            self.sock.close()
            print("🔌 Socket closed")

def register_test_users():
    """Register both test users (1000 and 1001)"""
    print("🚀 Starting SIP Registration Test")
    print("=" * 50)
    
    # Register user 1000
    print("\n📋 Registering user 1000")
    client1 = SIPAuthClient()
    if not client1.create_socket():
        return False
    
    success1 = client1.send_register("1000", "1234")
    client1.close()
    
    if success1:
        # Register user 1001
        print("\n📋 Registering user 1001")
        client2 = SIPAuthClient()
        if not client2.create_socket():
            return False
        
        success2 = client2.send_register("1001", "1234")
        client2.close()
        return success2
    
    return False

if __name__ == "__main__":
    register_test_users()
