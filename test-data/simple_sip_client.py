#!/usr/bin/env python3
"""
Simple SIP client for testing VoIP tracing on macOS
Uses raw socket programming to avoid complex dependencies
"""
import socket
import time
import uuid
import random
from datetime import datetime

class SimpleSIPClient:
    def __init__(self, server_ip="localhost", server_port=5060, local_port=None):
        self.server_ip = server_ip
        self.server_port = server_port
        self.local_port = local_port or random.randint(5061, 5099)
        self.sock = None
        self.call_id = str(uuid.uuid4())
        self.tag = f"tag{random.randint(1000, 9999)}"
        self.branch = f"z9hG4bK{random.randint(100000, 999999)}"
        
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
    
    def send_options(self):
        """Send SIP OPTIONS request"""
        print(f"📞 Sending SIP OPTIONS to {self.server_ip}:{self.server_port}")
        
        options_message = f"""OPTIONS sip:{self.server_ip} SIP/2.0
Via: SIP/2.0/UDP 127.0.0.1:{self.local_port};branch={self.branch}
From: <sip:testclient@127.0.0.1:{self.local_port}>;tag={self.tag}
To: <sip:{self.server_ip}:{self.server_port}>
Call-ID: {self.call_id}@127.0.0.1
CSeq: 1 OPTIONS
Contact: <sip:testclient@127.0.0.1:{self.local_port}>
Max-Forwards: 70
User-Agent: SimpleSIPClient/1.0
Content-Length: 0

"""
        
        try:
            self.sock.sendto(options_message.encode(), (self.server_ip, self.server_port))
            print("📤 OPTIONS request sent")
            
            # Try to receive response
            try:
                data, addr = self.sock.recvfrom(4096)
                response = data.decode()
                print(f"📥 Received response from {addr}:")
                print(response[:200] + "..." if len(response) > 200 else response)
                return True
            except socket.timeout:
                print("⏰ No response received (timeout)")
                return False
                
        except Exception as e:
            print(f"❌ Error sending OPTIONS: {e}")
            return False
    
    def send_register(self, username="1000", password="1234"):
        """Send SIP REGISTER request"""
        print(f"📞 Sending SIP REGISTER for user {username}")
        
        register_message = f"""REGISTER sip:{self.server_ip} SIP/2.0
Via: SIP/2.0/UDP 127.0.0.1:{self.local_port};branch={self.branch}
From: <sip:{username}@{self.server_ip}>;tag={self.tag}
To: <sip:{username}@{self.server_ip}>
Call-ID: {self.call_id}@127.0.0.1
CSeq: 1 REGISTER
Contact: <sip:{username}@127.0.0.1:{self.local_port}>
Max-Forwards: 70
User-Agent: SimpleSIPClient/1.0
Expires: 3600
Content-Length: 0

"""
        
        try:
            self.sock.sendto(register_message.encode(), (self.server_ip, self.server_port))
            print("📤 REGISTER request sent")
            
            # Try to receive response
            try:
                data, addr = self.sock.recvfrom(4096)
                response = data.decode()
                print(f"📥 Received response from {addr}:")
                print(response[:200] + "..." if len(response) > 200 else response)
                
                # Check if authentication is required (401/407 response)
                if "401 Unauthorized" in response or "407 Proxy Authentication Required" in response:
                    print("🔐 Authentication required - would need to implement digest auth")
                    
                return True
            except socket.timeout:
                print("⏰ No response received (timeout)")
                return False
                
        except Exception as e:
            print(f"❌ Error sending REGISTER: {e}")
            return False
    
    def send_invite(self, target_user="1001"):
        """Send SIP INVITE request"""
        print(f"📞 Sending SIP INVITE to {target_user}")
        
        # Simple SDP for audio call
        sdp_content = f"""v=0
o=testclient {random.randint(1000000, 9999999)} {random.randint(1000000, 9999999)} IN IP4 127.0.0.1
s=Test Call
c=IN IP4 127.0.0.1
t=0 0
m=audio {self.local_port + 1000} RTP/AVP 0 8
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
"""
        
        invite_message = f"""INVITE sip:{target_user}@{self.server_ip} SIP/2.0
Via: SIP/2.0/UDP 127.0.0.1:{self.local_port};branch={self.branch}
From: <sip:1000@{self.server_ip}>;tag={self.tag}
To: <sip:{target_user}@{self.server_ip}>
Call-ID: {self.call_id}@127.0.0.1
CSeq: 1 INVITE
Contact: <sip:1000@127.0.0.1:{self.local_port}>
Max-Forwards: 70
User-Agent: SimpleSIPClient/1.0
Content-Type: application/sdp
Content-Length: {len(sdp_content)}

{sdp_content}"""
        
        try:
            self.sock.sendto(invite_message.encode(), (self.server_ip, self.server_port))
            print("📤 INVITE request sent")
            
            # Try to receive responses
            for i in range(3):  # Try to get multiple responses (100 Trying, 180 Ringing, etc.)
                try:
                    data, addr = self.sock.recvfrom(4096)
                    response = data.decode()
                    print(f"📥 Response {i+1} from {addr}:")
                    print(response[:200] + "..." if len(response) > 200 else response)
                    
                    # If we get 200 OK, we should send ACK
                    if "200 OK" in response:
                        print("✅ Call answered! Should send ACK...")
                        # In a real client, we'd parse the response and send ACK
                        break
                        
                except socket.timeout:
                    print(f"⏰ No more responses (timeout on attempt {i+1})")
                    break
                    
            return True
                
        except Exception as e:
            print(f"❌ Error sending INVITE: {e}")
            return False
    
    def close(self):
        """Close the socket"""
        if self.sock:
            self.sock.close()
            print("🔌 Socket closed")

def run_sip_test_sequence():
    """Run a sequence of SIP tests"""
    print("🚀 Starting Simple SIP Client Test Sequence")
    print("=" * 50)
    
    client = SimpleSIPClient()
    
    if not client.create_socket():
        return False
    
    try:
        # Test 1: OPTIONS
        print("\n📋 Test 1: SIP OPTIONS")
        client.send_options()
        time.sleep(2)
        
        # Test 2: REGISTER
        print("\n📋 Test 2: SIP REGISTER")
        client.send_register()
        time.sleep(2)
        
        # Test 3: INVITE
        print("\n📋 Test 3: SIP INVITE")
        client.send_invite()
        time.sleep(2)
        
        print("\n✅ SIP test sequence completed")
        return True
        
    except KeyboardInterrupt:
        print("\n⚠️ Test interrupted by user")
        return False
    except Exception as e:
        print(f"\n❌ Test sequence error: {e}")
        return False
    finally:
        client.close()

if __name__ == "__main__":
    run_sip_test_sequence()
