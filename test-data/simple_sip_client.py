#!/usr/bin/env python3
"""
Simple SIP client for testing VoIP tracing on macOS
Uses raw socket programming to avoid complex dependencies
"""
import socket
import time
import sys

def create_sip_message(method, to_number, from_number, server_ip='127.0.0.1', branch='z9hG4bK-test'):
    return f"""\
{method} sip:{to_number}@{server_ip} SIP/2.0
Via: SIP/2.0/UDP 127.0.0.1:5061;branch={branch}
From: <sip:{from_number}@{server_ip}>;tag=test
To: <sip:{to_number}@{server_ip}>
Call-ID: test-call@127.0.0.1
CSeq: 1 {method}
Contact: <sip:{from_number}@127.0.0.1:5061>
Max-Forwards: 70
User-Agent: Python Test Client
Content-Length: 0

"""

def send_sip_request(sock, message, server_address):
    print("Sending message:")
    print(message)
    sock.sendto(message.encode(), server_address)

def main(from_number, to_number):
    server_ip = '127.0.0.1'
    server_port = 5060
    client_port = 5061

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', client_port))
    sock.settimeout(5)

    server_address = (server_ip, server_port)

    # Send REGISTER
    register_msg = create_sip_message('REGISTER', from_number, from_number)
    send_sip_request(sock, register_msg, server_address)
    time.sleep(1)

    # Send INVITE
    invite_msg = create_sip_message('INVITE', to_number, from_number)
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
        print("Usage: python simple_sip_client.py from_number to_number")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
        
    try:
            self.sock.sendto(options_message.encode(), (self.server_ip, self.server_port))
            print("📤 OPTIONS request sent")
            
            # Try to receive response
            try:
                data, addr = self.sock.recvfrom(4096)
                response = data.decode()
                print(f"📥 Received response from {addr}:")
                print(response[:200] + "..." if len(response) > 200 
                else response)
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
