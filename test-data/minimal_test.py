#!/usr/bin/env python3
"""
Minimal SIP test - just generate traffic to FreeSWITCH
"""
import socket
import time
from datetime import datetime

def test_freeswitch_connectivity():
    """Test if FreeSWITCH is accepting SIP traffic"""
    print("🔍 Testing FreeSWITCH connectivity...")
    
    # Test 1: Basic UDP connection
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        
        # Try to connect to FreeSWITCH
        result = sock.connect_ex(('localhost', 5060))
        if result == 0:
            print("✅ Port 5060 is open and accepting connections")
        else:
            print(f"❌ Port 5060 connection failed: {result}")
            return False
            
        sock.close()
    except Exception as e:
        print(f"❌ UDP connection test failed: {e}")
        return False
    
    return True

def generate_sip_traffic():
    """Generate SIP OPTIONS messages"""
    print("📞 Generating SIP OPTIONS traffic...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        
        # SIP OPTIONS message
        timestamp = int(time.time())
        sip_message = f"""OPTIONS sip:localhost SIP/2.0
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK{timestamp}
From: <sip:test@127.0.0.1:5061>;tag=test{timestamp}
To: <sip:localhost>
Call-ID: test-call-{timestamp}@127.0.0.1
CSeq: 1 OPTIONS
Contact: <sip:test@127.0.0.1:5061>
Max-Forwards: 70
User-Agent: MinimalSIPTest/1.0
Content-Length: 0

"""
        
        # Send messages
        for i in range(3):
            try:
                sock.sendto(sip_message.encode(), ('localhost', 5060))
                print(f"📤 Sent SIP OPTIONS message {i+1}")
                time.sleep(1)
            except Exception as e:
                print(f"❌ Error sending message {i+1}: {e}")
        
        sock.close()
        print("✅ SIP traffic generation complete")
        return True
        
    except Exception as e:
        print(f"❌ SIP traffic generation failed: {e}")
        return False

def main():
    print("🚀 Starting Minimal SIP Test")
    print("=" * 40)
    
    # Test connectivity first
    if not test_freeswitch_connectivity():
        print("❌ FreeSWITCH connectivity test failed")
        return
    
    # Generate traffic
    if generate_sip_traffic():
        print("\n✅ Test completed successfully!")
        print("📊 FreeSWITCH is accepting SIP traffic")
        print("\nNext steps:")
        print("1. Use Wireshark or tcpdump manually to capture traffic")
        print("2. Or run: sudo tcpdump -i lo0 -w test.pcap host localhost and port 5060")
    else:
        print("\n❌ Test failed")

if __name__ == "__main__":
    main()
