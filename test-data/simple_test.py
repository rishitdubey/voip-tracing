#!/usr/bin/env python3
"""
Simple SIP test that generates traffic directly to FreeSWITCH
"""
import socket
import time
import subprocess
import os
from datetime import datetime

def generate_sip_traffic():
    """Generate simple SIP OPTIONS messages to FreeSWITCH"""
    print("📞 Generating SIP OPTIONS traffic to FreeSWITCH...")
    
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # SIP OPTIONS message
    sip_message = """OPTIONS sip:localhost SIP/2.0
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bKtest123
From: <sip:test@127.0.0.1:5061>;tag=test123
To: <sip:localhost>
Call-ID: test-call-{timestamp}@127.0.0.1
CSeq: 1 OPTIONS
Contact: <sip:test@127.0.0.1:5061>
Max-Forwards: 70
User-Agent: SimpleSIPTest/1.0
Content-Length: 0

""".format(timestamp=int(time.time()))
    
    # Send multiple OPTIONS messages
    for i in range(5):
        try:
            sock.sendto(sip_message.encode(), ('localhost', 5060))
            print(f"📤 Sent SIP OPTIONS message {i+1}")
            time.sleep(1)
        except Exception as e:
            print(f"❌ Error sending message {i+1}: {e}")
    
    sock.close()
    print("✅ SIP traffic generation complete")

def capture_traffic():
    """Capture network traffic using tcpdump"""
    print("📡 Starting packet capture...")
    
    # Create pcaps directory if it doesn't exist
    os.makedirs("../pcaps", exist_ok=True)
    
    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = f"../pcaps/simple_test_{timestamp}.pcap"
    
    # Start tcpdump capture
    cmd = [
        'sudo', 'tcpdump', 
        '-i', 'lo0',  # Use loopback interface for localhost traffic
        '-w', pcap_file,
        '-s', '0',  # Capture full packets
        'host', 'localhost', 'and', 'port', '5060'
    ]
    
    try:
        print(f"🔍 Running: {' '.join(cmd)}")
        print(f"💾 Capture file: {pcap_file}")
        
        # Start capture
        capture_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Wait a moment for capture to start
        time.sleep(2)
        
        # Generate traffic
        generate_sip_traffic()
        
        # Wait a bit more
        time.sleep(3)
        
        # Stop capture
        capture_proc.terminate()
        capture_proc.wait(timeout=5)
        
        # Check if file was created and has content
        if os.path.exists(pcap_file):
            file_size = os.path.getsize(pcap_file)
            print(f"✅ Capture complete! File size: {file_size} bytes")
            
            if file_size > 0:
                print(f"📁 PCAP file saved: {pcap_file}")
                return pcap_file
            else:
                print("⚠️ PCAP file is empty")
                return None
        else:
            print("❌ PCAP file not created")
            return None
            
    except Exception as e:
        print(f"❌ Error during capture: {e}")
        return None

def main():
    print("🚀 Starting Simple SIP Test")
    print("=" * 40)
    
    # Generate traffic and capture
    pcap_file = capture_traffic()
    
    if pcap_file:
        print(f"\n✅ Test completed successfully!")
        print(f"📁 PCAP file: {pcap_file}")
        print(f"\nNext steps:")
        print(f"1. Parse PCAP: cd ../parser && python3 voip_parser.py {pcap_file}")
        print(f"2. Run correlation: python3 correlation_engine.py --trace-id simple_test")
    else:
        print(f"\n❌ Test failed - no valid PCAP file generated")

if __name__ == "__main__":
    main()
