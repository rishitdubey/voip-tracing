#!/usr/bin/env python3
"""
Create a working PCAP file with SIP traffic
"""
import subprocess
import time
import os
import signal
import sys

def create_working_pcap():
    """Create a working PCAP file"""
    print("📡 Creating working PCAP file...")
    
    # Ensure pcaps directory exists
    os.makedirs("../pcaps", exist_ok=True)
    
    # PCAP filename
    pcap_file = "../pcaps/working_test.pcap"
    
    # Remove old file if it exists
    if os.path.exists(pcap_file):
        os.remove(pcap_file)
    
    # Start tcpdump in background
    print("🔍 Starting tcpdump capture...")
    cmd = [
        'sudo', 'tcpdump',
        '-i', 'lo0',  # Loopback interface
        '-w', pcap_file,
        '-s', '0',  # Full packet capture
        'host', 'localhost', 'and', 'port', '5060'
    ]
    
    try:
        # Start tcpdump
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Wait for tcpdump to start
        time.sleep(3)
        
        print("📞 Generating SIP traffic...")
        
        # Generate SIP traffic using Python
        import socket
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Send multiple SIP OPTIONS messages
        for i in range(5):
            sip_msg = f"""OPTIONS sip:localhost SIP/2.0
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK{i}
From: <sip:test@127.0.0.1:5061>;tag=test{i}
To: <sip:localhost>
Call-ID: test-call-{i}@127.0.0.1
CSeq: 1 OPTIONS
Contact: <sip:test@127.0.0.1:5061>
Max-Forwards: 70
User-Agent: WorkingTest/1.0
Content-Length: 0

"""
            sock.sendto(sip_msg.encode(), ('localhost', 5060))
            print(f"📤 Sent SIP message {i+1}")
            time.sleep(1)
        
        sock.close()
        
        # Wait a bit more for capture
        time.sleep(3)
        
        # Stop tcpdump
        print("🛑 Stopping capture...")
        process.terminate()
        process.wait(timeout=5)
        
        # Check if file was created and has content
        if os.path.exists(pcap_file):
            file_size = os.path.getsize(pcap_file)
            print(f"✅ PCAP file created: {pcap_file}")
            print(f"📊 File size: {file_size} bytes")
            
            if file_size > 100:  # Should be more than just headers
                print("🎉 Success! Working PCAP file created")
                return pcap_file
            else:
                print("⚠️ PCAP file is too small - may not contain traffic")
                return None
        else:
            print("❌ PCAP file not created")
            return None
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return None

def main():
    print("🚀 Creating Working PCAP File")
    print("=" * 40)
    
    pcap_file = create_working_pcap()
    
    if pcap_file:
        print(f"\n✅ PCAP file ready: {pcap_file}")
        print("\nNext steps:")
        print(f"1. Parse PCAP: cd ../parser && python3 voip_parser.py {pcap_file}")
        print("2. Run correlation: python3 correlation_engine.py --trace-id working_test")
    else:
        print("\n❌ Failed to create working PCAP file")

if __name__ == "__main__":
    main()
