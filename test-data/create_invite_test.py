#!/usr/bin/env python3
"""
Create INVITE-based SIP test with proper Call-IDs
"""
import subprocess
import time
import os
import uuid

def create_invite_pcap():
    """Create PCAP with INVITE messages that have Call-IDs"""
    print("📡 Creating INVITE-based PCAP file...")
    
    # Ensure pcaps directory exists
    os.makedirs("../pcaps", exist_ok=True)
    
    # PCAP filename
    pcap_file = "../pcaps/invite_test.pcap"
    
    # Remove old file if it exists
    if os.path.exists(pcap_file):
        os.remove(pcap_file)
    
    # Start tcpdump
    print("🔍 Starting tcpdump capture...")
    cmd = [
        'sudo', 'tcpdump',
        '-i', 'lo0',
        '-w', pcap_file,
        '-s', '0',
        'host', 'localhost', 'and', 'port', '5060'
    ]
    
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(3)
        
        print("📞 Generating INVITE messages...")
        
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Generate INVITE messages with proper Call-IDs
        for i in range(3):
            call_id = str(uuid.uuid4())
            timestamp = int(time.time())
            
            # INVITE message with Call-ID
            sip_msg = f"""INVITE sip:1001@localhost SIP/2.0
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK{timestamp}
From: <sip:1000@localhost>;tag=tag{timestamp}
To: <sip:1001@localhost>
Call-ID: {call_id}
CSeq: 1 INVITE
Contact: <sip:1000@127.0.0.1:5061>
Max-Forwards: 70
User-Agent: InviteTest/1.0
Content-Type: application/sdp
Content-Length: 0

"""
            sock.sendto(sip_msg.encode(), ('localhost', 5060))
            print(f"📤 Sent INVITE message {i+1} with Call-ID: {call_id[:8]}...")
            time.sleep(1)
        
        # Also send some OPTIONS for variety
        for i in range(2):
            call_id = str(uuid.uuid4())
            timestamp = int(time.time())
            
            opt_msg = f"""OPTIONS sip:localhost SIP/2.0
Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK{timestamp}
From: <sip:test@127.0.0.1:5061>;tag=tag{timestamp}
To: <sip:localhost>
Call-ID: {call_id}
CSeq: 1 OPTIONS
Contact: <sip:test@127.0.0.1:5061>
Max-Forwards: 70
User-Agent: InviteTest/1.0
Content-Length: 0

"""
            sock.sendto(opt_msg.encode(), ('localhost', 5060))
            print(f"📤 Sent OPTIONS message {i+1} with Call-ID: {call_id[:8]}...")
            time.sleep(1)
        
        sock.close()
        
        # Wait for capture
        time.sleep(3)
        
        # Stop tcpdump
        print("🛑 Stopping capture...")
        process.terminate()
        process.wait(timeout=5)
        
        # Check file
        if os.path.exists(pcap_file):
            file_size = os.path.getsize(pcap_file)
            print(f"✅ PCAP file created: {pcap_file}")
            print(f"📊 File size: {file_size} bytes")
            
            if file_size > 100:
                print("🎉 Success! INVITE-based PCAP file created")
                return pcap_file
            else:
                print("⚠️ PCAP file is too small")
                return None
        else:
            print("❌ PCAP file not created")
            return None
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return None

def main():
    print("🚀 Creating INVITE-Based SIP Test")
    print("=" * 40)
    
    pcap_file = create_invite_pcap()
    
    if pcap_file:
        print(f"\n✅ PCAP file ready: {pcap_file}")
        print("\nNext steps:")
        print(f"1. Parse PCAP: cd ../parser && python3 voip_parser.py {pcap_file} invite_test")
        print("2. Run correlation: python3 correlation_engine.py --trace-id invite_test")
    else:
        print("\n❌ Failed to create INVITE-based PCAP file")

if __name__ == "__main__":
    main()
