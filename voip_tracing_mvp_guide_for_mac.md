# VoIP Tracing MVP - Complete Implementation Guide (Mac M4/Apple Silicon)

**Project Goal:** Build a cybersecurity tool that can trace VoIP calls through network metadata analysis, correlate caller-to-callee relationships, and detect potential security anomalies.

**Timeline:** 6 Days (Hackathon Schedule)

---

## Prerequisites & Environment Setup

### System Requirements
- macOS Sonoma 14.0+ (recommended for M4 Mac)
- Mac M4 with 8GB+ RAM, 50GB+ available disk space
- Internet connection for package downloads
- Admin access (sudo privileges)

### Initial System Setup

```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Add Homebrew to PATH (add to ~/.zshrc for persistence)
echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zshrc
eval "$(/opt/homebrew/bin/brew shellenv)"

# Install essential packages
brew update
brew install curl wget git vim docker docker-compose python@3.11 sqlite3 wireshark

# Install Python packages
pip3 install --upgrade pip

# Create project directory structure
mkdir -p ~/voip-tracing-mvp/{docker,configs,captures,pcaps,logs,parser,webapp,test-data}
cd ~/voip-tracing-mvp
```

### Docker Setup for Apple Silicon

```bash
# Start Docker Desktop (install from Docker website if not installed)
# Make sure Docker Desktop is running and configured for Apple Silicon

# Verify Docker is working with ARM64 support
docker --version
docker info | grep Architecture

# Test Docker with a simple ARM64 container
docker run --rm hello-world
```

---

## Day 1: Infrastructure Setup

### Step 1.1: Deploy FreeSWITCH with Docker (ARM64 Compatible)

Create the Docker Compose configuration optimized for Apple Silicon:

```bash
# Create docker-compose.yml with ARM64 compatible images
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  freeswitch:
    image: signalwire/freeswitch:1.10.9-release
    platform: linux/arm64
    container_name: voip-freeswitch
    ports:
      - "5060:5060/udp"     # SIP UDP
      - "5060:5060/tcp"     # SIP TCP
      - "5080:5080/tcp"     # SIP WSS
      - "8021:8021/tcp"     # Event Socket
      - "10000-10100:10000-10100/udp"  # RTP range
    volumes:
      - ./configs/freeswitch:/usr/local/freeswitch/conf:ro
      - ./logs:/usr/local/freeswitch/log
    environment:
      - FREESWITCH_LOG_LEVEL=DEBUG
      - PLATFORM=linux/arm64
    restart: unless-stopped
    networks:
      - voip-network

  database:
    image: alpine:latest
    platform: linux/arm64
    container_name: voip-db-helper
    volumes:
      - ./database:/data
    command: tail -f /dev/null
    networks:
      - voip-network

networks:
  voip-network:
    driver: bridge
EOF
```-

### Step 1.2: Configure FreeSWITCH for Apple Silicon

```bash
# Create configs directory
mkdir -p configs/freeswitch/{dialplan,directory,sip_profiles,vars}

# Create variables configuration
cat > configs/freeswitch/vars.xml << 'EOF'
<configuration name="vars.conf" description="Variable Configuration">
  <X-PRE-PROCESS cmd="set" data="default_password=1234"/>
  <X-PRE-PROCESS cmd="set" data="domain=voip-lab.local"/>
  <X-PRE-PROCESS cmd="set" data="bind_server_ip=0.0.0.0"/>
  <X-PRE-PROCESS cmd="set" data="external_rtp_ip=auto"/>
  <X-PRE-PROCESS cmd="set" data="external_sip_ip=auto"/>
</configuration>
EOF

# Create SIP profile optimized for container networking
cat > configs/freeswitch/sip_profiles/internal.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<configuration name="sofia.conf" description="SIP Endpoint Configuration">
  <profiles>
    <profile name="internal">
      <aliases>
        <alias name="default"/>
      </aliases>
      <gateways>
      </gateways>
      <domains>
        <domain name="all" alias="false" parse="true"/>
      </domains>
      <settings>
        <param name="user-agent-string" value="FreeSWITCH-VoIP-Lab"/>
        <param name="debug" value="9"/>
        <param name="sip-trace" value="yes"/>
        <param name="sip-capture" value="yes"/>
        <param name="watchdog-enabled" value="no"/>
        <param name="watchdog-step-timeout" value="30000"/>
        <param name="watchdog-event-timeout" value="30000"/>
        <param name="log-auth-failures" value="true"/>
        <param name="forward-unsolicited-mwi-notify" value="false"/>
        <param name="context" value="default"/>
        <param name="rfc2833-pt" value="101"/>
        <param name="sip-port" value="5060"/>
        <param name="dialplan" value="XML"/>
        <param name="dtmf-duration" value="2000"/>
        <param name="inbound-codec-prefs" value="PCMU,PCMA,G722"/>
        <param name="outbound-codec-prefs" value="PCMU,PCMA,G722"/>
        <param name="rtp-timer-name" value="soft"/>
        <param name="local-network-acl" value="localnet.auto"/>
        <param name="manage-presence" value="true"/>
        <param name="inbound-codec-negotiation" value="generous"/>
        <param name="nonce-ttl" value="60"/>
        <param name="auth-calls" value="true"/>
        <param name="auth-all-packets" value="false"/>
        <param name="ext-rtp-ip" value="auto"/>
        <param name="ext-sip-ip" value="auto"/>
        <param name="rtp-ip" value="0.0.0.0"/>
        <param name="sip-ip" value="0.0.0.0"/>
        <param name="hold-music" value="local_stream://moh"/>
        <param name="apply-nat-acl" value="nat.auto"/>
        <param name="rtp-port-min" value="10000"/>
        <param name="rtp-port-max" value="10100"/>
        <param name="force-register-domain" value="voip-lab.local"/>
        <param name="force-subscription-domain" value="voip-lab.local"/>
        <param name="force-register-db-domain" value="voip-lab.local"/>
        <param name="challenge-realm" value="auto_from"/>
      </settings>
    </profile>
  </profiles>
</configuration>
EOF

# Create basic dialplan
cat > configs/freeswitch/dialplan/default.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<configuration name="dialplan.conf" description="Regex/XML Dialplan">
  <context name="default">
    <extension name="test-users">
      <condition field="destination_number" expression="^(1000|1001|1002|1003)$">
        <action application="set" data="hangup_after_bridge=true"/>
        <action application="set" data="continue_on_fail=true"/>
        <action application="bridge" data="user/${destination_number}@voip-lab.local"/>
        <action application="answer"/>
        <action application="sleep" data="1000"/>
        <action application="playback" data="tone_stream://%(2000,4000,440,480);loops=3"/>
        <action application="hangup"/>
      </condition>
    </extension>
    
    <extension name="echo-test">
      <condition field="destination_number" expression="^9999$">
        <action application="answer"/>
        <action application="echo"/>
      </condition>
    </extension>
  </context>
</configuration>
EOF

# Create directory with test users
mkdir -p configs/freeswitch/directory/default

cat > configs/freeswitch/directory/default/1000.xml << 'EOF'
<include>
  <user id="1000">
    <params>
      <param name="password" value="1234"/>
      <param name="vm-password" value="1000"/>
    </params>
    <variables>
      <variable name="toll_allow" value="domestic,international,local"/>
      <variable name="accountcode" value="1000"/>
      <variable name="user_context" value="default"/>
      <variable name="effective_caller_id_name" value="Extension 1000"/>
      <variable name="effective_caller_id_number" value="1000"/>
    </variables>
  </user>
</include>
EOF

cat > configs/freeswitch/directory/default/1001.xml << 'EOF'
<include>
  <user id="1001">
    <params>
      <param name="password" value="1234"/>
      <param name="vm-password" value="1001"/>
    </params>
    <variables>
      <variable name="toll_allow" value="domestic,international,local"/>
      <variable name="accountcode" value="1001"/>
      <variable name="user_context" value="default"/>
      <variable name="effective_caller_id_name" value="Extension 1001"/>
      <variable name="effective_caller_id_number" value="1001"/>
    </variables>
  </user>
</include>
EOF
```

### Step 1.3: Start the VoIP Infrastructure

```bash
# Start FreeSWITCH
docker-compose up -d

# Verify FreeSWITCH is running
docker logs voip-freeswitch

# Check if ports are listening (use lsof on Mac instead of netstat)
lsof -i :5060
lsof -i :10000-10100

# Test FreeSWITCH connectivity
docker exec -it voip-freeswitch fs_cli -x "status"
```

### Step 1.4: Install SIP Testing Tools for macOS

```bash
# Install SIP testing utilities via Homebrew
brew install nmap

# Install Python SIP libraries
pip3 install pyshark scapy pjsua2 flask flask-cors elasticsearch requests

# Install additional network tools
brew install tcpdump ngrep

# Note: We'll use Python-based SIP tools instead of sipvicious which has limited macOS support
```

---

## Day 2: Parser Development Foundation

### Step 2.1: Create Database Schema (macOS Compatible)

```bash
# Create database initialization script
cat > parser/init_database.py << 'EOF'
#!/usr/bin/env python3
import sqlite3
import sys
import os

def init_database(db_path="voip_metadata.db"):
    # Ensure directory exists
    db_dir = os.path.dirname(os.path.abspath(db_path))
    os.makedirs(db_dir, exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    # Enable foreign keys
    cur.execute("PRAGMA foreign_keys = ON")
    
    # SIP Sessions table
    cur.execute('''
    CREATE TABLE IF NOT EXISTS sip_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        call_id TEXT UNIQUE NOT NULL,
        from_uri TEXT,
        to_uri TEXT,
        start_time TEXT,
        end_time TEXT,
        status TEXT DEFAULT 'UNKNOWN',
        trace_id TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(call_id, trace_id)
    )''')
    
    # SIP Messages table
    cur.execute('''
    CREATE TABLE IF NOT EXISTS sip_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        call_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        method TEXT,
        response_code INTEGER,
        from_uri TEXT,
        to_uri TEXT,
        user_agent TEXT,
        sdp_content TEXT,
        src_ip TEXT,
        src_port INTEGER,
        dst_ip TEXT,
        dst_port INTEGER,
        trace_id TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(call_id) REFERENCES sip_sessions(call_id)
    )''')
    
    # RTP Flows table
    cur.execute('''
    CREATE TABLE IF NOT EXISTS rtp_flows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ssrc TEXT NOT NULL,
        src_ip TEXT,
        src_port INTEGER,
        dst_ip TEXT,
        dst_port INTEGER,
        payload_type INTEGER,
        packet_count INTEGER DEFAULT 1,
        first_seen TEXT,
        last_seen TEXT,
        trace_id TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Correlation Results table
    cur.execute('''
    CREATE TABLE IF NOT EXISTS correlations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        call_id TEXT NOT NULL,
        ssrc TEXT,
        correlation_confidence REAL,
        correlation_method TEXT,
        trace_id TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(call_id) REFERENCES sip_sessions(call_id)
    )''')
    
    # Security Events table
    cur.execute('''
    CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
        description TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        call_id TEXT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
        trace_id TEXT,
        metadata TEXT  -- JSON formatted additional data
    )''')
    
    # Create indexes for performance
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sip_messages_call_id ON sip_messages(call_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sip_messages_timestamp ON sip_messages(timestamp)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_rtp_flows_ssrc ON rtp_flows(ssrc)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_rtp_flows_endpoints ON rtp_flows(src_ip, src_port, dst_ip, dst_port)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_correlations_call_id ON correlations(call_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp)")
    
    conn.commit()
    conn.close()
    print(f"✅ Database initialized: {os.path.abspath(db_path)}")
    print("📊 Created tables: sip_sessions, sip_messages, rtp_flows, correlations, security_events")

if __name__ == "__main__":
    db_path = sys.argv[1] if len(sys.argv) > 1 else "voip_metadata.db"
    init_database(db_path)
EOF

# Run database initialization
python3 parser/init_database.py
```

### Step 2.2: Create Enhanced Parser Classes (macOS Optimized)

```bash
# Create the main parser module optimized for macOS
cat > parser/voip_parser.py << 'EOF'
#!/usr/bin/env python3
import pyshark
import sqlite3
import re
import json
import sys
import os
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SIPSession:
    def __init__(self, call_id: str):
        self.call_id = call_id
        self.from_uri = None
        self.to_uri = None
        self.start_time = None
        self.end_time = None
        self.status = "UNKNOWN"
        self.messages = []
        self.sdp_data = {}
        
    def add_message(self, timestamp, method, response_code, from_uri, to_uri, 
                   user_agent, sdp_content, src_ip, src_port, dst_ip, dst_port):
        message = {
            'timestamp': timestamp,
            'method': method,
            'response_code': response_code,
            'from_uri': from_uri,
            'to_uri': to_uri,
            'user_agent': user_agent,
            'sdp_content': sdp_content,
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port
        }
        self.messages.append(message)
        
        # Update session info from first INVITE
        if method == "INVITE" and not self.from_uri:
            self.from_uri = from_uri
            self.to_uri = to_uri
            self.start_time = timestamp
            
        # Update session status based on responses
        if response_code:
            if response_code == 200:
                self.status = "CONNECTED"
            elif 400 <= response_code < 500:
                self.status = "CLIENT_ERROR"
            elif 500 <= response_code < 600:
                self.status = "SERVER_ERROR"
            
        # Parse SDP for media information
        if sdp_content:
            self.parse_sdp(sdp_content)
    
    def parse_sdp(self, sdp_content: str):
        """Extract media information from SDP"""
        try:
            lines = sdp_content.split('\n')
            current_media_type = None
            
            for line in lines:
                line = line.strip()
                
                if line.startswith('m='):
                    # Media line: m=audio 5004 RTP/AVP 0
                    parts = line.split()
                    if len(parts) >= 4:
                        current_media_type = parts[0].split('=')[1]  # audio, video, etc.
                        port = parts[1]
                        protocol = parts[2]
                        self.sdp_data[f'{current_media_type}_port'] = int(port)
                        self.sdp_data[f'{current_media_type}_protocol'] = protocol
                        
                elif line.startswith('c='):
                    # Connection line: c=IN IP4 192.168.1.100
                    parts = line.split()
                    if len(parts) >= 3:
                        ip = parts[2]
                        if current_media_type:
                            self.sdp_data[f'{current_media_type}_ip'] = ip
                        else:
                            self.sdp_data['connection_ip'] = ip
                            
                elif line.startswith('a=rtpmap:'):
                    # RTP mapping: a=rtpmap:0 PCMU/8000
                    if current_media_type:
                        rtpmap_key = f'{current_media_type}_rtpmap'
                        if rtpmap_key not in self.sdp_data:
                            self.sdp_data[rtpmap_key] = []
                        self.sdp_data[rtpmap_key].append(line)
                        
        except Exception as e:
            logger.warning(f"Error parsing SDP: {e}")

class RTPFlow:
    def __init__(self, ssrc: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int):
        self.ssrc = ssrc
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.payload_type = None
        self.packet_count = 0
        self.first_seen = None
        self.last_seen = None

class VoIPParser:
    def __init__(self, db_path: str = "voip_metadata.db"):
        self.db_path = db_path
        self.sip_sessions: Dict[str, SIPSession] = {}
        self.rtp_flows: Dict[str, RTPFlow] = {}
        
        # Ensure database exists
        if not os.path.exists(db_path):
            logger.warning(f"Database {db_path} doesn't exist. Creating...")
            from init_database import init_database
            init_database(db_path)
            
    def parse_pcap(self, pcap_path: str, trace_id: str = None):
        """Parse a PCAP file and extract VoIP metadata"""
        if not trace_id:
            trace_id = Path(pcap_path).stem
            
        logger.info(f"🔍 Parsing PCAP: {pcap_path}")
        logger.info(f"📋 Trace ID: {trace_id}")
        
        if not os.path.exists(pcap_path):
            logger.error(f"❌ PCAP file not found: {pcap_path}")
            return
        
        try:
            # Use tshark display filter for better performance on macOS
            display_filter = "sip or rtp or rtcp"
            cap = pyshark.FileCapture(
                pcap_path, 
                display_filter=display_filter,
                keep_packets=False,
                use_json=True,
                include_raw=False
            )
            
            packet_count = 0
            sip_count = 0
            rtp_count = 0
            
            for pkt in cap:
                packet_count += 1
                if packet_count % 1000 == 0:
                    logger.info(f"📦 Processed {packet_count} packets...")
                
                try:
                    timestamp = pkt.sniff_time.isoformat()
                    
                    # Parse SIP packets
                    if hasattr(pkt, 'sip'):
                        self.parse_sip_packet(pkt, timestamp, trace_id)
                        sip_count += 1
                    
                    # Parse RTP packets
                    elif hasattr(pkt, 'rtp'):
                        self.parse_rtp_packet(pkt, timestamp, trace_id)
                        rtp_count += 1
                        
                except Exception as e:
                    logger.debug(f"Error processing packet: {e}")
                    continue
                    
            cap.close()
            
            logger.info(f"✅ Parsing complete:")
            logger.info(f"   📦 Total packets: {packet_count}")
            logger.info(f"   📞 SIP packets: {sip_count}")
            logger.info(f"   🎵 RTP packets: {rtp_count}")
            logger.info(f"   📋 SIP sessions: {len(self.sip_sessions)}")
            logger.info(f"   🔊 RTP flows: {len(self.rtp_flows)}")
            
        except Exception as e:
            logger.error(f"❌ Error parsing PCAP: {e}")
            return
            
        # Save to database
        self.save_to_database(trace_id)
        
    def parse_sip_packet(self, pkt, timestamp: str, trace_id: str):
        """Extract SIP message information"""
        try:
            sip = pkt.sip
            
            # Get basic packet info
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            
            # Handle different transport layers
            if hasattr(pkt, 'udp'):
                src_port = int(pkt.udp.srcport)
                dst_port = int(pkt.udp.dstport)
            elif hasattr(pkt, 'tcp'):
                src_port = int(pkt.tcp.srcport)
                dst_port = int(pkt.tcp.dstport)
            else:
                src_port = dst_port = 0
            
            # Extract SIP headers (handle different pyshark versions)
            call_id = None
            for attr in ['Call-ID', 'call_id', 'Call_ID']:
                if hasattr(sip, attr):
                    call_id = getattr(sip, attr)
                    break
                    
            method = getattr(sip, 'Method', getattr(sip, 'method', None))
            response_code = None
            
            # Try to get response code
            if hasattr(sip, 'Status-Code'):
                try:
                    response_code = int(getattr(sip, 'Status-Code'))
                except:
                    pass
            elif hasattr(sip, 'response_code'):
                try:
                    response_code = int(getattr(sip, 'response_code'))
                except:
                    pass
                    
            from_uri = getattr(sip, 'From', getattr(sip, 'from', None))
            to_uri = getattr(sip, 'To', getattr(sip, 'to', None))
            user_agent = getattr(sip, 'User-Agent', getattr(sip, 'user_agent', None))
            
            # Extract SDP if present
            sdp_content = None
            if hasattr(pkt, 'sdp'):
                try:
                    sdp_content = str(pkt.sdp)
                except:
                    pass
                    
            if call_id:
                if call_id not in self.sip_sessions:
                    self.sip_sessions[call_id] = SIPSession(call_id)
                
                self.sip_sessions[call_id].add_message(
                    timestamp, method, response_code, from_uri, to_uri,
                    user_agent, sdp_content, src_ip, src_port, dst_ip, dst_port
                )
                
        except Exception as e:
            logger.debug(f"Error parsing SIP packet: {e}")
    
    def parse_rtp_packet(self, pkt, timestamp: str, trace_id: str):
        """Extract RTP flow information"""
        try:
            rtp = pkt.rtp
            
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            src_port = int(pkt.udp.srcport)
            dst_port = int(pkt.udp.dstport)
            
            # Extract RTP fields
            ssrc = getattr(rtp, 'ssrc', getattr(rtp, 'p_ssrc', None))
            payload_type = getattr(rtp, 'p_type', getattr(rtp, 'payload_type', None))
            
            if ssrc:
                # Convert SSRC to string for consistency
                ssrc = str(ssrc)
                flow_key = f"{ssrc}_{src_ip}_{src_port}_{dst_ip}_{dst_port}"
                
                if flow_key not in self.rtp_flows:
                    flow = RTPFlow(ssrc, src_ip, src_port, dst_ip, dst_port)
                    if payload_type:
                        flow.payload_type = int(payload_type)
                    flow.first_seen = timestamp
                    self.rtp_flows[flow_key] = flow
                else:
                    flow = self.rtp_flows[flow_key]
                
                flow.packet_count += 1
                flow.last_seen = timestamp
                
        except Exception as e:
            logger.debug(f"Error parsing RTP packet: {e}")
    
    def save_to_database(self, trace_id: str):
        """Save parsed data to SQLite database"""
        logger.info(f"💾 Saving to database...")
        
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        
        try:
            # Save SIP sessions
            for call_id, session in self.sip_sessions.items():
                cur.execute('''
                    INSERT OR REPLACE INTO sip_sessions 
                    (call_id, from_uri, to_uri, start_time, end_time, status, trace_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (call_id, session.from_uri, session.to_uri, session.start_time,
                     session.end_time, session.status, trace_id))
                
                # Save SIP messages
                for msg in session.messages:
                    cur.execute('''
                        INSERT INTO sip_messages 
                        (call_id, timestamp, method, response_code, from_uri, to_uri, 
                         user_agent, sdp_content, src_ip, src_port, dst_ip, dst_port, trace_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (call_id, msg['timestamp'], msg['method'], msg['response_code'],
                         msg['from_uri'], msg['to_uri'], msg['user_agent'], 
                         msg['sdp_content'], msg['src_ip'], msg['src_port'],
                         msg['dst_ip'], msg['dst_port'], trace_id))
            
            # Save RTP flows
            for flow_key, flow in self.rtp_flows.items():
                cur.execute('''
                    INSERT OR REPLACE INTO rtp_flows 
                    (ssrc, src_ip, src_port, dst_ip, dst_port, payload_type, 
                     packet_count, first_seen, last_seen, trace_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (flow.ssrc, flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port,
                     flow.payload_type, flow.packet_count, flow.first_seen, 
                     flow.last_seen, trace_id))
            
            conn.commit()
            logger.info(f"✅ Saved {len(self.sip_sessions)} SIP sessions and {len(self.rtp_flows)} RTP flows")
            
        except Exception as e:
            logger.error(f"❌ Error saving to database: {e}")
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def get_parsing_stats(self) -> dict:
        """Get statistics about the parsed data"""
        return {
            'sip_sessions': len(self.sip_sessions),
            'rtp_flows': len(self.rtp_flows),
            'total_sip_messages': sum(len(s.messages) for s in self.sip_sessions.values()),
            'sessions_with_sdp': len([s for s in self.sip_sessions.values() if s.sdp_data])
        }

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 voip_parser.py <pcap_file> [trace_id]")
        print("Example: python3 voip_parser.py captures/test1.pcap test1_basic_call")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    trace_id = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Verify file exists
    if not os.path.exists(pcap_file):
        logger.error(f"❌ PCAP file not found: {pcap_file}")
        sys.exit(1)
    
    parser = VoIPParser()
    parser.parse_pcap(pcap_file, trace_id)
    
    # Print statistics
    stats = parser.get_parsing_stats()
    print(f"\n📊 Parsing Statistics:")
    for key, value in stats.items():
        print(f"   {key}: {value}")

if __name__ == "__main__":
    main()
EOF

# Make parser executable
chmod +x parser/voip_parser.py
```

---

## Day 3: Correlation Engine & Testing Infrastructure

### Step 3.1: Create Advanced Correlation Engine

```bash
# Create correlation engine optimized for macOS
cat > parser/correlation_engine.py << 'EOF'
#!/usr/bin/env python3
import sqlite3
import json
import re
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional
import os

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CorrelationEngine:
    def __init__(self, db_path: str = "voip_metadata.db"):
        self.db_path = db_path
        if not os.path.exists(db_path):
            logger.error(f"❌ Database not found: {db_path}")
            raise FileNotFoundError(f"Database not found: {db_path}")
        
    def correlate_sessions_to_flows(self, trace_id: str = None, confidence_threshold: float = 0.3) -> List[Dict]:
        """Correlate SIP sessions with RTP flows using multiple methods"""
        logger.info(f"🔗 Starting correlation analysis...")
        if trace_id:
            logger.info(f"📋 Filtering by trace_id: {trace_id}")
            
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        
        correlations = []
        
        # Get all SIP sessions
        session_query = "SELECT * FROM sip_sessions"
        params = []
        if trace_id:
            session_query += " WHERE trace_id = ?"
            params.append(trace_id)
            
        cur.execute(session_query, params)
        sessions = cur.fetchall()
        
        logger.info(f"📞 Found {len(sessions)} SIP sessions")
        
        for session in sessions:
            call_id = session[1]  # call_id is second column
            correlation = self.find_rtp_flows_for_session(cur, call_id, trace_id, confidence_threshold)
            if correlation and correlation['confidence'] >= confidence_threshold:
                correlations.append(correlation)
                logger.info(f"✅ Correlated session {call_id[:8]}... with {len(correlation['matching_flows'])} flows (confidence: {correlation['confidence']:.2f})")
            else:
                logger.warning(f"❌ No correlation found for session {call_id[:8]}...")
                
        conn.close()
        logger.info(f"🎯 Total correlations found: {len(correlations)}")
        return correlations
    
    def find_rtp_flows_for_session(self, cur, call_id: str, trace_id: str = None, confidence_threshold: float = 0.3) -> Optional[Dict]:
        """Find RTP flows that belong to a specific SIP session using multiple correlation methods"""
        
        # Get SIP messages for this session
        msg_query = '''
            SELECT timestamp, sdp_content, src_ip, dst_ip, method, response_code 
            FROM sip_messages 
            WHERE call_id = ?
        '''
        params = [call_id]
        if trace_id:
            msg_query += " AND trace_id = ?"
            params.append(trace_id)
        msg_query += " ORDER BY timestamp"
            
        cur.execute(msg_query, params)
        messages = cur.fetchall()
        
        if not messages:
            return None
        
        # Extract session timing and SDP information
        session_start_time = None
        session_end_time = None
        expected_media_endpoints = []
        session_participants = set()
        
        for msg in messages:
            timestamp, sdp_content, src_ip, dst_ip, method, response_code = msg
            msg_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            
            if not session_start_time:
                session_start_time = msg_time
            session_end_time = msg_time
            
            # Track session participants
            session_participants.add(src_ip)
            session_participants.add(dst_ip)
            
            # Parse SDP for media endpoints
            if sdp_content:
                media_info = self.parse_sdp_for_correlation(sdp_content, src_ip, dst_ip)
                expected_media_endpoints.extend(media_info)
        
        if not session_start_time:
            return None
        
        # Method 1: SDP-based correlation
        sdp_flows = self.correlate_by_sdp(cur, expected_media_endpoints, session_start_time, trace_id)
        
        # Method 2: Timing-based correlation
        timing_flows = self.correlate_by_timing(cur, session_participants, session_start_time, session_end_time, trace_id)
        
        # Method 3: Port-proximity correlation (common for RTP port allocation)
        proximity_flows = self.correlate_by_port_proximity(cur, session_participants, session_start_time, trace_id)
        
        # Combine and score correlations
        all_flows = {}
        
        # Add SDP correlations (highest confidence)
        for flow in sdp_flows:
            flow_key = f"{flow['ssrc']}_{flow['src_ip']}_{flow['src_port']}"
            if flow_key not in all_flows:
                all_flows[flow_key] = flow
                all_flows[flow_key]['correlation_methods'] = ['sdp']
                all_flows[flow_key]['base_confidence'] = 0.9
            else:
                all_flows[flow_key]['correlation_methods'].append('sdp')
                all_flows[flow_key]['base_confidence'] = max(all_flows[flow_key]['base_confidence'], 0.9)
        
        # Add timing correlations (medium confidence)
        for flow in timing_flows:
            flow_key = f"{flow['ssrc']}_{flow['src_ip']}_{flow['src_port']}"
            if flow_key not in all_flows:
                all_flows[flow_key] = flow
                all_flows[flow_key]['correlation_methods'] = ['timing']
                all_flows[flow_key]['base_confidence'] = 0.6
            else:
                all_flows[flow_key]['correlation_methods'].append('timing')
                all_flows[flow_key]['base_confidence'] = max(all_flows[flow_key]['base_confidence'], 0.6)
        
        # Add proximity correlations (lower confidence)
        for flow in proximity_flows:
            flow_key = f"{flow['ssrc']}_{flow['src_ip']}_{flow['src_port']}"
            if flow_key not in all_flows:
                all_flows[flow_key] = flow
                all_flows[flow_key]['correlation_methods'] = ['proximity']
                all_flows[flow_key]['base_confidence'] = 0.4
            else:
                all_flows[flow_key]['correlation_methods'].append('proximity')
                all_flows[flow_key]['base_confidence'] = max(all_flows[flow_key]['base_confidence'], 0.4)
        
        # Calculate final confidence scores
        matching_flows = []
        for flow_key, flow in all_flows.items():
            method_bonus = len(flow['correlation_methods']) * 0.1
            final_confidence = min(1.0, flow['base_confidence'] + method_bonus)
            
            flow['confidence'] = final_confidence
            flow['correlation_methods_str'] = ','.join(flow['correlation_methods'])
            
            if final_confidence >= confidence_threshold:
                matching_flows.append(flow)
        
        if matching_flows:
            avg_confidence = sum(f['confidence'] for f in matching_flows) / len(matching_flows)
            
            # Save correlation to database
            self.save_correlation(call_id, matching_flows, avg_confidence, "multi_method", trace_id)
            
            return {
                'call_id': call_id,
                'matching_flows': matching_flows,
                'confidence': avg_confidence,
                'method': 'multi_method_correlation',
                'session_duration': (session_end_time - session_start_time).total_seconds()
            }
        
        return None
    
    def correlate_by_sdp(self, cur, expected_endpoints: List[Dict], session_start: datetime, trace_id: str) -> List[Dict]:
        """Correlate RTP flows based on SDP-declared endpoints"""
        flows = []
        
        for endpoint in expected_endpoints:
            # Look for RTP flows matching SDP-declared IP and port
            flow_query = '''
                SELECT * FROM rtp_flows 
                WHERE ((src_ip = ? AND src_port = ?) OR (dst_ip = ? AND dst_port = ?))
                AND datetime(first_seen) >= datetime(?)
                AND datetime(first_seen) <= datetime(?)
            '''
            start_window = (session_start - timedelta(seconds=5)).isoformat()
            end_window = (session_start + timedelta(seconds=60)).isoformat()
            
            params = [endpoint['ip'], endpoint['port'], endpoint['ip'], endpoint['port'], start_window, end_window]
            
            if trace_id:
                flow_query += " AND trace_id = ?"
                params.append(trace_id)
                
            cur.execute(flow_query, params)
            rtp_flows = cur.fetchall()
            
            for flow in rtp_flows:
                flows.append({
                    'ssrc': flow[1],
                    'src_ip': flow[2],
                    'src_port': flow[3],
                    'dst_ip': flow[4],
                    'dst_port': flow[5],
                    'packet_count': flow[7],
                    'payload_type': flow[6]
                })
        
        return flows
    
    def correlate_by_timing(self, cur, participants: set, session_start: datetime, session_end: datetime, trace_id: str) -> List[Dict]:
        """Correlate RTP flows based on timing overlap with SIP session"""
        flows = []
        
        # Look for RTP flows that started around the session time and involve session participants
        participant_list = list(participants)
        if len(participant_list) < 2:
            return flows
            
        start_window = (session_start - timedelta(seconds=10)).isoformat()
        end_window = (session_start + timedelta(seconds=30)).isoformat()
        
        flow_query = '''
            SELECT * FROM rtp_flows 
            WHERE datetime(first_seen) >= datetime(?)
            AND datetime(first_seen) <= datetime(?)
            AND ((src_ip IN ({}) AND dst_ip IN ({}))
                 OR (src_ip IN ({}) AND dst_ip IN ({})))
        '''.format(
            ','.join(['?' for _ in participant_list]),
            ','.join(['?' for _ in participant_list]),
            ','.join(['?' for _ in participant_list]),
            ','.join(['?' for _ in participant_list])
        )
        
        params = [start_window, end_window] + participant_list * 4
        
        if trace_id:
            flow_query += " AND trace_id = ?"
            params.append(trace_id)
            
        cur.execute(flow_query, params)
        rtp_flows = cur.fetchall()
        
        for flow in rtp_flows:
            flows.append({
                'ssrc': flow[1],
                'src_ip': flow[2],
                'src_port': flow[3],
                'dst_ip': flow[4],
                'dst_port': flow[5],
                'packet_count': flow[7],
                'payload_type': flow[6]
            })
        
        return flows
    
    def correlate_by_port_proximity(self, cur, participants: set, session_start: datetime, trace_id: str) -> List[Dict]:
        """Correlate RTP flows based on port proximity (RTP ports are often allocated sequentially)"""
        flows = []
        
        participant_list = list(participants)
        if len(participant_list) < 2:
            return flows
            
        # Look for RTP flows in common RTP port ranges
        start_window = (session_start - timedelta(seconds=15)).isoformat()
        end_window = (session_start + timedelta(seconds=45)).isoformat()
        
        flow_query = '''
            SELECT * FROM rtp_flows 
            WHERE datetime(first_seen) >= datetime(?)
            AND datetime(first_seen) <= datetime(?)
            AND ((src_port BETWEEN 10000 AND 20000) OR (dst_port BETWEEN 10000 AND 20000))
            AND ((src_ip IN ({}) AND dst_ip IN ({}))
                 OR (dst_ip IN ({}) AND src_ip IN ({})))
        '''.format(
            ','.join(['?' for _ in participant_list]),
            ','.join(['?' for _ in participant_list]),
            ','.join(['?' for _ in participant_list]),
            ','.join(['?' for _ in participant_list])
        )
        
        params = [start_window, end_window] + participant_list * 4
        
        if trace_id:
            flow_query += " AND trace_id = ?"
            params.append(trace_id)
            
        cur.execute(flow_query, params)
        rtp_flows = cur.fetchall()
        
        for flow in rtp_flows:
            flows.append({
                'ssrc': flow[1],
                'src_ip': flow[2],
                'src_port': flow[3],
                'dst_ip': flow[4],
                'dst_port': flow[5],
                'packet_count': flow[7],
                'payload_type': flow[6]
            })
        
        return flows
    
    def parse_sdp_for_correlation(self, sdp_content: str, src_ip: str, dst_ip: str) -> List[Dict]:
        """Extract media endpoint information from SDP for correlation"""
        endpoints = []
        current_ip = None
        
        lines = sdp_content.split('\n')
        for line in lines:
            line = line.strip()
            
            # Connection information: c=IN IP4 192.168.1.100
            if line.startswith('c='):
                parts = line.split()
                if len(parts) >= 3:
                    current_ip = parts[2]
            
            # Media line: m=audio 5004 RTP/AVP 0
            elif line.startswith('m='):
                parts = line.split()
                if len(parts) >= 3:
                    media_type = parts[0].split('=')[1]
                    try:
                        port = int(parts[1])
                        
                        # Use connection IP if available, otherwise use source IP
                        ip = current_ip if current_ip else src_ip
                        
                        endpoints.append({
                            'type': media_type,
                            'ip': ip,
                            'port': port
                        })
                    except ValueError:
                        continue
        
        return endpoints
    
    def save_correlation(self, call_id: str, flows: List[Dict], confidence: float, method: str, trace_id: str):
        """Save correlation result to database"""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        
        try:
            for flow in flows:
                cur.execute('''
                    INSERT OR REPLACE INTO correlations 
                    (call_id, ssrc, correlation_confidence, correlation_method, trace_id)
                    VALUES (?, ?, ?, ?, ?)
                ''', (call_id, flow['ssrc'], confidence, method, trace_id))
            
            conn.commit()
        except Exception as e:
            logger.error(f"❌ Error saving correlation: {e}")
            conn.rollback()
        finally:
            conn.close()
    
    def generate_call_flow_report(self, trace_id: str = None, output_format: str = 'json') -> Dict:
        """Generate a comprehensive report of call flows"""
        logger.info(f"📊 Generating call flow report...")
        
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        
        # Get all correlations with session and flow details
        corr_query = '''
            SELECT c.call_id, c.ssrc, c.correlation_confidence, c.correlation_method,
                   s.from_uri, s.to_uri, s.start_time, s.status,
                   r.src_ip, r.src_port, r.dst_ip, r.dst_port, r.packet_count, r.payload_type
            FROM correlations c
            JOIN sip_sessions s ON c.call_id = s.call_id
            JOIN rtp_flows r ON c.ssrc = r.ssrc
        '''
        params = []
        if trace_id:
            corr_query += " WHERE c.trace_id = ?"
            params.append(trace_id)
        corr_query += " ORDER BY s.start_time, c.call_id"
            
        cur.execute(corr_query, params)
        results = cur.fetchall()
        
        report = {
            'metadata': {
                'trace_id': trace_id,
                'generated_at': datetime.now().isoformat(),
                'total_correlated_calls': 0,
                'high_confidence_calls': 0,
                'medium_confidence_calls': 0,
                'low_confidence_calls': 0
            },
            'calls': [],
            'summary': {
                'total_rtp_flows': 0,
                'average_confidence': 0.0,
                'correlation_methods': {}
            }
        }
        
        # Group by call_id
        calls_dict = {}
        confidence_scores = []
        
        for row in results:
            call_id = row[0]
            confidence = row[2]
            confidence_scores.append(confidence)
            
            if call_id not in calls_dict:
                calls_dict[call_id] = {
                    'call_id': call_id,
                    'from_uri': row[4],
                    'to_uri': row[5],
                    'start_time': row[6],
                    'status': row[7],
                    'confidence': confidence,
                    'correlation_method': row[3],
                    'media_flows': []
                }
            
            # Update confidence to highest for this call
            if confidence > calls_dict[call_id]['confidence']:
                calls_dict[call_id]['confidence'] = confidence
            
            calls_dict[call_id]['media_flows'].append({
                'ssrc': row[1],
                'src_endpoint': f"{row[8]}:{row[9]}",
                'dst_endpoint': f"{row[10]}:{row[11]}",
                'packet_count': row[12],
                'payload_type': row[13],
                'confidence': confidence
            })
            
            # Count correlation methods
            method = row[3]
            if method not in report['summary']['correlation_methods']:
                report['summary']['correlation_methods'][method] = 0
            report['summary']['correlation_methods'][method] += 1
        
        report['calls'] = list(calls_dict.values())
        report['metadata']['total_correlated_calls'] = len(calls_dict)
        
        # Calculate confidence distribution
        for call in report['calls']:
            conf = call['confidence']
            if conf >= 0.8:
                report['metadata']['high_confidence_calls'] += 1
            elif conf >= 0.5:
                report['metadata']['medium_confidence_calls'] += 1
            else:
                report['metadata']['low_confidence_calls'] += 1
        
        # Calculate summary statistics
        if confidence_scores:
            report['summary']['average_confidence'] = sum(confidence_scores) / len(confidence_scores)
        
        report['summary']['total_rtp_flows'] = sum(len(call['media_flows']) for call in report['calls'])
        
        conn.close()
        
        logger.info(f"✅ Report generated:")
        logger.info(f"   📞 Total calls: {report['metadata']['total_correlated_calls']}")
        logger.info(f"   🎯 Average confidence: {report['summary']['average_confidence']:.2f}")
        logger.info(f"   📊 High confidence calls: {report['metadata']['high_confidence_calls']}")
        
        return report

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='VoIP Call Flow Correlation Engine')
    parser.add_argument('--db', default='voip_metadata.db', help='Database path')
    parser.add_argument('--trace-id', help='Filter by trace ID')
    parser.add_argument('--confidence', type=float, default=0.3, help='Minimum confidence threshold')
    parser.add_argument('--report', action='store_true', help='Generate detailed report')
    parser.add_argument('--output', default='report.json', help='Output file for report')
    
    args = parser.parse_args()
    
    engine = CorrelationEngine(args.db)
    
    # Run correlation analysis
    correlations = engine.correlate_sessions_to_flows(args.trace_id, args.confidence)
    
    if args.report:
        report = engine.generate_call_flow_report(args.trace_id)
        
        # Save report to file
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"📊 Report saved to: {args.output}")
    else:
        print(f"🎯 Found {len(correlations)} correlations")
        for corr in correlations[:5]:  # Show first 5
            print(f"   📞 {corr['call_id'][:8]}... -> {len(corr['matching_flows'])} flows (confidence: {corr['confidence']:.2f})")

if __name__ == "__main__":
    main()
EOF

# Make correlation engine executable
chmod +x parser/correlation_engine.py
```

### Step 3.2: Create macOS-Compatible Test Infrastructure

```bash
# Create test call generator for macOS
cat > test-data/generate_test_calls.py << 'EOF'
#!/usr/bin/env python3
import subprocess
import time
import os
import json
import logging
from datetime import datetime
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MacOSTestCallGenerator:
    def __init__(self, freeswitch_ip="localhost", sip_port=5060):
        self.freeswitch_ip = freeswitch_ip
        self.sip_port = sip_port
        self.pcap_dir = Path("../pcaps")
        self.pcap_dir.mkdir(exist_ok=True)
        
    def check_prerequisites(self):
        """Check if required tools are available on macOS"""
        logger.info("🔍 Checking prerequisites...")
        
        # Check if tcpdump is available (requires sudo)
        try:
            result = subprocess.run(['which', 'tcpdump'], capture_output=True, text=True)
            if result.returncode != 0:
                logger.error("❌ tcpdump not found. Install with: brew install tcpdump")
                return False
            logger.info("✅ tcpdump found")
        except Exception as e:
            logger.error(f"❌ Error checking tcpdump: {e}")
            return False
            
        # Check Docker containers
        try:
            result = subprocess.run(['docker', 'ps', '--filter', 'name=voip-freeswitch', '--format', '{{.Status}}'], 
                                  capture_output=True, text=True)
            if 'Up' not in result.stdout:
                logger.warning("⚠️  FreeSWITCH container not running. Starting it...")
                subprocess.run(['docker-compose', 'up', '-d'], cwd='../', check=True)
                time.sleep(5)  # Wait for startup
        except Exception as e:
            logger.error(f"❌ Error checking FreeSWITCH container: {e}")
            return False
            
        logger.info("✅ Prerequisites check complete")
        return True
    
    def start_packet_capture(self, test_name: str) -> tuple:
        """Start packet capture using tcpdump on macOS"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_file = self.pcap_dir / f"{test_name}_{timestamp}.pcap"
        
        # Determine network interface (usually en0 on macOS)
        try:
            # Get default route interface
            route_result = subprocess.run(['route', 'get', 'default'], capture_output=True, text=True)
            interface = 'en0'  # fallback
            for line in route_result.stdout.split('\n'):
                if 'interface:' in line:
                    interface = line.split(':')[1].strip()
                    break
        except:
            interface = 'en0'
            
        logger.info(f"📡 Starting packet capture on interface {interface}")
        logger.info(f"💾 Capture file: {pcap_file}")
        
        # Start tcpdump with broader filter for VoIP traffic
        capture_cmd = [
            'sudo', 'tcpdump', '-i', interface, '-w', str(pcap_file),
            '-s', '0',  # Capture full packets
            f'host {self.freeswitch_ip} and (port 5060 or portrange 10000-10100 or port 8021)'
        ]
        
        try:
            capture_proc = subprocess.Popen(capture_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            logger.info("📦 Packet capture started")
            return capture_proc, pcap_file
        except Exception as e:
            logger.error(f"❌ Failed to start packet capture: {e}")
            return None, None
    
    def stop_packet_capture(self, capture_proc, pcap_file):
        """Stop packet capture and return file info"""
        if capture_proc:
            logger.info("🛑 Stopping packet capture...")
            capture_proc.terminate()
            
            # Wait for termination
            try:
                capture_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                capture_proc.kill()
                capture_proc.wait()
            
            # Check if file was created and has content
            if pcap_file and os.path.exists(pcap_file):
                file_size = os.path.getsize(pcap_file)
                logger.info(f"✅ Capture stopped. File size: {file_size} bytes")
                return True
            else:
                logger.warning("⚠️  Capture file not found or empty")
                return False
        return False
    
    def generate_sip_traffic_with_pjsua(self, test_scenario: str):
        """Generate SIP traffic using Python pjsua2 library"""
        logger.info(f"📞 Generating SIP traffic for: {test_scenario}")
        
        # Create a simple Python script to generate SIP traffic
        pjsua_script = f'''
import pjsua2 as pj
import time
import sys

class SipAccount(pj.Account):
    def __init__(self):
        pj.Account.__init__(self)
        
    def onRegState(self, prm):
        print(f"Registration status: {{prm.code}} ({{prm.reason}})")
        
    def onIncomingCall(self, prm):
        print(f"Incoming call from: {{prm.rdata.srcAddress}}")

def create_sip_test():
    # Create endpoint
    ep = pj.Endpoint()
    ep.libCreate()
    
    # Initialize endpoint
    ep_cfg = pj.EpConfig()
    ep_cfg.logConfig.level = 4
    ep_cfg.logConfig.consoleLevel = 4
    ep.libInit(ep_cfg)
    
    # Create transport
    transport_cfg = pj.TransportConfig()
    transport_cfg.port = 0
    ep.transportCreate(pj.PJSIP_TRANSPORT_UDP, transport_cfg)
    
    # Start endpoint
    ep.libStart()
    
    # Create account config
    acc_cfg = pj.AccountConfig()
    acc_cfg.idUri = "sip:test1000@{self.freeswitch_ip}"
    acc_cfg.regConfig.registrarUri = "sip:{self.freeswitch_ip}:{self.sip_port}"
    
    # Add credentials
    cred = pj.AuthCredInfo()
    cred.scheme = "digest"
    cred.realm = "*"
    cred.username = "1000"
    cred.data = "1234"
    cred.dataType = pj.PJSIP_CRED_DATA_PLAIN_PASSWD
    acc_cfg.sipConfig.authCreds.append(cred)
    
    # Create account
    acc = SipAccount()
    acc.create(acc_cfg)
    
    print("Waiting for registration...")
    time.sleep(3)
    
    # Make a simple call attempt
    try:
        call = pj.Call(acc)
        call_prm = pj.CallOpParam()
        call_prm.opt.audioCount = 1
        call_prm.opt.videoCount = 0
        
        call.makeCall("sip:1001@{self.freeswitch_ip}", call_prm)
        print("Call initiated...")
        
        time.sleep(10)  # Let call attempt run
        
        # Hangup
        call.hangup(pj.CallOpParam())
        print("Call terminated")
        
    except Exception as e:
        print(f"Call error: {{e}}")
    
    time.sleep(2)
    
    # Cleanup
    ep.libDestroy()
    
if __name__ == "__main__":
    create_sip_test()
'''
        
        # Save script to temp file
        script_file = Path("/tmp/sip_test.py")
        with open(script_file, 'w') as f:
            f.write(pjsua_script)
        
        try:
            # Run the SIP test script
            result = subprocess.run(['python3', str(script_file)], 
                                  timeout=30, capture_output=True, text=True)
            logger.info("📞 SIP traffic generation completed")
            logger.info(f"Output: {result.stdout}")
            if result.stderr:
                logger.warning(f"Warnings: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            logger.info("📞 SIP traffic generation timed out (as expected)")
        except Exception as e:
            logger.warning(f"⚠️ SIP traffic generation error: {e}")
        finally:
            # Cleanup temp file
            if script_file.exists():
                script_file.unlink()
    
    def generate_simple_udp_traffic(self):
        """Generate simple UDP traffic to SIP port for basic testing"""
        logger.info("📡 Generating simple UDP traffic to SIP port...")
        
        try:
            import socket
            
            # Send simple UDP packets to SIP port
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Simple SIP OPTIONS message
            sip_message = f'''OPTIONS sip:{self.freeswitch_ip} SIP/2.0
Via: SIP/2.0/UDP test-client:5060;branch=z9hG4bKtest123
From: <sip:test@test-client>;tag=test123
To: <sip:{self.freeswitch_ip}>
Call-ID: test-call-{datetime.now().strftime('%H%M%S')}@test-client
CSeq: 1 OPTIONS
Contact: <sip:test@test-client:5060>
Content-Length: 0

'''
            
            for i in range(3):
                sock.sendto(sip_message.encode(), (self.freeswitch_ip, self.sip_port))
                time.sleep(1)
                
            sock.close()
            logger.info("✅ UDP traffic sent")
            
        except Exception as e:
            logger.warning(f"⚠️ UDP traffic generation error: {e}")
    
    def run_test_scenario(self, scenario_name: str, scenario_config: dict):
        """Run a complete test scenario with packet capture"""
        logger.info(f"🚀 Starting test scenario: {scenario_name}")
        
        # Start packet capture
        capture_proc, pcap_file = self.start_packet_capture(scenario_name)
        
        if not capture_proc:
            logger.error("❌ Failed to start packet capture")
            return None
        
        try:
            # Wait for capture to start
            time.sleep(2)
            
            # Generate traffic based on scenario
            if scenario_config.get('method') == 'pjsua':
                self.generate_sip_traffic_with_pjsua(scenario_name)
            elif scenario_config.get('method') == 'docker':
                self.generate_docker_sip_traffic(scenario_config)
            else:
                # Fallback to simple UDP traffic
                self.generate_simple_udp_traffic()
            
            # Let traffic flow for a bit
            time.sleep(scenario_config.get('duration', 15))
            
        except Exception as e:
            logger.error(f"❌ Error during traffic generation: {e}")
        finally:
            # Stop capture
            success = self.stop_packet_capture(capture_proc, pcap_file)
            
            if success:
                logger.info(f"✅ Test scenario '{scenario_name}' completed")
                logger.info(f"📁 PCAP file: {pcap_file}")
                return pcap_file
            else:
                logger.error(f"❌ Test scenario '{scenario_name}' failed")
                return None
    
    def generate_docker_sip_traffic(self, scenario_config):
        """Generate SIP traffic using docker exec commands"""
        logger.info("📞 Generating SIP traffic via FreeSWITCH console...")
        
        try:
            # Use FreeSWITCH fs_cli to generate test calls
            commands = [
                "originate user/1000 &echo()",
                "status",
                "show registrations"
            ]
            
            for cmd in commands:
                docker_cmd = [
                    'docker', 'exec', 'voip-freeswitch', 
                    'fs_cli', '-x', cmd
                ]
                
                result = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=10)
                logger.info(f"FreeSWITCH command '{cmd}': {result.stdout.strip()}")
                
                time.sleep(2)
                
        except Exception as e:
            logger.warning(f"⚠️ Docker SIP traffic generation error: {e}")

def main():
    """Main function to run test scenarios"""
    generator = MacOSTestCallGenerator()
    
    if not generator.check_prerequisites():
        logger.error("❌ Prerequisites check failed")
        return 1
    
    # Define test scenarios
    test_scenarios = {
        'basic_sip_options': {
            'method': 'udp',
            'duration': 10,
            'description': 'Basic SIP OPTIONS requests'
        },
        'registration_attempt': {
            'method': 'pjsua',
            'duration': 15,
            'description': 'SIP registration and call attempt'
        },
        'freeswitch_internal': {
            'method': 'docker',
            'duration': 20,
            'description': 'Internal FreeSWITCH call generation'
        }
    }
    
    pcap_files = []
    
    for scenario_name, config in test_scenarios.items():
        logger.info(f"\n{'='*50}")
        logger.info(f"🎯 Test Scenario: {scenario_name}")
        logger.info(f"📝 Description: {config['description']}")
        logger.info(f"{'='*50}")
        
        pcap_file = generator.run_test_scenario(scenario_name, config)
        
        if pcap_file:
            pcap_files.append({
                'scenario': scenario_name,
                'file': str(pcap_file),
                'description': config['description']
            })
        
        # Wait between scenarios
        time.sleep(5)
    
    # Summary
    logger.info(f"\n{'='*50}")
    logger.info("📊 TEST SUMMARY")
    logger.info(f"{'='*50}")
    logger.info(f"✅ Generated {len(pcap_files)} test captures:")
    
    for pcap_info in pcap_files:
        logger.info(f"   📁 {pcap_info['scenario']}: {pcap_info['file']}")
    
    # Save test manifest
    manifest = {
        'generated_at': datetime.now().isoformat(),
        'test_scenarios': pcap_files,
        'next_steps': [
            'Parse PCAP files with: python3 ../parser/voip_parser.py <pcap_file>',
            'Run correlation analysis with: python3 ../parser/correlation_engine.py',
            'Generate reports with: python3 ../parser/correlation_engine.py --report'
        ]
    }
    
    manifest_file = Path('../test_manifest.json')
    with open(manifest_file, 'w') as f:
        json.dump(manifest, f, indent=2)
    
    logger.info(f"📋 Test manifest saved: {manifest_file}")
    
    return 0

if __name__ == "__main__":
    exit(main())
EOF

# Make test generator executable
chmod +x test-data/generate_test_calls.py
```

### Step 3.3: Create Simple SIP Client for Testing

```bash
# Create a simple SIP client for macOS testing
cat > test-data/simple_sip_client.py << 'EOF'
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
EOF

# Make simple SIP client executable
chmod +x test-data/simple_sip_client.py
```

---

## Day 4: Security Analysis Module

### Step 4.1: Create Security Analysis Engine

```bash
# Create security analysis module
cat > parser/security_analyzer.py << 'EOF'
#!/usr/bin/env python3
"""
VoIP Security Analysis Module
Detects common VoIP attacks and suspicious patterns
"""
import sqlite3
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from collections import defaultdict, Counter

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class VoIPSecurityAnalyzer:
    def __init__(self, db_path: str = "voip_metadata.db"):
        self.db_path = db_path
        self.security_rules = {
            'sip_flooding': {
                'threshold': 100,  # requests per minute
                'severity': 'HIGH',
                'description': 'Excessive SIP requests detected'
            },
            'failed_registrations': {
                'threshold': 10,   # failed attempts per minute
                'severity': 'MEDIUM',
                'description': 'Multiple failed registration attempts'
            },
            'unusual_user_agents': {
                'threshold': 5,    # different UAs from same IP
                'severity': 'LOW',
                'description': 'Unusual User-Agent diversity from single IP'
            },
            'port_scanning': {
                'threshold': 20,   # different ports contacted
                'severity': 'HIGH',
                'description': 'Potential port scanning activity'
            },
            'call_pattern_anomaly': {
                'threshold': 0.8,  # statistical threshold
                'severity': 'MEDIUM',
                'description': 'Anomalous calling patterns detected'
            }
        }
        
    def analyze_trace(self, trace_id: str = None) -> Dict:
        """Perform comprehensive security analysis on VoIP trace"""
        logger.info(f"🔍 Starting security analysis...")
        if trace_id:
            logger.info(f"📋 Analyzing trace: {trace_id}")
        
        analysis_results = {
            'analysis_id': f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'trace_id': trace_id,
            'timestamp': datetime.now().isoformat(),
            'security_events': [],
            'risk_score': 0.0,
            'summary': {
                'total_events': 0,
                'critical_events': 0,
                'high_risk_events': 0,
                'medium_risk_events': 0,
                'low_risk_events': 0
            },
            'recommendations': []
        }
        
        conn = sqlite3.connect(self.db_path)
        
        try:
            # Run security analysis checks
            self.detect_sip_flooding(conn, analysis_results, trace_id)
            self.detect_failed_registrations(conn, analysis_results, trace_id)
            self.detect_unusual_user_agents(conn, analysis_results, trace_id)
            self.detect_port_scanning(conn, analysis_results, trace_id)
            self.detect_call_pattern_anomalies(conn, analysis_results, trace_id)
            self.detect_suspicious_sdp_patterns(conn, analysis_results, trace_id)
            self.detect_rtp_anomalies(conn, analysis_results, trace_id)
            
            # Calculate overall risk score
            analysis_results['risk_score'] = self.calculate_risk_score(analysis_results['security_events'])
            
            # Generate recommendations
            analysis_results['recommendations'] = self.generate_recommendations(analysis_results)
            
            # Update summary
            self.update_analysis_summary(analysis_results)
            
            # Save to database
            self.save_security_analysis(conn, analysis_results)
            
        except Exception as e:
            logger.error(f"❌ Error during security analysis: {e}")
        finally:
            conn.close()
        
        logger.info(f"✅ Security analysis complete. Risk score: {analysis_results['risk_score']:.2f}")
        return analysis_results
    
    def detect_sip_flooding(self, conn, results: Dict, trace_id: str = None):
        """Detect SIP flooding attacks"""
        logger.info("🔍 Checking for SIP flooding...")
        
        # Query for SIP request rates by source IP
        query = '''
            SELECT src_ip, 
                   COUNT(*) as request_count,
                   MIN(timestamp) as first_request,
                   MAX(timestamp) as last_request
            FROM sip_messages 
            WHERE method IS NOT NULL
        '''
        params = []
        if trace_id:
            query += " AND trace_id = ?"
            params.append(trace_id)
            
        query += '''
            GROUP BY src_ip
            HAVING request_count > 10
            ORDER BY request_count DESC
        '''
        
        cursor = conn.cursor()
        cursor.execute(query, params)
        flooding_candidates = cursor.fetchall()
        
        for candidate in flooding_candidates:
            src_ip, request_count, first_request, last_request = candidate
            
            # Calculate request rate (requests per minute)
            first_time = datetime.fromisoformat(first_request.replace('Z', '+00:00'))
            last_time = datetime.fromisoformat(last_request.replace('Z', '+00:00'))
            duration_minutes = max(1, (last_time - first_time).total_seconds() / 60)
            request_rate = request_count / duration_minutes
            
            if request_rate > self.security_rules['sip_flooding']['threshold']:
                event = {
                    'type': 'sip_flooding',
                    'severity': self.security_rules['sip_flooding']['severity'],
                    'description': f"SIP flooding detected from {src_ip}: {request_rate:.1f} req/min",
                    'src_ip': src_ip,
                    'metadata': {
                        'request_count': request_count,
                        'request_rate': request_rate,
                        'duration_minutes': duration_minutes,
                        'first_request': first_request,
                        'last_request': last_request
                    },
                    'timestamp': datetime.now().isoformat()
                }
                results['security_events'].append(event)
                logger.warning(f"⚠️ SIP flooding detected: {src_ip} ({request_rate:.1f} req/min)")
    
    def detect_failed_registrations(self, conn, results: Dict, trace_id: str = None):
        """Detect suspicious failed registration patterns"""
        logger.info("🔍 Checking for failed registrations...")
        
        query = '''
            SELECT src_ip, 
                   COUNT(*) as failed_count,
                   GROUP_CONCAT(DISTINCT from_uri) as attempted_users
            FROM sip_messages 
            WHERE method = 'REGISTER' AND response_code >= 400
        '''
        params = []
        if trace_id:
            query += " AND trace_id = ?"
            params.append(trace_id)
            
        query += '''
            GROUP BY src_ip
            HAVING failed_count >= ?
            ORDER BY failed_count DESC
        '''
        params.append(self.security_rules['failed_registrations']['threshold'])
        
        cursor = conn.cursor()
        cursor.execute(query, params)
        failed_reg_candidates = cursor.fetchall()
        
        for candidate in failed_reg_candidates:
            src_ip, failed_count, attempted_users = candidate
            
            # Count unique usernames attempted
            unique_users = len(set(attempted_users.split(',')) if attempted_users else [])
            
            event = {
                'type': 'failed_registrations',
                'severity': self.security_rules['failed_registrations']['severity'],
                'description': f"Multiple failed registrations from {src_ip}: {failed_count} attempts",
                'src_ip': src_ip,
                'metadata': {
                    'failed_count': failed_count,
                    'unique_users_attempted': unique_users,
                    'attempted_users': attempted_users
                },
                'timestamp': datetime.now().isoformat()
            }
            results['security_events'].append(event)
            logger.warning(f"⚠️ Failed registrations detected: {src_ip} ({failed_count} failures)")
    
    def detect_unusual_user_agents(self, conn, results: Dict, trace_id: str = None):
        """Detect unusual User-Agent patterns that might indicate scanning"""
        logger.info("🔍 Checking for unusual User-Agent patterns...")
        
        query = '''
            SELECT src_ip, 
                   COUNT(DISTINCT user_agent) as ua_count,
                   GROUP_CONCAT(DISTINCT user_agent) as user_agents
            FROM sip_messages 
            WHERE user_agent IS NOT NULL AND user_agent != ''
        '''
        params = []
        if trace_id:
            query += " AND trace_id = ?"
            params.append(trace_id)
            
        query += '''
            GROUP BY src_ip
            HAVING ua_count >= ?
            ORDER BY ua_count DESC
        '''
        params.append(self.security_rules['unusual_user_agents']['threshold'])
        
        cursor = conn.cursor()
        cursor.execute(query, params)
        ua_candidates = cursor.fetchall()
        
        for candidate in ua_candidates:
            src_ip, ua_count, user_agents = candidate
            
            event = {
                'type': 'unusual_user_agents',
                'severity': self.security_rules['unusual_user_agents']['severity'],
                'description': f"Unusual User-Agent diversity from {src_ip}: {ua_count} different UAs",
                'src_ip': src_ip,
                'metadata': {
                    'ua_count': ua_count,
                    'user_agents': user_agents[:500]  # Truncate for storage
                },
                'timestamp': datetime.now().isoformat()
            }
            results['security_events'].append(event)
            logger.warning(f"⚠️ Unusual User-Agent pattern: {src_ip} ({ua_count} UAs)")
    
    def detect_port_scanning(self, conn, results: Dict, trace_id: str = None):
        """Detect potential port scanning activity"""
        logger.info("🔍 Checking for port scanning...")
        
        query = '''
            SELECT src_ip, 
                   COUNT(DISTINCT dst_port) as port_count,
                   GROUP_CONCAT(DISTINCT dst_port) as ports_contacted
            FROM sip_messages
        '''
        params = []
        if trace_id:
            query += " WHERE trace_id = ?"
            params.append(trace_id)
            
        query += '''
            GROUP BY src_ip
            HAVING port_count >= ?
            ORDER BY port_count DESC
        '''
        params.append(self.security_rules['port_scanning']['threshold'])
        
        cursor = conn.cursor()
        cursor.execute(query, params)
        port_scan_candidates = cursor.fetchall()
        
        for candidate in port_scan_candidates:
            src_ip, port_count, ports_contacted = candidate
            
            event = {
                'type': 'port_scanning',
                'severity': self.security_rules['port_scanning']['severity'],
                'description': f"Potential port scanning from {src_ip}: {port_count} ports contacted",
                'src_ip': src_ip,
                'metadata': {
                    'port_count': port_count,
                    'ports_contacted': ports_contacted
                },
                'timestamp': datetime.now().isoformat()
            }
            results['security_events'].append(event)
            logger.warning(f"⚠️ Port scanning detected: {src_ip} ({port_count} ports)")
    
    def detect_call_pattern_anomalies(self, conn, results: Dict, trace_id: str = None):
        """Detect anomalous calling patterns"""
        logger.info("🔍 Checking for call pattern anomalies...")
        
        # Get call patterns by hour of day
        query = '''
            SELECT strftime('%H', timestamp) as hour,
                   COUNT(*) as call_count,
                   GROUP_CONCAT(DISTINCT src_ip) as callers
            FROM sip_messages 
            WHERE method = 'INVITE'
        '''
        params = []
        if trace_id:
            query += " AND trace_id = ?"
            params.append(trace_id)
            
        query += '''
            GROUP BY hour
            ORDER BY hour
        '''
        
        cursor = conn.cursor()
        cursor.execute(query, params)
        hourly_patterns = cursor.fetchall()
        
        if len(hourly_patterns) >= 3:  # Need some data for analysis
            call_counts = [int(row[1]) for row in hourly_patterns]
            avg_calls = sum(call_counts) / len(call_counts)
            
            # Simple anomaly detection: calls significantly above average
            for hour, call_count, callers in hourly_patterns:
                if call_count > avg_calls * 3:  # 3x average threshold
                    unique_callers = len(set(callers.split(',')) if callers else [])
                    
                    event = {
                        'type': 'call_pattern_anomaly',
                        'severity': self.security_rules['call_pattern_anomaly']['severity'],
                        'description': f"Unusual call volume at hour {hour}: {call_count} calls",
                        'metadata': {
                            'hour': hour,
                            'call_count': call_count,
                            'average_calls': avg_calls,
                            'unique_callers': unique_callers,
                            'anomaly_ratio': call_count / avg_calls
                        },
                        'timestamp': datetime.now().isoformat()
                    }
                    results['security_events'].append(event)
                    logger.warning(f"⚠️ Call pattern anomaly: Hour {hour} has {call_count} calls vs avg {avg_calls:.1f}")
    
    def detect_suspicious_sdp_patterns(self, conn, results: Dict, trace_id: str = None):
        """Detect suspicious SDP patterns that might indicate attacks"""
        logger.info("🔍 Checking for suspicious SDP patterns...")
        
        query = '''
            SELECT src_ip, sdp_content, COUNT(*) as occurrence_count
            FROM sip_messages 
            WHERE sdp_content IS NOT NULL AND sdp_content != ''
        '''
        params = []
        if trace_id:
            query += " AND trace_id = ?"
            params.append(trace_id)
            
        query += '''
            GROUP BY src_ip, sdp_content
            ORDER BY occurrence_count DESC
        '''
        
        cursor = conn.cursor()
        cursor.execute(query, params)
        sdp_patterns = cursor.fetchall()
        
        suspicious_patterns = [
            'c=IN IP4 0.0.0.0',  # Invalid connection address
            'c=IN IP4 255.255.255.255',  # Broadcast address
            'm=audio 0 ',  # Port 0
            'a=sendonly',  # Suspicious attribute for normal calls
        ]
        
        for src_ip, sdp_content, count in sdp_patterns:
            for pattern in suspicious_patterns:
                if pattern in sdp_content:
                    event = {
                        'type': 'suspicious_sdp',
                        'severity': 'MEDIUM',
                        'description': f"Suspicious SDP pattern from {src_ip}: {pattern}",
                        'src_ip': src_ip,
                        'metadata': {
                            'suspicious_pattern': pattern,
                            'occurrence_count': count,
                            'sdp_sample': sdp_content[:200]
                        },
                        'timestamp': datetime.now().isoformat()
                    }
                    results['security_events'].append(event)
                    logger.warning(f"⚠️ Suspicious SDP pattern: {src_ip} using {pattern}")
                    break  # Only report first match per SDP
    
    def detect_rtp_anomalies(self, conn, results: Dict, trace_id: str = None):
        """Detect RTP flow anomalies"""
        logger.info("🔍 Checking for RTP anomalies...")
        
        # Check for RTP flows with unusual characteristics
        query = '''
            SELECT src_ip, dst_ip, COUNT(*) as flow_count,
                   AVG(packet_count) as avg_packets,
                   GROUP_CONCAT(DISTINCT payload_type) as payload_types
            FROM rtp_flows
        '''
        params = []
        if trace_id:
            query += " WHERE trace_id = ?"
            params.append(trace_id)
            
        query += '''
            GROUP BY src_ip, dst_ip
            HAVING flow_count > 10 OR avg_packets < 5
            ORDER BY flow_count DESC
        '''
        
        cursor = conn.cursor()
        cursor.execute(query, params)
        rtp_anomalies = cursor.fetchall()
        
        for src_ip, dst_ip, flow_count, avg_packets, payload_types in rtp_anomalies:
            if flow_count > 50:  # Too many flows between same endpoints
                event = {
                    'type': 'rtp_flow_anomaly',
                    'severity': 'MEDIUM',
                    'description': f"Excessive RTP flows: {src_ip} -> {dst_ip} ({flow_count} flows)",
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'metadata': {
                        'flow_count': flow_count,
                        'avg_packets': avg_packets,
                        'payload_types': payload_types
                    },
                    'timestamp': datetime.now().isoformat()
                }
                results['security_events'].append(event)
                logger.warning(f"⚠️ RTP flow anomaly: {flow_count} flows {src_ip} -> {dst_ip}")
            
            elif avg_packets < 5:  # Very short flows (potential scanning)
                event = {
                    'type': 'rtp_short_flows',
                    'severity': 'LOW',
                    'description': f"Short RTP flows detected: {src_ip} -> {dst_ip} (avg {avg_packets:.1f} packets)",
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'metadata': {
                        'flow_count': flow_count,
                        'avg_packets': avg_packets,
                        'payload_types': payload_types
                    },
                    'timestamp': datetime.now().isoformat()
                }
                results['security_events'].append(event)
                logger.warning(f"⚠️ Short RTP flows: {src_ip} -> {dst_ip} (avg {avg_packets:.1f} packets)")
    
    def calculate_risk_score(self, events: List[Dict]) -> float:
        """Calculate overall risk score based on security events"""
        if not events:
            return 0.0
        
        severity_weights = {
            'CRITICAL': 1.0,
            'HIGH': 0.8,
            'MEDIUM': 0.5,
            'LOW': 0.2
        }
        
        total_score = 0.0
        for event in events:
            severity = event.get('severity', 'LOW')
            weight = severity_weights.get(severity, 0.2)
            total_score += weight
        
        # Normalize to 0-10 scale, with diminishing returns for many events
        import math
        normalized_score = min(10.0, total_score * math.log(len(events) + 1) / 2)
        
        return round(normalized_score, 2)
    
    def generate_recommendations(self, results: Dict) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        events_by_type = defaultdict(int)
        
        for event in results['security_events']:
            events_by_type[event['type']] += 1
        
        if events_by_type['sip_flooding'] > 0:
            recommendations.append("Implement SIP rate limiting to prevent flooding attacks")
            recommendations.append("Consider deploying a SIP firewall or session border controller")
        
        if events_by_type['failed_registrations'] > 0:
            recommendations.append("Enable account lockout after multiple failed registration attempts")
            recommendations.append("Implement strong authentication policies and monitor for brute force attacks")
        
        if events_by_type['port_scanning'] > 0:
            recommendations.append("Deploy network intrusion detection systems (IDS)")
            recommendations.append("Use fail2ban or similar tools to automatically block scanning sources")
        
        if events_by_type['unusual_user_agents'] > 0:
            recommendations.append("Monitor and whitelist expected User-Agent strings")
            recommendations.append("Consider blocking requests with suspicious or scanner-like User-Agents")
        
        if events_by_type['rtp_flow_anomaly'] > 0:
            recommendations.append("Implement RTP flow monitoring and anomaly detection")
            recommendations.append("Consider using SRTP for encrypted media transmission")
        
        # General recommendations
        if results['risk_score'] > 7.0:
            recommendations.append("HIGH RISK: Immediate security review recommended")
            recommendations.append("Consider temporarily blocking suspicious source IPs")
        elif results['risk_score'] > 4.0:
            recommendations.append("MEDIUM RISK: Enhanced monitoring recommended")
        
        if not recommendations:
            recommendations.append("No immediate security concerns detected")
            recommendations.append("Continue regular monitoring and maintain security best practices")
        
        return recommendations
    
    def update_analysis_summary(self, results: Dict):
        """Update analysis summary with event counts"""
        severity_counts = Counter(event['severity'] for event in results['security_events'])
        
        results['summary']['total_events'] = len(results['security_events'])
        results['summary']['critical_events'] = severity_counts.get('CRITICAL', 0)
        results['summary']['high_risk_events'] = severity_counts.get('HIGH', 0)
        results['summary']['medium_risk_events'] = severity_counts.get('MEDIUM', 0)
        results['summary']['low_risk_events'] = severity_counts.get('LOW', 0)
    
    def save_security_analysis(self, conn, results: Dict):
        """Save security analysis results to database"""
        cursor = conn.cursor()
        
        try:
            for event in results['security_events']:
                cursor.execute('''
                    INSERT INTO security_events 
                    (event_type, severity, description, src_ip, dst_ip, trace_id, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event['type'],
                    event['severity'],
                    event['description'],
                    event.get('src_ip'),
                    event.get('dst_ip'),
                    results['trace_id'],
                    json.dumps(event.get('metadata', {}))
                ))
            
            conn.commit()
            logger.info(f"💾 Saved {len(results['security_events'])} security events to database")
            
        except Exception as e:
            logger.error(f"❌ Error saving security analysis: {e}")
            conn.rollback()

def main():
    """Main function for security analysis"""
    import argparse
    
    parser = argparse.ArgumentParser(description='VoIP Security Analyzer')
    parser.add_argument('--db', default='voip_metadata.db', help='Database path')
    parser.add_argument('--trace-id', help='Analyze specific trace ID')
    parser.add_argument('--output', default='security_report.json', help='Output file for report')
    parser.add_argument('--threshold', choices=['low', 'medium', 'high'], default='medium',
                       help='Detection sensitivity threshold')
    
    args = parser.parse_args()
    
    # Adjust thresholds based on sensitivity
    analyzer = VoIPSecurityAnalyzer(args.db)
    
    if args.threshold == 'low':
        # More permissive thresholds
        analyzer.security_rules['sip_flooding']['threshold'] *= 2
        analyzer.security_rules['failed_registrations']['threshold'] *= 2
    elif args.threshold == 'high':
        # More sensitive thresholds
        analyzer.security_rules['sip_flooding']['threshold'] //= 2
        analyzer.security_rules['failed_registrations']['threshold'] //= 2
    
    # Run analysis
    results = analyzer.analyze_trace(args.trace_id)
    
    # Save detailed report
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Print summary
    print(f"\n{'='*50}")
    print("🔒 VOIP SECURITY ANALYSIS REPORT")
    print(f"{'='*50}")
    print(f"📋 Analysis ID: {results['analysis_id']}")
    print(f"🎯 Risk Score: {results['risk_score']}/10.0")
    print(f"📊 Total Events: {results['summary']['total_events']}")
    print(f"   🔴 High Risk: {results['summary']['high_risk_events']}")
    print(f"   🟡 Medium Risk: {results['summary']['medium_risk_events']}")
    print(f"   🟢 Low Risk: {results['summary']['low_risk_events']}")
    
    if results['security_events']:
        print(f"\n⚠️  TOP SECURITY EVENTS:")
        for i, event in enumerate(results['security_events'][:5], 1):
            print(f"   {i}. [{event['severity']}] {event['description']}")
    
    if results['recommendations']:
        print(f"\n💡 RECOMMENDATIONS:")
        for i, rec in enumerate(results['recommendations'][:5], 1):
            print(f"   {i}. {rec}")
    
    print(f"\n📁 Detailed report saved: {args.output}")

if __name__ == "__main__":
    main()
EOF

# Make security analyzer executable
chmod +x parser/security_analyzer.py
```

---

## Day 5: Web Interface & Visualization

### Step 5.1: Create Flask Web Application

```bash
# Create web application directory structure
mkdir -p webapp/{static/{css,js},templates}

# Create main Flask application
cat > webapp/app.py << 'EOF'
#!/usr/bin/env python3
"""
VoIP Tracing MVP Web Interface
Flask-based dashboard for visualizing VoIP call traces and security analysis
"""
from flask import Flask, render_template, jsonify, request, send_file
from flask_cors import CORS
import sqlite3
import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
import logging

# Add parser directory to path
sys.path.append(str(Path(__file__).parent.parent / 'parser'))

from correlation_engine import CorrelationEngine
from security_analyzer import VoIPSecurityAnalyzer

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configuration
DB_PATH = '../voip_metadata.db'
PCAP_DIR = '../pcaps'

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/traces')
def api_traces():
    """Get list of all traces"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Get trace statistics
        cursor.execute('''
            SELECT 
                trace_id,
                COUNT(DISTINCT s.call_id) as sip_sessions,
                COUNT(DISTINCT r.ssrc) as rtp_flows,
                MIN(s.start_time) as first_seen,
                MAX(s.start_time) as last_seen
            FROM sip_sessions s
            LEFT JOIN rtp_flows r ON s.trace_id = r.trace_id
            WHERE s.trace_id IS NOT NULL
            GROUP BY trace_id
            ORDER BY first_seen DESC
        ''')
        
        traces = []
        for row in cursor.fetchall():
            trace_id, sip_sessions, rtp_flows, first_seen, last_seen = row
            traces.append({
                'trace_id': trace_id,
                'sip_sessions': sip_sessions or 0,
                'rtp_flows': rtp_flows or 0,
                'first_seen': first_seen,
                'last_seen': last_seen,
                'duration': str(datetime.fromisoformat(last_seen.replace('Z', '+00:00')) - 
                               datetime.fromisoformat(first_seen.replace('Z', '+00:00'))) if first_seen and last_seen else 'Unknown'
            })
        
        conn.close()
        return jsonify({'traces': traces})
        
    except Exception as e:
        logger.error(f"Error fetching traces: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/trace/<trace_id>')
def api_trace_details(trace_id):
    """Get detailed information about a specific trace"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Get SIP sessions
        cursor.execute('''
            SELECT call_id, from_uri, to_uri, start_time, end_time, status
            FROM sip_sessions 
            WHERE trace_id = ?
            ORDER BY start_time
        ''', (trace_id,))
        
        sessions = []
        for row in cursor.fetchall():
            call_id, from_uri, to_uri, start_time, end_time, status = row
            sessions.append({
                'call_id': call_id,
                'from_uri': from_uri,
                'to_uri': to_uri,
                'start_time': start_time,
                'end_time': end_time,
                'status': status
            })
        
        # Get RTP flows
        cursor.execute('''
            SELECT ssrc, src_ip, src_port, dst_ip, dst_port, packet_count, payload_type
            FROM rtp_flows 
            WHERE trace_id = ?
            ORDER BY packet_count DESC
        ''', (trace_id,))
        
        flows = []
        for row in cursor.fetchall():
            ssrc, src_ip, src_port, dst_ip, dst_port, packet_count, payload_type = row
            flows.append({
                'ssrc': ssrc,
                'src_endpoint': f"{src_ip}:{src_port}",
                'dst_endpoint': f"{dst_ip}:{dst_port}",
                'packet_count': packet_count,
                'payload_type': payload_type
            })
        
        # Get correlations
        cursor.execute('''
            SELECT c.call_id, c.ssrc, c.correlation_confidence, c.correlation_method,
                   s.from_uri, s.to_uri
            FROM correlations c
            JOIN sip_sessions s ON c.call_id = s.call_id
            WHERE c.trace_id = ?
            ORDER BY c.correlation_confidence DESC
        ''', (trace_id,))
        
        correlations = []
        for row in cursor.fetchall():
            call_id, ssrc, confidence, method, from_uri, to_uri = row
            correlations.append({
                'call_id': call_id,
                'ssrc': ssrc,
                'confidence': confidence,
                'method': method,
                'from_uri': from_uri,
                'to_uri': to_uri
            })
        
        conn.close()
        
        return jsonify({
            'trace_id': trace_id,
            'sessions': sessions,
            'flows': flows,
            'correlations': correlations
        })
        
    except Exception as e:
        logger.error(f"Error fetching trace details: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/security/<trace_id>')
def api_security_analysis(trace_id):
    """Get security analysis for a trace"""
    try:
        analyzer = VoIPSecurityAnalyzer(DB_PATH)
        results = analyzer.analyze_trace(trace_id)
        return jsonify(results)
        
    except Exception as e:
        logger.error(f"Error running security analysis: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/correlation/<trace_id>')
def api_run_correlation(trace_id):
    """Run correlation analysis for a trace"""
    try:
        engine = CorrelationEngine(DB_PATH)
        correlations = engine.correlate_sessions_to_flows(trace_id)
        report = engine.generate_call_flow_report(trace_id)
        
        return jsonify({
            'correlations': correlations,
            'report': report
        })
        
    except Exception as e:
        logger.error(f"Error running correlation: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/network-graph/<trace_id>')
def api_network_graph(trace_id):
    """Generate network graph data for visualization"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Get all IPs involved in the trace
        cursor.execute('''
            SELECT DISTINCT src_ip, dst_ip, 'sip' as protocol, COUNT(*) as count
            FROM sip_messages 
            WHERE trace_id = ?
            GROUP BY src_ip, dst_ip
            UNION ALL
            SELECT DISTINCT src_ip, dst_ip, 'rtp' as protocol, COUNT(*) as count
            FROM rtp_flows 
            WHERE trace_id = ?
            GROUP BY src_ip, dst_ip
        ''', (trace_id, trace_id))
        
        connections = cursor.fetchall()
        
        # Build nodes and edges
        nodes = {}
        edges = []
        
        for src_ip, dst_ip, protocol, count in connections:
            # Add nodes
            if src_ip not in nodes:
                nodes[src_ip] = {
                    'id': src_ip,
                    'label': src_ip,
                    'type': 'ip_address',
                    'protocols': set()
                }
            if dst_ip not in nodes:
                nodes[dst_ip] = {
                    'id': dst_ip,
                    'label': dst_ip,
                    'type': 'ip_address',
                    'protocols': set()
                }
            
            # Track protocols
            nodes[src_ip]['protocols'].add(protocol)
            nodes[dst_ip]['protocols'].add(protocol)
            
            # Add edge
            edges.append({
                'source': src_ip,
                'target': dst_ip,
                'protocol': protocol,
                'count': count,
                'label': f"{protocol.upper()}: {count}"
            })
        
        # Convert sets to lists for JSON serialization
        for node in nodes.values():
            node['protocols'] = list(node['protocols'])
        
        conn.close()
        
        return jsonify({
            'nodes': list(nodes.values()),
            'edges': edges
        })
        
    except Exception as e:
        logger.error(f"Error generating network graph: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats')
def api_stats():
    """Get overall statistics"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Get general statistics
        cursor.execute('SELECT COUNT(DISTINCT trace_id) FROM sip_sessions WHERE trace_id IS NOT NULL')
        total_traces = cursor.fetchone()[0] or 0
        
        cursor.execute('SELECT COUNT(*) FROM sip_sessions')
        total_sessions = cursor.fetchone()[0] or 0
        
        cursor.execute('SELECT COUNT(*) FROM rtp_flows')
        total_flows = cursor.fetchone()[0] or 0
        
        cursor.execute('SELECT COUNT(*) FROM correlations')
        total_correlations = cursor.fetchone()[0] or 0
        
        cursor.execute('SELECT COUNT(*) FROM security_events')
        total_security_events = cursor.fetchone()[0] or 0
        
        # Get recent activity
        cursor.execute('''
            SELECT trace_id, COUNT(*) as session_count, MAX(start_time) as latest_activity
            FROM sip_sessions 
            WHERE start_time > datetime('now', '-24 hours')
            GROUP BY trace_id
            ORDER BY latest_activity DESC
            LIMIT 5
        ''')
        recent_activity = cursor.fetchall()
        
        conn.close()
        
        return jsonify({
            'total_traces': total_traces,
            'total_sessions': total_sessions,
            'total_flows': total_flows,
            'total_correlations': total_correlations,
            'total_security_events': total_security_events,
            'recent_activity': [
                {
                    'trace_id': row[0],
                    'session_count': row[1],
                    'latest_activity': row[2]
                }
                for row in recent_activity
            ]
        })
        
    except Exception as e:
        logger.error(f"Error fetching stats: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Check if database exists
    if not os.path.exists(DB_PATH):
        logger.warning(f"Database not found at {DB_PATH}. Please ensure you've run the parser first.")
    
    logger.info("🚀 Starting VoIP Tracing MVP Web Interface")
    logger.info(f"📊 Dashboard will be available at: http://localhost:5000")
    logger.info(f"🗄️ Using database: {DB_PATH}")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
EOF

# Create main dashboard template
cat > webapp/templates/dashboard.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VoIP Tracing MVP - Dashboard</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="{{ url_for('static', filename='css/dashboard.css') }}" rel="stylesheet">
</head>
<body class="bg-dark text-light">
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container-fluid">
            <a class="navbar-brand" href="#">
                <i class="fas fa-phone-alt me-2"></i>
                VoIP Tracing MVP
            </a>
            <div class="navbar-nav ms-auto">
                <span class="nav-link" id="last-updated">Last Updated: <span id="update-time">--</span></span>
            </div>
        </div>
    </nav>

    <div class="container-fluid py-4">
        <!-- Statistics Cards -->
        <div class="row mb-4">
            <div class="col-md-2">
                <div class="card bg-secondary">
                    <div class="card-body text-center">
                        <i class="fas fa-list-alt fa-2x mb-2 text-primary"></i>
                        <h3 id="total-traces" class="mb-1">0</h3>
                        <p class="text-muted mb-0">Total Traces</p>
                    </div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="card bg-secondary">
                    <div class="card-body text-center">
                        <i class="fas fa-phone fa-2x mb-2 text-success"></i>
                        <h3 id="total-sessions" class="mb-1">0</h3>
                        <p class="text-muted mb-0">SIP Sessions</p>
                    </div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="card bg-secondary">
                    <div class="card-body text-center">
                        <i class="fas fa-stream fa-2x mb-2 text-info"></i>
                        <h3 id="total-flows" class="mb-1">0</h3>
                        <p class="text-muted mb-0">RTP Flows</p>
                    </div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="card bg-secondary">
                    <div class="card-body text-center">
                        <i class="fas fa-link fa-2x mb-2 text-warning"></i>
                        <h3 id="total-correlations" class="mb-1">0</h3>
                        <p class="text-muted mb-0">Correlations</p>
                    </div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="card bg-secondary">
                    <div class="card-body text-center">
                        <i class="fas fa-shield-alt fa-2x mb-2 text-danger"></i>
                        <h3 id="total-security-events" class="mb-1">0</h3>
                        <p class="text-muted mb-0">Security Events</p>
                    </div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="card bg-secondary">
                    <div class="card-body text-center">
                        <button class="btn btn-primary btn-sm" onclick="refreshDashboard()">
                            <i class="fas fa-sync-alt"></i> Refresh
                        </button>
                        <p class="text-muted mb-0 mt-2">Update Data</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Main Content Tabs -->
        <ul class="nav nav-tabs mb-4" id="mainTabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="traces-tab" data-bs-toggle="tab" data-bs-target="#traces" type="button" role="tab">
                    <i class="fas fa-list me-1"></i> Traces
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="analysis-tab" data-bs-toggle="tab" data-bs-target="#analysis" type="button" role="tab">
                    <i class="fas fa-chart-line me-1"></i> Analysis
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="security-tab" data-bs-toggle="tab" data-bs-target="#security" type="button" role="tab">
                    <i class="fas fa-shield-alt me-1"></i> Security
                </button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="network-tab" data-bs-toggle="tab" data-bs-target="#network" type="button" role="tab">
                    <i class="fas fa-project-diagram me-1"></i> Network View
                </button>
            </li>
        </ul>

        <div class="tab-content" id="mainTabContent">
            <!-- Traces Tab -->
            <div class="tab-pane fade show active" id="traces" role="tabpanel">
                <div class="card bg-secondary">
                    <div class="card-header">
                        <h5 class="mb-0"><i class="fas fa-list me-2"></i>VoIP Traces</h5>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-dark table-striped">
                                <thead>
                                    <tr>
                                        <th>Trace ID</th>
                                        <th>SIP Sessions</th>
                                        <th>RTP Flows</th>
                                        <th>First Seen</th>
                                        <th>Duration</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody id="traces-table">
                                    <tr>
                                        <td colspan="6" class="text-center">Loading...</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            