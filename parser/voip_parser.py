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
                    print(f"🔍 Processing packet {packet_count}: {pkt.highest_layer}")
                    
                    # Parse SIP packets
                    if hasattr(pkt, 'sip'):
                        print(f"📞 Found SIP packet {sip_count + 1}")
                        self.parse_sip_packet(pkt, timestamp, trace_id)
                        sip_count += 1
                    
                    # Parse RTP packets
                    elif hasattr(pkt, 'rtp'):
                        print(f"🎵 Found RTP packet {rtp_count + 1}")
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
        print(f"🔍 Starting to parse SIP packet...")
        try:
            sip = pkt.sip
            print(f"✅ Got SIP layer: {type(sip)}")
            
            # Get basic packet info
            print(f"🔍 Getting IP addresses...")
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            print(f"✅ IP addresses: {src_ip} -> {dst_ip}")
            
            # Handle different transport layers
            print(f"🔍 Getting transport layer info...")
            if hasattr(pkt, 'udp'):
                src_port = int(pkt.udp.srcport)
                dst_port = int(pkt.udp.dstport)
                print(f"✅ UDP ports: {src_port} -> {dst_port}")
            elif hasattr(pkt, 'tcp'):
                src_port = int(pkt.tcp.srcport)
                dst_port = int(pkt.tcp.tcp.dstport)
                print(f"✅ TCP ports: {src_port} -> {dst_port}")
            else:
                src_port = dst_port = 0
                print(f"⚠️ No transport layer found")
            
            # Extract SIP headers (handle different pyshark versions)
            print(f"🔍 Starting Call-ID extraction...")
            print(f"🔍 Available field names: {sip.field_names}")
            call_id = None
            
            # For JsonLayer, try to get Call-ID from nested structure
            try:
                print(f"🔍 Trying to access msg_hdr field...")
                if hasattr(sip, 'msg_hdr'):
                    msg_hdr = sip.msg_hdr
                    print(f"✅ Got msg_hdr: {type(msg_hdr)}")
                    
                    # Try to get Call-ID from msg_hdr using all_fields
                    print(f"🔍 Checking all_fields in msg_hdr...")
                    if hasattr(msg_hdr, 'all_fields'):
                        all_fields = msg_hdr.all_fields
                        print(f"✅ all_fields: {all_fields}")
                        
                        # Look for Call-ID in all_fields text content
                        print(f"🔍 Processing {len(all_fields)} fields...")
                        for i, field in enumerate(all_fields):
                            print(f"🔍 Processing field {i}: {type(field)}")
                            print(f"🔍 Field {i} attributes: {dir(field)}")
                            
                            # Try different ways to access the field content
                            field_text = str(field)
                            print(f"🔍 Field {i} string representation: {field_text[:100]}...")
                            
                            # Look for Call-ID in the text content
                            if 'Call-ID:' in field_text:
                                print(f"✅ Found 'Call-ID:' in field {i}")
                                # Extract Call-ID using regex or string parsing
                                import re
                                call_id_match = re.search(r'Call-ID:\s*([^\r\n]+)', field_text)
                                if call_id_match:
                                    call_id = call_id_match.group(1).strip()
                                    print(f"✅ Found Call-ID in field text: {call_id}")
                                    break
                                else:
                                    print(f"❌ Regex didn't match Call-ID in: {field_text}")
                            else:
                                print(f"❌ No Call-ID found in field {i}")
                        
                        print(f"🔍 After loop, call_id = {call_id}")
                    else:
                        print(f"❌ No all_fields method in msg_hdr")
                        
                    # Also try direct access to common field names
                    if not call_id:
                        for field_name in ['Call-ID', 'call_id', 'call_id_generated']:
                            try:
                                if hasattr(msg_hdr, field_name):
                                    call_id = getattr(msg_hdr, field_name)
                                    print(f"✅ Found Call-ID using {field_name}: {call_id}")
                                    break
                            except:
                                continue
                else:
                    print(f"❌ No msg_hdr field found")
            except Exception as e:
                print(f"❌ Exception accessing msg_hdr: {e}")
            
            # Fallback: try direct attribute access
            if not call_id:
                print(f"🔍 Trying direct attribute access...")
                for attr in ['call_id', 'Call-ID', 'Call_ID']:
                    if hasattr(sip, attr):
                        call_id = getattr(sip, attr)
                        print(f"✅ Found Call-ID using attribute '{attr}': {call_id}")
                        break
                    else:
                        print(f"❌ Attribute '{attr}' not found")
                    
            # Extract method
            try:
                method = sip.get_field('Method') or getattr(sip, 'method', getattr(sip, 'Method', None))
                print(f"🔍 Extracted method: {method}")
            except Exception as e:
                print(f"❌ Error extracting method: {e}")
                method = None
            
            # Extract response code
            response_code = None
            try:
                status_code = sip.get_field('Status-Code') or sip.get_field('status_code')
                if status_code:
                    response_code = int(status_code)
                print(f"🔍 Extracted response_code: {response_code}")
            except Exception as e:
                print(f"❌ Error extracting response_code: {e}")
                    
            # Extract URIs and User-Agent
            try:
                from_uri = sip.get_field('From') or getattr(sip, 'from', getattr(sip, 'From', None))
                to_uri = sip.get_field('To') or getattr(sip, 'to', getattr(sip, 'To', None))
                user_agent = sip.get_field('User-Agent') or getattr(sip, 'user_agent', getattr(sip, 'User-Agent', None))
                print(f"🔍 Extracted from_uri: {from_uri}")
                print(f"🔍 Extracted to_uri: {to_uri}")
                print(f"🔍 Extracted user_agent: {user_agent}")
            except Exception as e:
                print(f"❌ Error extracting URIs: {e}")
                from_uri = to_uri = user_agent = None
            
            # Extract SDP if present
            sdp_content = None
            if hasattr(pkt, 'sdp'):
                try:
                    sdp_content = str(pkt.sdp)
                except:
                    pass
                    
            if call_id:
                print(f"✅ Found Call-ID: {call_id}, Method: {method}")
                print(f"🔍 Current sessions count: {len(self.sip_sessions)}")
                
                if call_id not in self.sip_sessions:
                    self.sip_sessions[call_id] = SIPSession(call_id)
                    print(f"✅ Created new SIP session for Call-ID: {call_id}")
                    print(f"🔍 Sessions after creation: {len(self.sip_sessions)}")
                else:
                    print(f"✅ Using existing session for Call-ID: {call_id}")
                
                try:
                    self.sip_sessions[call_id].add_message(
                        timestamp, method, response_code, from_uri, to_uri,
                        user_agent, sdp_content, src_ip, src_port, dst_ip, dst_port
                    )
                    print(f"✅ Added message to session {call_id}")
                except Exception as e:
                    print(f"❌ Error adding message to session: {e}")
            else:
                print(f"❌ No Call-ID found in SIP packet")
                print(f"🔍 Available fields: {[f for f in dir(sip) if 'call' in f.lower() or 'id' in f.lower()]}")
                
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
