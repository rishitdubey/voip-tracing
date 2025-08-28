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
