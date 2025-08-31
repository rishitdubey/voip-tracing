#!/usr/bin/env python3
"""
Enhanced VoIP Parser for LLM Training
Stores call data in structured JSON format with rich metadata
"""
import pyshark
import sqlite3
import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import hashlib

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class SIPMessage:
    """Structured SIP message data"""
    timestamp: str
    method: str
    call_id: str
    from_uri: str
    to_uri: str
    user_agent: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    transport: str
    message_size: int
    headers: Dict[str, str]
    raw_message: str
    message_hash: str

@dataclass
class SIPSession:
    """Structured SIP session data"""
    session_id: str
    call_id: str
    start_time: str
    end_time: str
    duration_seconds: float
    message_count: int
    methods: List[str]
    participants: List[str]
    status: str
    media_type: str
    sdp_present: bool
    security_flags: List[str]
    quality_metrics: Dict[str, Any]
    messages: List[SIPMessage]

@dataclass
class CallMetadata:
    """Call metadata for LLM training"""
    trace_id: str
    capture_timestamp: str
    network_environment: str
    protocol_version: str
    encryption_status: str
    call_complexity: str
    threat_indicators: List[str]
    call_pattern: str
    geographic_info: Dict[str, str]
    device_info: Dict[str, str]

class EnhancedVoIPParser:
    """Enhanced parser with structured data storage for LLM training"""
    
    def __init__(self, db_path: str = "voip_metadata.db", output_dir: str = "structured_data"):
        self.db_path = db_path
        self.output_dir = output_dir
        self.sip_sessions: Dict[str, SIPSession] = {}
        self.sip_messages: List[SIPMessage] = []
        self.call_metadata: Dict[str, CallMetadata] = {}
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(f"{self.output_dir}/sessions", exist_ok=True)
        os.makedirs(f"{self.output_dir}/messages", exist_ok=True)
        os.makedirs(f"{self.output_dir}/metadata", exist_ok=True)
        
        # Initialize database
        self.init_database()
    
    def init_database(self):
        """Initialize enhanced database schema"""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        
        # Enhanced SIP sessions table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS enhanced_sip_sessions (
                session_id TEXT PRIMARY KEY,
                call_id TEXT UNIQUE,
                start_time TEXT,
                end_time TEXT,
                duration_seconds REAL,
                message_count INTEGER,
                methods TEXT,
                participants TEXT,
                status TEXT,
                media_type TEXT,
                sdp_present BOOLEAN,
                security_flags TEXT,
                quality_metrics TEXT,
                trace_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Enhanced SIP messages table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS enhanced_sip_messages (
                message_id TEXT PRIMARY KEY,
                session_id TEXT,
                timestamp TEXT,
                method TEXT,
                call_id TEXT,
                from_uri TEXT,
                to_uri TEXT,
                user_agent TEXT,
                src_ip TEXT,
                src_port INTEGER,
                dst_ip TEXT,
                dst_port INTEGER,
                transport TEXT,
                message_size INTEGER,
                headers TEXT,
                raw_message TEXT,
                message_hash TEXT,
                trace_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES enhanced_sip_sessions (session_id)
            )
        """)
        
        # Call metadata table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS call_metadata (
                trace_id TEXT PRIMARY KEY,
                capture_timestamp TEXT,
                network_environment TEXT,
                protocol_version TEXT,
                encryption_status TEXT,
                call_complexity TEXT,
                threat_indicators TEXT,
                call_pattern TEXT,
                geographic_info TEXT,
                device_info TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create indexes for performance
        cur.execute("CREATE INDEX IF NOT EXISTS idx_call_id ON enhanced_sip_sessions(call_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_session_id ON enhanced_sip_messages(session_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON enhanced_sip_messages(timestamp)")
        
        conn.commit()
        conn.close()
        logger.info("✅ Enhanced database initialized")
    
    def parse_pcap(self, pcap_file: str, trace_id: str):
        """Parse PCAP file and extract structured data"""
        logger.info(f"🔍 Parsing PCAP: {pcap_file}")
        logger.info(f"📋 Trace ID: {trace_id}")
        
        try:
            cap = pyshark.FileCapture(pcap_file, display_filter='sip')
            
            packet_count = 0
            sip_count = 0
            
            for pkt in cap:
                packet_count += 1
                if packet_count % 1000 == 0:
                    logger.info(f"📦 Processed {packet_count} packets...")
                
                try:
                    timestamp = pkt.sniff_time.isoformat()
                    
                    if hasattr(pkt, 'sip'):
                        self.parse_sip_packet(pkt, timestamp, trace_id)
                        sip_count += 1
                        
                except Exception as e:
                    logger.debug(f"Error processing packet: {e}")
                    continue
            
            cap.close()
            
            logger.info(f"✅ Parsing complete:")
            logger.info(f"   📦 Total packets: {packet_count}")
            logger.info(f"   📞 SIP packets: {sip_count}")
            logger.info(f"   �� SIP sessions: {len(self.sip_sessions)}")
            
        except Exception as e:
            logger.error(f"❌ Error parsing PCAP: {e}")
            return
        
        # Generate call metadata
        self.generate_call_metadata(trace_id)
        
        # Save structured data
        self.save_structured_data(trace_id)
        
        # Save to database
        self.save_to_database(trace_id)
    
    def parse_sip_packet(self, pkt, timestamp: str, trace_id: str):
        """Extract structured SIP message data"""
        try:
            sip = pkt.sip
            
            # Get basic packet info
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            
            if hasattr(pkt, 'udp'):
                src_port = int(pkt.udp.srcport)
                dst_port = int(pkt.udp.dstport)
                transport = "UDP"
            elif hasattr(pkt, 'tcp'):
                src_port = int(pkt.tcp.srcport)
                dst_port = int(pkt.tcp.dstport)
                transport = "TCP"
            else:
                src_port = dst_port = 0
                transport = "Unknown"
            
            # Extract Call-ID using enhanced method
            call_id = self.extract_call_id(sip)
            if not call_id:
                return
            
            # Extract method and other fields
            method = self.extract_field_safe(sip, 'Method') or "UNKNOWN"
            from_uri = self.extract_field_safe(sip, 'From') or "unknown@unknown"
            to_uri = self.extract_field_safe(sip, 'To') or "unknown@unknown"
            user_agent = self.extract_field_safe(sip, 'User-Agent') or "Unknown"
            
            # Extract all headers
            headers = self.extract_all_headers(sip)
            
            # Get raw message
            raw_message = self.get_raw_message(pkt)
            message_size = len(raw_message) if raw_message else 0
            
            # Generate message hash
            message_hash = hashlib.sha256(raw_message.encode() if raw_message else b"").hexdigest()
            
            # Create SIP message
            sip_message = SIPMessage(
                timestamp=timestamp,
                method=method,
                call_id=call_id,
                from_uri=from_uri,
                to_uri=to_uri,
                user_agent=user_agent,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                transport=transport,
                message_size=message_size,
                headers=headers,
                raw_message=raw_message,
                message_hash=message_hash
            )
            
            self.sip_messages.append(sip_message)
            
            # Update or create session
            self.update_session(call_id, sip_message)
            
        except Exception as e:
            logger.debug(f"Error parsing SIP packet: {e}")
    
    def extract_call_id(self, sip) -> Optional[str]:
        """Enhanced Call-ID extraction"""
        try:
            if hasattr(sip, 'msg_hdr'):
                msg_hdr = sip.msg_hdr
                if hasattr(msg_hdr, 'all_fields'):
                    for field in msg_hdr.all_fields:
                        if hasattr(field, 'value') and field.value:
                            field_text = str(field.value)
                            if 'Call-ID:' in field_text:
                                import re
                                call_id_match = re.search(r'Call-ID:\s*([^\r\n]+)', field_text)
                                if call_id_match:
                                    return call_id_match.group(1).strip()
        except Exception as e:
            logger.debug(f"Error in enhanced Call-ID extraction: {e}")
        
        return None
    
    def extract_field_safe(self, sip, field_name: str) -> Optional[str]:
        """Safely extract field values"""
        try:
            return sip.get_field(field_name)
        except:
            try:
                return getattr(sip, field_name.lower(), None)
            except:
                return None
    
    def extract_all_headers(self, sip) -> Dict[str, str]:
        """Extract all available SIP headers"""
        headers = {}
        try:
            if hasattr(sip, 'msg_hdr') and hasattr(sip.msg_hdr, 'all_fields'):
                for field in sip.msg_hdr.all_fields:
                    if hasattr(field, 'value') and field.value:
                        field_text = str(field.value)
                        # Parse headers from text
                        lines = field_text.split('\n')
                        for line in lines:
                            if ':' in line and not line.startswith(' '):
                                parts = line.split(':', 1)
                                if len(parts) == 2:
                                    key = parts[0].strip()
                                    value = parts[1].strip()
                                    headers[key] = value
        except Exception as e:
            logger.debug(f"Error extracting headers: {e}")
        
        return headers
    
    def get_raw_message(self, pkt) -> Optional[str]:
        """Get raw SIP message content"""
        try:
            if hasattr(pkt, 'sip'):
                return str(pkt.sip)
        except:
            pass
        return None
    
    def update_session(self, call_id: str, message: SIPMessage):
        """Update or create SIP session"""
        if call_id not in self.sip_sessions:
            # Create new session
            session = SIPSession(
                session_id=f"session_{call_id[:8]}",
                call_id=call_id,
                start_time=message.timestamp,
                end_time=message.timestamp,
                duration_seconds=0.0,
                message_count=1,
                methods=[message.method],
                participants=[message.from_uri, message.to_uri],
                status="active",
                media_type="unknown",
                sdp_present="sdp" in message.headers.get("Content-Type", "").lower(),
                security_flags=[],
                quality_metrics={},
                messages=[message]
            )
            self.sip_sessions[call_id] = session
        else:
            # Update existing session
            session = self.sip_sessions[call_id]
            session.message_count += 1
            session.end_time = message.timestamp
            session.methods.append(message.method)
            
            # Add new participants
            if message.from_uri not in session.participants:
                session.participants.append(message.from_uri)
            if message.to_uri not in session.participants:
                session.participants.append(message.to_uri)
            
            # Update duration
            start_time = datetime.fromisoformat(session.start_time.replace('Z', '+00:00'))
            end_time = datetime.fromisoformat(session.end_time.replace('Z', '+00:00'))
            session.duration_seconds = (end_time - start_time).total_seconds()
            
            # Add message to session
            session.messages.append(message)
    
    def generate_call_metadata(self, trace_id: str):
        """Generate comprehensive call metadata for LLM training"""
        metadata = CallMetadata(
            trace_id=trace_id,
            capture_timestamp=datetime.now().isoformat(),
            network_environment="local_test",
            protocol_version="SIP/2.0",
            encryption_status="none",
            call_complexity=self.assess_call_complexity(),
            threat_indicators=self.analyze_threat_indicators(),
            call_pattern=self.analyze_call_patterns(),
            geographic_info={"source": "localhost", "destination": "localhost"},
            device_info={"user_agents": list(set([msg.user_agent for msg in self.sip_messages]))}
        )
        
        self.call_metadata[trace_id] = metadata
    
    def assess_call_complexity(self) -> str:
        """Assess the complexity of calls for training data"""
        if not self.sip_sessions:
            return "none"
        
        total_messages = sum(session.message_count for session in self.sip_sessions.values())
        avg_messages = total_messages / len(self.sip_sessions)
        
        if avg_messages > 10:
            return "high"
        elif avg_messages > 5:
            return "medium"
        else:
            return "low"
    
    def analyze_threat_indicators(self) -> List[str]:
        """Analyze potential security threats"""
        threats = []
        
        for message in self.sip_messages:
            # Check for suspicious patterns
            if message.method == "INVITE" and "anonymous" in message.from_uri.lower():
                threats.append("anonymous_caller")
            if message.user_agent.lower() == "unknown":
                threats.append("unknown_user_agent")
            if message.message_size > 10000:  # Very large messages
                threats.append("oversized_message")
        
        return threats
    
    def analyze_call_patterns(self) -> str:
        """Analyze call patterns for training"""
        if not self.sip_sessions:
            return "none"
        
        methods = [msg.method for msg in self.sip_messages]
        unique_methods = set(methods)
        
        if len(unique_methods) > 3:
            return "complex"
        elif len(unique_methods) > 1:
            return "standard"
        else:
            return "simple"
    
    def save_structured_data(self, trace_id: str):
        """Save data in structured JSON format for LLM training"""
        logger.info(f"💾 Saving structured data for trace: {trace_id}")
        
        # Save sessions
        sessions_file = f"{self.output_dir}/sessions/{trace_id}_sessions.json"
        sessions_data = [asdict(session) for session in self.sip_sessions.values()]
        with open(sessions_file, 'w') as f:
            json.dump(sessions_data, f, indent=2, default=str)
        
        # Save messages
        messages_file = f"{self.output_dir}/messages/{trace_id}_messages.json"
        messages_data = [asdict(message) for message in self.sip_messages]
        with open(messages_file, 'w') as f:
            json.dump(messages_data, f, indent=2, default=str)
        
        # Save metadata
        metadata_file = f"{self.output_dir}/metadata/{trace_id}_metadata.json"
        metadata_data = asdict(self.call_metadata[trace_id])
        with open(metadata_file, 'w') as f:
            json.dump(metadata_data, f, indent=2, default=str)
        
        # Create training dataset
        training_file = f"{self.output_dir}/{trace_id}_training_dataset.json"
        training_data = {
            "trace_id": trace_id,
            "summary": {
                "total_sessions": len(self.sip_sessions),
                "total_messages": len(self.sip_messages),
                "call_complexity": self.assess_call_complexity(),
                "threat_level": len(self.analyze_threat_indicators()),
                "protocol_version": "SIP/2.0"
            },
            "sessions": sessions_data,
            "messages": messages_data,
            "metadata": metadata_data,
            "training_features": {
                "call_patterns": self.analyze_call_patterns(),
                "security_indicators": self.analyze_threat_indicators(),
                "network_characteristics": {
                    "transport_protocols": list(set([msg.transport for msg in self.sip_messages])),
                    "ip_ranges": list(set([msg.src_ip for msg in self.sip_messages] + [msg.dst_ip for msg in self.sip_messages])),
                    "port_ranges": list(set([msg.src_port for msg in self.sip_messages] + [msg.dst_port for msg in self.sip_messages]))
                }
            }
        }
        
        with open(training_file, 'w') as f:
            json.dump(training_data, f, indent=2, default=str)
        
        logger.info(f"✅ Structured data saved:")
        logger.info(f"   📁 Sessions: {sessions_file}")
        logger.info(f"   📁 Messages: {messages_file}")
        logger.info(f"   📁 Metadata: {metadata_file}")
        logger.info(f"   📁 Training Dataset: {training_file}")
    
    def save_to_database(self, trace_id: str):
        """Save enhanced data to SQLite database"""
        logger.info(f"�� Saving to enhanced database...")
        
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        
        try:
            # Save sessions
            for session in self.sip_sessions.values():
                cur.execute("""
                    INSERT OR REPLACE INTO enhanced_sip_sessions 
                    (session_id, call_id, start_time, end_time, duration_seconds, 
                     message_count, methods, participants, status, media_type, 
                     sdp_present, security_flags, quality_metrics, trace_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    session.session_id, session.call_id, session.start_time, 
                    session.end_time, session.duration_seconds, session.message_count,
                    json.dumps(session.methods), json.dumps(session.participants),
                    session.status, session.media_type, session.sdp_present,
                    json.dumps(session.security_flags), json.dumps(session.quality_metrics),
                    trace_id
                ))
            
            # Save messages
            for message in self.sip_messages:
                session_id = next((s.session_id for s in self.sip_sessions.values() 
                                 if s.call_id == message.call_id), None)
                
                cur.execute("""
                    INSERT OR REPLACE INTO enhanced_sip_messages 
                    (message_id, session_id, timestamp, method, call_id, from_uri, 
                     to_uri, user_agent, src_ip, src_port, dst_ip, dst_port, 
                     transport, message_size, headers, raw_message, message_hash, trace_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    f"msg_{message.message_hash[:8]}", session_id, message.timestamp,
                    message.method, message.call_id, message.from_uri, message.to_uri,
                    message.user_agent, message.src_ip, message.src_port, message.dst_ip,
                    message.dst_port, message.transport, message.message_size,
                    json.dumps(message.headers), message.raw_message, message.message_hash,
                    trace_id
                ))
            
            # Save metadata
            metadata = self.call_metadata[trace_id]
            cur.execute("""
                INSERT OR REPLACE INTO call_metadata 
                (trace_id, capture_timestamp, network_environment, protocol_version,
                 encryption_status, call_complexity, threat_indicators, call_pattern,
                 geographic_info, device_info)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                metadata.trace_id, metadata.capture_timestamp, metadata.network_environment,
                metadata.protocol_version, metadata.encryption_status, metadata.call_complexity,
                json.dumps(metadata.threat_indicators), metadata.call_pattern,
                json.dumps(metadata.geographic_info), json.dumps(metadata.device_info)
            ))
            
            conn.commit()
            logger.info(f"✅ Enhanced database updated successfully")
            
        except Exception as e:
            logger.error(f"❌ Error saving to database: {e}")
            conn.rollback()
        finally:
            conn.close()

def main():
    """Main function for testing"""
    parser = EnhancedVoIPParser()
    
    # Test with existing PCAP
    pcap_file = "../pcaps/invite_test.pcap"
    if os.path.exists(pcap_file):
        parser.parse_pcap(pcap_file, "enhanced_test")
    else:
        logger.error(f"PCAP file not found: {pcap_file}")

if __name__ == "__main__":
    main()