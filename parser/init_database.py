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
