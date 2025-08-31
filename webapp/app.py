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
    
    app.run(debug=True, host='0.0.0.0', port=3000)
