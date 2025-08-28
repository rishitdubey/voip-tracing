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
