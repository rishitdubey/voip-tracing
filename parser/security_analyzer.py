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
