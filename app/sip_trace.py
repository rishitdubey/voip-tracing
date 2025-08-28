import pyshark
from scapy.all import *
from elasticsearch import Elasticsearch

class SIPTracer:
    def __init__(self, elasticsearch_host='localhost'):
        self.es = Elasticsearch([elasticsearch_host])
        
    def capture_live(self, interface='any', display_filter='sip'):
        """
        Capture live SIP traffic
        """
        capture = pyshark.LiveCapture(
            interface=interface,
            display_filter=display_filter
        )
        
        for packet in capture.sniff_continuously():
            if 'SIP' in packet:
                self.process_sip_packet(packet)

    def process_sip_packet(self, packet):
        """
        Process and store SIP packet information
        """
        sip_data = {
            'timestamp': packet.sniff_time.isoformat(),
            'source_ip': packet.ip.src,
            'dest_ip': packet.ip.dst,
            'method': packet.sip.method if hasattr(packet.sip, 'method') else packet.sip.status_code,
            'call_id': packet.sip.call_id if hasattr(packet.sip, 'call_id') else None,
        }
        
        # Store in elasticsearch
        try:
            self.es.index(index='sip-traces', document=sip_data)
        except Exception as e:
            print(f"Error storing packet: {e}")
            
    def get_call_flow(self, call_id):
        """
        Retrieve call flow for a specific Call-ID
        """
        query = {
            "query": {
                "match": {
                    "call_id": call_id
                }
            },
            "sort": [
                {"timestamp": {"order": "asc"}}
            ]
        }
        
        try:
            result = self.es.search(index='sip-traces', body=query)
            return result['hits']['hits']
        except Exception as e:
            print(f"Error retrieving call flow: {e}")
            return []
