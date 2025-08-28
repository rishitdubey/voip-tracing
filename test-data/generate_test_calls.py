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
            logger.info("�� SIP traffic generation timed out (as expected)")
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
        logger.info(f"�� Description: {config['description']}")
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
    logger.info("�� TEST SUMMARY")
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
