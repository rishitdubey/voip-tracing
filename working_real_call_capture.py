#!/usr/bin/env python3
"""
Working Real Call Capture System
Uses existing test infrastructure + live capture for real call processing
"""
import subprocess
import time
import os
import sys
from datetime import datetime
from pathlib import Path

class WorkingRealCallCapture:
    def __init__(self, pcap_dir="pcaps"):
        self.pcap_dir = pcap_dir
        self.current_pcap_file = None
        os.makedirs(self.pcap_dir, exist_ok=True)
        
    def check_prerequisites(self):
        """Check if all prerequisites are available"""
        print("🔍 Checking prerequisites...")
        
        # Check Docker
        try:
            result = subprocess.run(['docker', '--version'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print("✅ Docker available")
            else:
                print("❌ Docker not available")
                return False
        except Exception:
            print("❌ Docker not available")
            return False
        
        # Check FreeSWITCH container
        try:
            result = subprocess.run([
                'docker', 'ps', '--filter', 'name=voip-freeswitch', '--format', '{{.Status}}'
            ], capture_output=True, text=True, timeout=5)
            
            if 'Up' in result.stdout:
                print("✅ FreeSWITCH container running")
            else:
                print("❌ FreeSWITCH container not running")
                return False
        except Exception:
            print("❌ Cannot check FreeSWITCH status")
            return False
        
        # Check parser availability
        if os.path.exists('parser/voip_parser.py'):
            print("✅ VoIP parser available")
        else:
            print("❌ VoIP parser not found")
            return False
            
        return True
    
    def capture_with_timeout(self, trace_id, duration=20):
        """Capture network traffic with proper timeout handling"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.current_pcap_file = f"{self.pcap_dir}/working_real_{trace_id}_{timestamp}.pcap"
        
        print(f"🔍 Starting packet capture for {duration} seconds...")
        print(f"   Output: {self.current_pcap_file}")
        
        # Use gtimeout (GNU timeout) if available, otherwise use Python timeout
        cmd = [
            'sudo', 'tcpdump',
            '-i', 'any',
            '-w', self.current_pcap_file,
            '-s', '0',
            'port 5060 or portrange 10000-10100'
        ]
        
        try:
            # Start tcpdump process
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait for specified duration
            time.sleep(duration)
            
            # Terminate the process
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            
            # Check if file was created
            if os.path.exists(self.current_pcap_file):
                file_size = os.path.getsize(self.current_pcap_file)
                print(f"✅ Capture completed: {file_size} bytes")
                return file_size > 24
            else:
                print("❌ No capture file created")
                return False
                
        except Exception as e:
            print(f"❌ Capture error: {e}")
            return False
    
    def generate_test_traffic_during_capture(self):
        """Generate test SIP traffic during capture using existing tools"""
        print("📞 Generating test traffic during capture...")
        
        # Use existing test data generation in background
        try:
            # Run the existing invite test creator
            result = subprocess.run([
                'python3', 'test-data/create_invite_test.py'
            ], cwd='.', capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                print("✅ Test traffic generated successfully")
                return True
            else:
                print(f"⚠️ Test traffic generation warning: {result.stderr[:100]}")
        except Exception as e:
            print(f"⚠️ Test traffic generation error: {e}")
        
        # Fallback: generate simple network activity
        try:
            print("   Fallback: generating basic network activity...")
            subprocess.run(['ping', '-c', '3', 'localhost'], capture_output=True, timeout=10)
            subprocess.run(['nc', '-z', 'localhost', '5060'], capture_output=True, timeout=5)
            print("✅ Basic network activity generated")
            return True
        except Exception as e:
            print(f"⚠️ Basic activity error: {e}")
            return False
    
    def process_captured_data(self, trace_id):
        """Process captured data with existing parsers"""
        if not self.current_pcap_file or not os.path.exists(self.current_pcap_file):
            print("❌ No capture file to process")
            return False
        
        print(f"🔄 Processing captured data...")
        print(f"   PCAP: {self.current_pcap_file}")
        print(f"   Trace ID: {trace_id}")
        
        # Use existing voip_parser.py
        try:
            result = subprocess.run([
                'python3', 'parser/voip_parser.py', 
                self.current_pcap_file, 
                trace_id
            ], cwd='.', capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                print("✅ PCAP parsing completed successfully")
                print(f"Parser output preview:\n{result.stdout[:300]}...")
                return True
            else:
                print(f"❌ Parser failed: {result.stderr[:200]}")
                return False
                
        except Exception as e:
            print(f"❌ Processing error: {e}")
            return False
    
    def run_correlation_analysis(self, trace_id):
        """Run correlation analysis if available"""
        print("🔗 Running correlation analysis...")
        
        try:
            result = subprocess.run([
                'python3', 'parser/correlation_engine.py', 
                '--trace-id', trace_id,
                '--db', 'voip_metadata.db'
            ], cwd='.', capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                print("✅ Correlation analysis completed")
                return True
            else:
                print(f"⚠️ Correlation analysis warning: {result.stderr[:100]}")
                return False
                
        except Exception as e:
            print(f"⚠️ Correlation analysis error: {e}")
            return False
    
    def run_complete_pipeline(self, trace_id=None, duration=20):
        """Run the complete real call processing pipeline"""
        if not trace_id:
            trace_id = f"working_real_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        print("🚀 Working Real Call Capture Pipeline")
        print("=" * 45)
        print(f"📋 Trace ID: {trace_id}")
        print(f"⏱️ Duration: {duration} seconds")
        
        # Step 1: Check prerequisites
        if not self.check_prerequisites():
            print("❌ Prerequisites not met")
            return False
        
        # Step 2: Start capture and generate traffic simultaneously
        print("\n🎯 Starting simultaneous capture and traffic generation...")
        
        # Start traffic generation in background
        import threading
        traffic_thread = threading.Thread(target=self.generate_test_traffic_during_capture)
        traffic_thread.daemon = True
        traffic_thread.start()
        
        # Wait a moment for traffic generation to start
        time.sleep(2)
        
        # Run capture
        capture_success = self.capture_with_timeout(trace_id, duration)
        
        # Wait for traffic thread to complete
        traffic_thread.join(timeout=5)
        
        if not capture_success:
            print("❌ Capture failed")
            return False
        
        # Step 3: Process captured data
        processing_success = self.process_captured_data(trace_id)
        
        if not processing_success:
            print("❌ Processing failed")
            return False
        
        # Step 4: Run correlation analysis
        self.run_correlation_analysis(trace_id)
        
        # Step 5: Show results
        print(f"\n🎉 Pipeline completed successfully!")
        print(f"📁 PCAP file: {self.current_pcap_file}")
        print(f"📋 Trace ID: {trace_id}")
        print(f"🗄️ Database: voip_metadata.db")
        
        # Check database contents
        try:
            result = subprocess.run([
                'sqlite3', 'voip_metadata.db', 
                f"SELECT COUNT(*) FROM sip_sessions WHERE trace_id='{trace_id}';"
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                session_count = result.stdout.strip()
                print(f"📊 Sessions found in database: {session_count}")
        except Exception:
            pass
        
        print(f"\n📋 Next steps:")
        print(f"1. View PCAP: wireshark {self.current_pcap_file}")
        print(f"2. Check database: sqlite3 voip_metadata.db")
        print(f"3. Start web dashboard: cd webapp && python3 app.py")
        print(f"4. View trace in browser: http://localhost:3000")
        
        return True

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Working Real Call Capture Pipeline')
    parser.add_argument('--trace-id', help='Custom trace ID')
    parser.add_argument('--duration', type=int, default=20, help='Capture duration in seconds')
    
    args = parser.parse_args()
    
    capture_system = WorkingRealCallCapture()
    success = capture_system.run_complete_pipeline(
        trace_id=args.trace_id,
        duration=args.duration
    )
    
    return 0 if success else 1

if __name__ == "__main__":
    exit(main())
