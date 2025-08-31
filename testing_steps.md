
# 🚀 **Complete VoIP Tracing MVP Testing Guide**

Now that we've achieved successful test results, here's your comprehensive testing workflow for future use:

## 📋 **Prerequisites Check**

Before starting any test, ensure these are running:

```bash
# Check if FreeSWITCH container is healthy
docker ps --filter name=voip-freeswitch

# Should show: (healthy) status
# If not healthy, restart with:
docker-compose restart freeswitch
```

## �� **Complete Testing Workflow**

### **Step 1: Activate Virtual Environment**
```bash
cd /Users/rishitdubey/Desktop/voip-tracing
source venv/bin/activate
```
**What it achieves**: Activates Python virtual environment with all required dependencies (pyshark, flask, etc.)

### **Step 2: Initialize Database (First time only)**
```bash
cd parser
python3 init_database.py
```
**What it achieves**: Creates SQLite database with proper schema for SIP sessions, messages, and RTP flows

### **Step 3: Generate Test VoIP Traffic**
```bash
cd ../test-data
python3 create_invite_test.py
```
**What it achieves**: 
- Creates PCAP file with INVITE/OPTIONS messages
- Generates proper Call-IDs for session tracking
- Saves to `../pcaps/invite_test.pcap`

**Expected Output**: 
```
✅ PCAP file ready: ../pcaps/invite_test.pcap
📊 File size: ~2000 bytes
```

### **Step 4: Parse PCAP and Create Sessions**
```bash
cd ../parser
python3 voip_parser.py ../pcaps/invite_test.pcap invite_test
```
**What it achieves**:
- Extracts SIP messages from PCAP
- Creates SIP sessions based on Call-IDs
- Stores data in SQLite database

**Expected Output**:
```
📦 Total packets: 5
📞 SIP packets: 5
📋 SIP sessions: 5
✅ Saved 5 SIP sessions and 0 RTP flows
```

### **Step 5: Verify Database Contents**
```bash
python3 -c "
import sqlite3
conn = sqlite3.connect('voip_metadata.db')
cur = conn.cursor()

print('=== DATABASE CONTENTS ===')
cur.execute('SELECT COUNT(*) FROM sip_sessions')
print(f'SIP Sessions: {cur.fetchone()[0]}')

cur.execute('SELECT COUNT(*) FROM sip_messages')
print(f'SIP Messages: {cur.fetchone()[0]}')

cur.execute('SELECT call_id, method FROM sip_sessions LIMIT 3')
print('\n=== SAMPLE SESSIONS ===')
for row in cur.fetchall():
    print(f'Call-ID: {row[0][:8]}..., Method: {row[1]}')

conn.close()
"
```
**What it achieves**: Confirms data was properly stored in database

## �� **Alternative Test Scenarios**

### **Option A: Simple SIP Test**
```bash
cd test-data
python3 simple_test.py
```
**Use case**: Basic SIP OPTIONS testing without complex session creation

### **Option B: Manual PCAP Capture**
```bash
# Start capture in background
sudo tcpdump -i lo0 -w ../pcaps/manual_test.pcap host localhost and port 5060 &

# Generate traffic
cd test-data
python3 minimal_test.py

# Stop capture
sudo pkill tcpdump
```
**Use case**: When you want to capture specific traffic patterns

### **Option C: Custom PCAP with Specific Content**
```bash
cd test-data
python3 create_working_pcap.py
```
**Use case**: Generate working PCAP files for debugging parser issues

## �� **Cleanup Commands**

### **Reset Database (Start Fresh)**
```bash
cd parser
rm voip_metadata.db
python3 init_database.py
```

### **Clean PCAP Files**
```bash
cd pcaps
rm *.pcap
```

### **Restart FreeSWITCH Container**
```bash
docker-compose restart freeswitch
```

## �� **Expected Results Matrix**

| Test Type | Expected PCAP Size | Expected Sessions | Expected Messages |
|-----------|-------------------|-------------------|-------------------|
| `create_invite_test.py` | ~2000 bytes | 5 | 5 |
| `simple_test.py` | ~1700 bytes | 0* | 5 |
| `minimal_test.py` | Variable | 0* | Variable |

*Note: Simple tests may not create sessions if Call-IDs are missing

## 🚨 **Troubleshooting Commands**

### **Check Container Health**
```bash
docker logs voip-freeswitch --tail 20
docker exec voip-freeswitch ps aux | grep freeswitch
```

### **Verify Network Connectivity**
```bash
# Test if FreeSWITCH is accepting SIP
cd test-data
python3 minimal_test.py
```

### **Debug Parser Issues**
```bash
cd parser
python3 voip_parser.py ../pcaps/invite_test.pcap invite_test 2>&1 | grep -E "(✅|❌|🔍)"
```

## 🎯 **Quick Test Command (All-in-One)**
```bash
# Complete test in one go
cd /Users/rishitdubey/Desktop/voip-tracing && \
source venv/bin/activate && \
cd test-data && \
python3 create_invite_test.py && \
cd ../parser && \
python3 voip_parser.py ../pcaps/invite_test.pcap invite_test
```

## 📝 **Test Validation Checklist**

After each test run, verify:
- [ ] FreeSWITCH container is healthy
- [ ] PCAP file was created (>100 bytes)
- [ ] Parser completed without errors
- [ ] Database contains expected sessions
- [ ] No "No Call-ID found" warnings

## 🔄 **Continuous Testing Workflow**

For ongoing development:
1. **Make code changes**
2. **Run quick test**: `python3 create_invite_test.py && python3 voip_parser.py ../pcaps/invite_test.pcap test`
3. **Verify results match expectations**
4. **Iterate and improve**

This workflow ensures you can consistently test your VoIP tracing system and catch any regressions quickly! 🎉