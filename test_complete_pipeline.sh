# Create comprehensive testing script
#!/bin/bash

echo "🧪 VoIP Tracing MVP - Complete Pipeline Test"
echo "============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

run_test() {
    local test_name="$1"
    local test_command="$2"
    
    echo -e "\n📋 Testing: $test_name"
    echo "   Command: $test_command"
    
    if eval "$test_command"; then
        echo -e "   ${GREEN}✅ PASSED${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "   ${RED}❌ FAILED${NC}"
        ((TESTS_FAILED++))
    fi
}

echo "🔍 Pre-flight checks..."

# Check if we're in the right directory
if [ ! -d "parser" ] || [ ! -d "webapp" ] || [ ! -d "test-data" ]; then
    echo "❌ Please run this script from the voip-tracing-mvp root directory"
    exit 1
fi

# Check Docker
run_test "Docker availability" "docker --version > /dev/null 2>&1"
run_test "Docker Compose availability" "docker-compose --version > /dev/null 2>&1"

# Check Python and dependencies
run_test "Python 3 availability" "python3 --version > /dev/null 2>&1"
run_test "Required Python packages" "python3 -c 'import sqlite3, pyshark, flask, scapy' > /dev/null 2>&1"

echo -e "\n🏗️  Infrastructure tests..."

# Test database initialization
run_test "Database initialization" "python3 parser/init_database.py test_voip.db && rm -f test_voip.db"

# Test FreeSWITCH container
echo -e "\n🐳 Testing FreeSWITCH container..."
docker-compose ps | grep -q "voip-freeswitch.*Up"
if [ $? -eq 0 ]; then
    echo -e "   ${GREEN}✅ FreeSWITCH container is running${NC}"
    ((TESTS_PASSED++))
else
    echo -e "   ${YELLOW}⚠️  FreeSWITCH container not running, starting...${NC}"
    docker-compose up -d
    sleep 10
    if docker-compose ps | grep -q "voip-freeswitch.*Up"; then
        echo -e "   ${GREEN}✅ FreeSWITCH container started successfully${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "   ${RED}❌ Failed to start FreeSWITCH container${NC}"
        ((TESTS_FAILED++))
    fi
fi

echo -e "\n📦 Testing packet capture and parsing..."

# Generate test data
echo "🎯 Generating test PCAP data..."
cd test-data
python3 generate_test_calls.py > /dev/null 2>&1 &
TEST_PID=$!
sleep 15  # Let it generate some traffic
kill $TEST_PID 2>/dev/null
cd ..

# Find a test PCAP file
TEST_PCAP=$(find pcaps/ -name "*.pcap" -type f | head -1)
if [ -n "$TEST_PCAP" ] && [ -f "$TEST_PCAP" ]; then
    echo "✅ Found test PCAP: $TEST_PCAP"
    
    # Test parsing
    run_test "PCAP parsing" "python3 parser/voip_parser.py '$TEST_PCAP' test_trace"
    
    # Test correlation
    run_test "Correlation analysis" "python3 parser/correlation_engine.py --trace-id test_trace --db voip_metadata.db"
    
    # Test security analysis
    run_test "Security analysis" "python3 parser/security_analyzer.py --trace-id test_trace --db voip_metadata.db"
    
else
    echo -e "${YELLOW}⚠️  No test PCAP found, skipping parsing tests${NC}"
    ((TESTS_FAILED++))
fi

echo -e "\n🌐 Testing web interface..."

# Test Flask app startup (background)
cd webapp
python3 app.py > flask_test.log 2>&1 &
FLASK_PID=$!
cd ..

sleep 5

# Test if Flask is responding
run_test "Web interface startup" "curl -s http://localhost:5000 > /dev/null 2>&1"
run_test "API stats endpoint" "curl -s http://localhost:5000/api/stats | grep -q 'total_traces'"
run_test "API traces endpoint" "curl -s http://localhost:5000/api/traces | grep -q 'traces'"

# Cleanup
kill $FLASK_PID 2>/dev/null
rm -f webapp/flask_test.log

echo -e "\n📊 Test Results Summary"
echo "======================="
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
echo -e "Total Tests: $((TESTS_PASSED + TESTS_FAILED))"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}🎉 All tests passed! Your VoIP Tracing MVP is ready!${NC}"
    echo ""
    echo "📋 Next steps:"
    echo "1. Generate test data: cd test-data && python3 generate_test_calls.py"
    echo "2. Parse PCAP files: python3 parser/voip_parser.py your_file.pcap"
    echo "3. Run correlation: python3 parser/correlation_engine.py --trace-id your_trace"
    echo "4. Start web interface: cd webapp && ./start_dashboard.sh"
    echo ""
else
    echo -e "\n${RED}❌ Some tests failed. Please check the errors above.${NC}"
fi