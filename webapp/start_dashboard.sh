# Create a startup script for the web interface
#!/bin/bash

echo "🚀 Starting VoIP Tracing MVP Dashboard"
echo "======================================="

# Check if database exists
if [ ! -f "../voip_metadata.db" ]; then
    echo "⚠️  Warning: Database not found at ../voip_metadata.db"
    echo "   Please ensure you've parsed some PCAP files first:"
    echo "   python3 ../parser/voip_parser.py your_pcap_file.pcap"
    echo ""
fi

# Check Python dependencies
echo "📋 Checking dependencies..."
python3 -c "import flask, flask_cors" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "❌ Missing Flask dependencies. Installing..."
    pip3 install flask flask-cors
fi

echo "✅ Dependencies OK"
echo ""

# Start the Flask application
echo "🌐 Starting web server on http://localhost:5000"
echo "   Press Ctrl+C to stop"
echo ""

export FLASK_ENV=development
python3 app.py