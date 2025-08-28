from flask import jsonify, request
from app import create_app
from app.sip_trace import SIPTracer

app = create_app()
tracer = None

@app.route('/start', methods=['POST'])
def start_capture():
    global tracer
    try:
        interface = request.json.get('interface', 'any')
        tracer = SIPTracer()
        # Start in a separate thread to not block the API
        import threading
        capture_thread = threading.Thread(target=tracer.capture_live, args=(interface,))
        capture_thread.daemon = True
        capture_thread.start()
        return jsonify({"status": "success", "message": "Capture started"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/calls/<call_id>', methods=['GET'])
def get_call_flow(call_id):
    global tracer
    if not tracer:
        return jsonify({"status": "error", "message": "Tracer not initialized"}), 400
    
    call_flow = tracer.get_call_flow(call_id)
    return jsonify({"status": "success", "data": call_flow})

if __name__ == '__main__':
    app.run(debug=True)
