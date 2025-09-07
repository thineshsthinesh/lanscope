# lanscope/app.py - Enhanced Version with Full Network Scanning
from gevent import monkey
monkey.patch_all()

import logging
import threading
import time
from ipaddress import ip_network, AddressValueError
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import netifaces as ni
from engine.discovery_engine import DiscoveryEngine

# Configuration
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("geventwebsocket.handler").setLevel(logging.WARNING)

# Manual network override
MANUAL_INTERFACE = None  # e.g., "eth0"
MANUAL_SUBNET = None     # e.g., "192.168.1.0/24"

# Flask & SocketIO initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'lanscope-enhanced-secret-key-change-in-production'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='gevent')

# Global state
discovery_engine = None
engine_lock = threading.Lock()
scan_in_progress = False
last_scan_time = None

def get_network_details():
    """Enhanced network detection with better error handling."""
    try:
        gateways = ni.gateways()
        default_gateway_info = gateways.get('default', {}).get(ni.AF_INET)
        address_family = ni.AF_INET

        if not default_gateway_info:
            logging.warning("No IPv4 default gateway found. Trying IPv6.")
            default_gateway_info = gateways.get('default', {}).get(ni.AF_INET6)
            address_family = ni.AF_INET6

        if not default_gateway_info:
            logging.error("Could not determine any default gateway.")
            return None, None

        interface = default_gateway_info[1]
        addresses = ni.ifaddresses(interface).get(address_family)
        
        if not addresses:
            logging.error(f"No addresses found for interface {interface}")
            return None, None
            
        ip_info = addresses[0]

        # Clean IP address and handle different netmask formats
        ip_address = ip_info['addr'].split('%')[0]
        netmask = ip_info['netmask']

        if '/' in netmask:
            prefix = netmask.split('/')[1]
            subnet_string = f"{ip_address}/{prefix}"
        else:
            subnet_string = f"{ip_address}/{netmask}"

        network = ip_network(subnet_string, strict=False)
        subnet = str(network.with_prefixlen)

        logging.info(f"Auto-detected interface: {interface}, subnet: {subnet}")
        return interface, subnet
        
    except Exception as e:
        logging.error(f"Network detection failed: {e}")
        return None, None

@app.route('/')
def index():
    """Serve the enhanced dashboard."""
    return render_template('index.html')

@app.route('/api/network-info')
def network_info():
    """API endpoint to get current network information."""
    interface, subnet = None, None
    
    if MANUAL_INTERFACE and MANUAL_SUBNET:
        interface, subnet = MANUAL_INTERFACE, MANUAL_SUBNET
    else:
        interface, subnet = get_network_details()
    
    return jsonify({
        'interface': interface,
        'subnet': subnet,
        'scan_in_progress': scan_in_progress,
        'last_scan': last_scan_time.isoformat() if last_scan_time else None
    })

@app.route('/api/start-scan', methods=['POST'])
def start_scan():
    """API endpoint to manually start a network scan."""
    global discovery_engine, scan_in_progress
    
    with engine_lock:
        if scan_in_progress:
            return jsonify({'error': 'Scan already in progress'}), 400
        
        interface, subnet = None, None
        if MANUAL_INTERFACE and MANUAL_SUBNET:
            interface, subnet = MANUAL_INTERFACE, MANUAL_SUBNET
        else:
            interface, subnet = get_network_details()
        
        if not interface or not subnet:
            return jsonify({'error': 'Could not determine network configuration'}), 500
        
        # Create new engine instance with full scan enabled
        discovery_engine = DiscoveryEngine(socketio, interface, subnet, full_scan=True)
        scan_in_progress = True
        
        # Start scan in background
        socketio.start_background_task(target=run_discovery_scan)
        
        return jsonify({'message': 'Full network scan started successfully'})

@app.route('/api/start-custom-scan', methods=['POST'])
def start_custom_scan():
    """API endpoint to start a custom network scan with user-specified parameters."""
    global discovery_engine, scan_in_progress
    
    with engine_lock:
        if scan_in_progress:
            return jsonify({'error': 'Scan already in progress'}), 400
        
        try:
            config = request.get_json()
            subnet = config.get('subnet')
            max_hosts = config.get('maxHosts', 65535)
            scan_type = config.get('scanType', 'comprehensive')
            
            if not subnet:
                return jsonify({'error': 'Subnet is required'}), 400
            
            # Validate subnet format
            try:
                ip_network(subnet, strict=False)
            except AddressValueError:
                return jsonify({'error': 'Invalid subnet format'}), 400
            
            # Get interface
            interface, _ = get_network_details()
            if not interface:
                return jsonify({'error': 'Could not determine network interface'}), 500
            
            # Create new engine instance with custom configuration
            discovery_engine = DiscoveryEngine(
                socketio, 
                interface, 
                subnet, 
                full_scan=(scan_type == 'comprehensive'),
                max_hosts=max_hosts
            )
            scan_in_progress = True
            
            # Start scan in background
            socketio.start_background_task(target=run_discovery_scan)
            
            return jsonify({
                'message': 'Custom scan started successfully',
                'subnet': subnet,
                'max_hosts': max_hosts,
                'scan_type': scan_type
            })
            
        except Exception as e:
            logging.error(f"Failed to start custom scan: {e}")
            return jsonify({'error': f'Failed to start custom scan: {str(e)}'}), 500

def run_discovery_scan():
    """Background task to run network discovery."""
    global scan_in_progress, last_scan_time
    
    try:
        discovery_engine.run()
        last_scan_time = time.time()
        socketio.emit('scan_complete', {'timestamp': last_scan_time})
    except Exception as e:
        logging.error(f"Scan failed: {e}")
        socketio.emit('scan_error', {'error': str(e)})
    finally:
        scan_in_progress = False

@socketio.on('connect')
def handle_connect():
    """Handle client connection with enhanced status reporting."""
    global discovery_engine, scan_in_progress
    
    logging.info(f'Client connected from {request.sid}')
    emit('connection_status', {'status': 'connected'})
    
    with engine_lock:
        if discovery_engine is None and not scan_in_progress:
            logging.info("Starting initial network discovery...")
            
            interface, subnet = None, None
            if MANUAL_INTERFACE and MANUAL_SUBNET:
                interface, subnet = MANUAL_INTERFACE, MANUAL_SUBNET
            else:
                interface, subnet = get_network_details()

            if interface and subnet:
                discovery_engine = DiscoveryEngine(socketio, interface, subnet, full_scan=True)
                scan_in_progress = True
                socketio.start_background_task(target=run_discovery_scan)
                emit('scan_started', {'interface': interface, 'subnet': subnet, 'full_scan': True})
            else:
                emit('scan_error', {'error': 'Network configuration detection failed'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    logging.info(f'Client disconnected: {request.sid}')

@socketio.on('request_refresh')
def handle_refresh_request():
    """Handle manual refresh requests from frontend."""
    emit('scan_started', {'message': 'Starting network refresh...'})
    socketio.start_background_task(target=start_scan)

@socketio.on('cancel_scan')
def handle_cancel_scan():
    """Handle scan cancellation requests."""
    global discovery_engine, scan_in_progress
    
    if discovery_engine and scan_in_progress:
        discovery_engine.cancel_scan()
        scan_in_progress = False
        emit('scan_cancelled', {'message': 'Scan cancelled successfully'})

@socketio.on('get_network_stats')
def handle_stats_request():
    """Provide current network statistics."""
    stats = {
        'scan_in_progress': scan_in_progress,
        'last_scan': last_scan_time,
        'interface': MANUAL_INTERFACE,
        'subnet': MANUAL_SUBNET,
        'full_scan_enabled': True
    }
    emit('network_stats', stats)

if __name__ == '__main__':
    logging.info("Starting LanScope Enhanced Server with Full Network Scanning...")
    logging.info("Access the dashboard at: http://127.0.0.1:5000")
    logging.info("For production, use a proper WSGI server like Gunicorn")
    
    try:
        socketio.run(
            app, 
            host='0.0.0.0', 
            port=5000, 
            debug=False,
            allow_unsafe_werkzeug=True
        )
    except KeyboardInterrupt:
        logging.info("Server shutdown requested by user")
    except Exception as e:
        logging.error(f"Server error: {e}")