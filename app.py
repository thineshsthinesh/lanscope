#!/usr/bin/env python3
"""
Enhanced Cumulative Network Topology Scanner with Real-Time Traffic Visualization
- Cumulative scan results like Zenmap
- Persistent storage of discovered hosts and topology
- Intelligent merging of multiple scan results
- Historical scan tracking and comparison
- Export/Import functionality for scan results
- Enhanced visualization with draggable nodes and zoom
- Real-time network traffic visualization with packet capture
- Auto-discovery of hosts from packet capture
- Automatic subnet expansion for gateways
- Path-aware traffic visualization
"""

from flask import Flask, render_template, send_file, request, jsonify
from flask_socketio import SocketIO, emit
import subprocess
import socket
import ipaddress
import threading
import time
import sys
import re
import os
import json
import sqlite3
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import tempfile
import zipfile
import queue

app = Flask(__name__)
app.config['SECRET_KEY'] = 'topo-scanner'
socketio = SocketIO(app, cors_allowed_origins="*")

class CumulativeTopologyScanner:
    def __init__(self):
        self.active_hosts = {}
        self.host_routes = {}
        self.scan_active = False
        self.traffic_capture_active = False
        self.traffic_process = None
        self.cumulative_data = {
            'hosts': {},
            'routes': {},
            'links': [],
            'scan_history': [],
            'node_positions': {}
        }
        # New: Track discovered hosts from traffic
        self.traffic_discovered_hosts = set()
        self.discovery_queue = queue.Queue()
        self.discovery_thread = None
        self.processed_gateways = set()
        
        self.init_database()
        self.load_cumulative_data()
        
    def init_database(self):
        """Initialize SQLite database for persistent storage"""
        try:
            self.db_path = 'network_topology.db'
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Hosts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS hosts (
                    ip TEXT PRIMARY KEY,
                    hostname TEXT,
                    mac TEXT,
                    device_type TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    scan_count INTEGER DEFAULT 1,
                    active INTEGER DEFAULT 1,
                    discovered_via TEXT DEFAULT 'scan'
                )
            ''')
            
            # Routes table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS routes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_ip TEXT,
                    hop_number INTEGER,
                    hop_ip TEXT,
                    hop_hostname TEXT,
                    rtt REAL,
                    first_seen TEXT,
                    last_seen TEXT,
                    UNIQUE(target_ip, hop_number, hop_ip)
                )
            ''')
            
            # Links table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS links (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_ip TEXT,
                    target_ip TEXT,
                    link_type TEXT,
                    hop_number INTEGER,
                    rtt REAL,
                    first_seen TEXT,
                    last_seen TEXT,
                    active INTEGER DEFAULT 1,
                    UNIQUE(source_ip, target_ip, link_type)
                )
            ''')
            
            # Scans table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    network TEXT,
                    start_time TEXT,
                    end_time TEXT,
                    hosts_found INTEGER,
                    new_hosts INTEGER,
                    status TEXT
                )
            ''')
            
            # Node positions table for persistent draggable positions
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS node_positions (
                    ip TEXT PRIMARY KEY,
                    x REAL,
                    y REAL,
                    fixed INTEGER DEFAULT 1
                )
            ''')
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Database initialization error: {e}")
    
    def load_cumulative_data(self):
        """Load existing cumulative data from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Load hosts
            cursor.execute('SELECT * FROM hosts WHERE active = 1')
            for row in cursor.fetchall():
                ip = row[0]
                hostname = row[1]
                mac = row[2]
                device_type = row[3]
                first_seen = row[4]
                last_seen = row[5]
                scan_count = row[6]
                active = row[7]
                discovered_via = row[8] if len(row) > 8 else 'scan'
                
                self.cumulative_data['hosts'][ip] = {
                    'ip': ip,
                    'hostname': hostname,
                    'mac': mac,
                    'device_type': device_type,
                    'first_seen': first_seen,
                    'last_seen': last_seen,
                    'scan_count': scan_count,
                    'active': bool(active),
                    'discovered_via': discovered_via
                }
            
            # Load node positions
            cursor.execute('SELECT * FROM node_positions')
            for row in cursor.fetchall():
                ip, x, y, fixed = row
                self.cumulative_data['node_positions'][ip] = {
                    'x': x, 'y': y, 'fixed': bool(fixed)
                }
            
            # Load recent scan history
            cursor.execute('SELECT * FROM scans ORDER BY start_time DESC LIMIT 10')
            self.cumulative_data['scan_history'] = [
                {
                    'id': row[0], 'network': row[1], 'start_time': row[2],
                    'end_time': row[3], 'hosts_found': row[4], 'new_hosts': row[5], 'status': row[6]
                }
                for row in cursor.fetchall()
            ]
            
            conn.close()
            
            self.emit_update('cumulative_loaded', {
                'total_hosts': len(self.cumulative_data['hosts']),
                'scan_history': self.cumulative_data['scan_history']
            })
            
        except Exception as e:
            print(f"Error loading cumulative data: {e}")
    
    def save_node_position(self, ip, x, y, fixed=True):
        """Save node position to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO node_positions (ip, x, y, fixed)
                VALUES (?, ?, ?, ?)
            ''', (ip, x, y, int(fixed)))
            conn.commit()
            conn.close()
            
            self.cumulative_data['node_positions'][ip] = {
                'x': x, 'y': y, 'fixed': fixed
            }
        except Exception as e:
            print(f"Error saving node position: {e}")
    
    def export_scan_data(self, include_positions=True):
        """Export all scan data to JSON format"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            export_data = {
                'export_info': {
                    'timestamp': datetime.now().isoformat(),
                    'version': '1.0',
                    'scanner': 'Cumulative Network Topology Scanner'
                },
                'hosts': {},
                'routes': [],
                'scans': [],
                'node_positions': {} if include_positions else {}
            }
            
            # Export hosts
            cursor.execute('SELECT * FROM hosts')
            for row in cursor.fetchall():
                ip = row[0]
                export_data['hosts'][ip] = {
                    'hostname': row[1],
                    'mac': row[2],
                    'device_type': row[3],
                    'first_seen': row[4],
                    'last_seen': row[5],
                    'scan_count': row[6],
                    'active': bool(row[7]),
                    'discovered_via': row[8] if len(row) > 8 else 'scan'
                }
            
            # Export routes
            cursor.execute('SELECT * FROM routes')
            for row in cursor.fetchall():
                export_data['routes'].append({
                    'target_ip': row[1],
                    'hop_number': row[2],
                    'hop_ip': row[3],
                    'hop_hostname': row[4],
                    'rtt': row[5],
                    'first_seen': row[6],
                    'last_seen': row[7]
                })
            
            # Export scans
            cursor.execute('SELECT * FROM scans')
            for row in cursor.fetchall():
                export_data['scans'].append({
                    'network': row[1],
                    'start_time': row[2],
                    'end_time': row[3],
                    'hosts_found': row[4],
                    'new_hosts': row[5],
                    'status': row[6]
                })
            
            # Export node positions if requested
            if include_positions:
                cursor.execute('SELECT * FROM node_positions')
                for row in cursor.fetchall():
                    ip, x, y, fixed = row
                    export_data['node_positions'][ip] = {
                        'x': x, 'y': y, 'fixed': bool(fixed)
                    }
            
            conn.close()
            return export_data
            
        except Exception as e:
            print(f"Error exporting scan data: {e}")
            return None
    
    def import_scan_data(self, import_data, merge=True):
        """Import scan data from JSON format"""
        try:
            if not isinstance(import_data, dict) or 'hosts' not in import_data:
                raise ValueError("Invalid import data format")
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            imported_hosts = 0
            imported_routes = 0
            imported_scans = 0
            
            # Import hosts
            for ip, host_data in import_data.get('hosts', {}).items():
                if merge:
                    cursor.execute('SELECT scan_count FROM hosts WHERE ip = ?', (ip,))
                    existing = cursor.fetchone()
                    
                    if existing:
                        cursor.execute('''
                            UPDATE hosts SET 
                            hostname = ?, mac = ?, device_type = ?, 
                            last_seen = ?, scan_count = scan_count + ?, active = 1
                            WHERE ip = ?
                        ''', (
                            host_data['hostname'], host_data['mac'], host_data['device_type'],
                            host_data['last_seen'], host_data.get('scan_count', 1), ip
                        ))
                    else:
                        cursor.execute('''
                            INSERT INTO hosts 
                            (ip, hostname, mac, device_type, first_seen, last_seen, scan_count, active, discovered_via)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            ip, host_data['hostname'], host_data['mac'], host_data['device_type'],
                            host_data['first_seen'], host_data['last_seen'], 
                            host_data.get('scan_count', 1), int(host_data.get('active', True)),
                            host_data.get('discovered_via', 'scan')
                        ))
                        imported_hosts += 1
                else:
                    cursor.execute('''
                        INSERT OR REPLACE INTO hosts 
                        (ip, hostname, mac, device_type, first_seen, last_seen, scan_count, active, discovered_via)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        ip, host_data['hostname'], host_data['mac'], host_data['device_type'],
                        host_data['first_seen'], host_data['last_seen'], 
                        host_data.get('scan_count', 1), int(host_data.get('active', True)),
                        host_data.get('discovered_via', 'scan')
                    ))
                    imported_hosts += 1
            
            # Import routes
            for route_data in import_data.get('routes', []):
                cursor.execute('''
                    INSERT OR REPLACE INTO routes
                    (target_ip, hop_number, hop_ip, hop_hostname, rtt, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    route_data['target_ip'], route_data['hop_number'], route_data['hop_ip'],
                    route_data['hop_hostname'], route_data['rtt'], 
                    route_data['first_seen'], route_data['last_seen']
                ))
                imported_routes += 1
            
            # Import scans
            for scan_data in import_data.get('scans', []):
                cursor.execute('''
                    INSERT OR REPLACE INTO scans
                    (network, start_time, end_time, hosts_found, new_hosts, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    scan_data['network'], scan_data['start_time'], scan_data['end_time'],
                    scan_data['hosts_found'], scan_data['new_hosts'], scan_data['status']
                ))
                imported_scans += 1
            
            # Import node positions
            for ip, pos_data in import_data.get('node_positions', {}).items():
                cursor.execute('''
                    INSERT OR REPLACE INTO node_positions (ip, x, y, fixed)
                    VALUES (?, ?, ?, ?)
                ''', (ip, pos_data['x'], pos_data['y'], int(pos_data.get('fixed', True))))
            
            conn.commit()
            conn.close()
            
            self.load_cumulative_data()
            
            return {
                'success': True,
                'imported_hosts': imported_hosts,
                'imported_routes': imported_routes,
                'imported_scans': imported_scans,
                'total_hosts': len(self.cumulative_data['hosts'])
            }
            
        except Exception as e:
            print(f"Error importing scan data: {e}")
            return {'success': False, 'error': str(e)}
    
    def save_host_to_db(self, host_info, is_new=False, discovered_via='scan'):
        """Save or update host in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            current_time = datetime.now().isoformat()
            
            if is_new:
                cursor.execute('''
                    INSERT OR REPLACE INTO hosts 
                    (ip, hostname, mac, device_type, first_seen, last_seen, scan_count, active, discovered_via)
                    VALUES (?, ?, ?, ?, ?, ?, 1, 1, ?)
                ''', (
                    host_info['ip'], host_info['hostname'], host_info['mac'],
                    host_info['device_type'], current_time, current_time, discovered_via
                ))
            else:
                cursor.execute('''
                    UPDATE hosts SET 
                    hostname = ?, mac = ?, device_type = ?, last_seen = ?, 
                    scan_count = scan_count + 1, active = 1
                    WHERE ip = ?
                ''', (
                    host_info['hostname'], host_info['mac'], host_info['device_type'],
                    current_time, host_info['ip']
                ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error saving host to DB: {e}")
    
    def save_route_to_db(self, target_ip, route):
        """Save route information to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            current_time = datetime.now().isoformat()
            
            for hop_info in route:
                cursor.execute('''
                    INSERT OR REPLACE INTO routes
                    (target_ip, hop_number, hop_ip, hop_hostname, rtt, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, 
                        COALESCE((SELECT first_seen FROM routes WHERE target_ip = ? AND hop_number = ? AND hop_ip = ?), ?),
                        ?)
                ''', (
                    target_ip, hop_info['hop'], hop_info['ip'], hop_info['hostname'],
                    hop_info['rtt'], target_ip, hop_info['hop'], hop_info['ip'],
                    current_time, current_time
                ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error saving route to DB: {e}")
    
    def save_scan_record(self, network, start_time, hosts_found, new_hosts):
        """Save scan record to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            end_time = datetime.now().isoformat()
            
            cursor.execute('''
                INSERT INTO scans (network, start_time, end_time, hosts_found, new_hosts, status)
                VALUES (?, ?, ?, ?, ?, 'completed')
            ''', (network, start_time, end_time, hosts_found, new_hosts))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error saving scan record: {e}")
    
    def emit_update(self, event, data):
        socketio.emit(event, data)
    
    def ping_host(self, ip: str) -> tuple:
        """Fast ping check with RTT"""
        try:
            if sys.platform.startswith('win'):
                cmd = ['ping', '-n', '1', '-w', '1000', ip]
            else:
                cmd = ['ping', '-c', '1', '-W', '1', ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                if sys.platform.startswith('win'):
                    rtt_match = re.search(r'time[<=](\d+)ms', result.stdout)
                else:
                    rtt_match = re.search(r'time=(\d+\.?\d*)', result.stdout)
                rtt = float(rtt_match.group(1)) if rtt_match else 1.0
                return True, rtt
            return False, 0
        except:
            return False, 0
    
    def get_hostname(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return ip
    
    def get_mac_via_arp(self, ip: str) -> str:
        try:
            if sys.platform.startswith('win'):
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=2)
                mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', result.stdout)
                return mac_match.group(0) if mac_match else None
            else:
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if ip in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                return parts[2] if ':' in parts[2] else None
                return None
        except:
            return None
    
    def traceroute_to_host(self, ip: str) -> list:
        """Enhanced traceroute to find exact path to host - FIXED for Linux"""
        try:
            if sys.platform.startswith('win'):
                cmd = ['tracert', '-h', '15', '-w', '2000', ip]
            else:
                # FIXED: Use -n for numeric output, -q 1 for one probe per hop
                cmd = ['traceroute', '-n', '-m', '15', '-w', '2', '-q', '1', ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            hops = []
            hop_number = 0
            
            for line in result.stdout.split('\n'):
                if 'traceroute' in line.lower() or 'tracing route' in line.lower():
                    continue
                
                if sys.platform.startswith('win'):
                    hop_match = re.search(r'^\s*(\d+)\s+.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    if hop_match:
                        hop_number = int(hop_match.group(1))
                        hop_ip = hop_match.group(2)
                        rtt_matches = re.findall(r'(\d+)\s*ms', line)
                        avg_rtt = sum(int(r) for r in rtt_matches) / len(rtt_matches) if rtt_matches else 0
                        
                        hops.append({
                            'hop': hop_number,
                            'ip': hop_ip,
                            'hostname': self.get_hostname(hop_ip),
                            'rtt': avg_rtt
                        })
                else:
                    # FIXED: Better Linux traceroute parsing with -n flag
                    # Format: " 1  192.168.1.1  1.234 ms"
                    hop_match = re.search(r'^\s*(\d+)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d+\.?\d*)\s*ms', line)
                    if hop_match:
                        hop_number = int(hop_match.group(1))
                        hop_ip = hop_match.group(2)
                        rtt = float(hop_match.group(3))
                        
                        hops.append({
                            'hop': hop_number,
                            'ip': hop_ip,
                            'hostname': self.get_hostname(hop_ip),
                            'rtt': rtt
                        })
                    elif re.search(r'^\s*(\d+)\s+\*', line):
                        # Handle timeout hops
                        hop_match_timeout = re.search(r'^\s*(\d+)', line)
                        if hop_match_timeout:
                            hop_number = int(hop_match_timeout.group(1))
                            hops.append({
                                'hop': hop_number,
                                'ip': '*',
                                'hostname': '* timeout',
                                'rtt': 0
                            })
            
            return hops
        except Exception as e:
            print(f"Traceroute error for {ip}: {e}")
            return []
    
    def process_discovery_queue(self):
        """Process discovered hosts from traffic capture"""
        while self.traffic_capture_active or not self.discovery_queue.empty():
            try:
                ip = self.discovery_queue.get(timeout=1)
                
                # Check if already processed
                if ip in self.cumulative_data['hosts'] or ip in self.traffic_discovered_hosts:
                    continue
                
                self.traffic_discovered_hosts.add(ip)
                
                # Check if host is reachable
                is_alive, rtt = self.ping_host(ip)
                if is_alive:
                    hostname = self.get_hostname(ip)
                    mac = self.get_mac_via_arp(ip)
                    device_type = self._detect_device_type(hostname, ip)
                    
                    # Check if it's a gateway
                    if ip.endswith('.1') or ip.endswith('.254'):
                        self._expand_subnet_for_gateway(ip)
                    
                    host_info = {
                        'ip': ip,
                        'hostname': hostname,
                        'mac': mac,
                        'device_type': device_type,
                        'new': True,
                        'scan_count': 1,
                        'discovered_via': 'traffic'
                    }
                    
                    self.active_hosts[ip] = host_info
                    self.cumulative_data['hosts'][ip] = host_info
                    self.save_host_to_db(host_info, True, 'traffic')
                    
                    # Traceroute to new host
                    route = self.traceroute_to_host(ip)
                    if route:
                        self.host_routes[ip] = route
                        self.save_route_to_db(ip, route)
                    
                    self.emit_update('traffic_host_discovered', {
                        'ip': ip,
                        'hostname': hostname,
                        'device_type': device_type,
                        'rtt': rtt
                    })
                    
                    # Rebuild topology with new host
                    self._build_cumulative_topology()
                    
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Error processing discovery: {e}")
    
    def _expand_subnet_for_gateway(self, gateway_ip):
        """Automatically discover subnet hosts for a gateway"""
        try:
            # Parse gateway network
            network = ipaddress.IPv4Network(f"{gateway_ip}/24", strict=False)
            
            if str(network) in self.processed_gateways:
                return
                
            self.processed_gateways.add(str(network))
            
            self.emit_update('subnet_expansion', {
                'gateway': gateway_ip,
                'network': str(network)
            })
            
            # Quick scan of common hosts in subnet
            common_hosts = list(network.hosts())[:10] + list(network.hosts())[-10:]
            
            discovered = 0
            for host_ip in common_hosts:
                host_ip_str = str(host_ip)
                if host_ip_str not in self.cumulative_data['hosts']:
                    is_alive, rtt = self.ping_host(host_ip_str)
                    if is_alive:
                        hostname = self.get_hostname(host_ip_str)
                        mac = self.get_mac_via_arp(host_ip_str)
                        device_type = self._detect_device_type(hostname, host_ip_str)
                        
                        host_info = {
                            'ip': host_ip_str,
                            'hostname': hostname,
                            'mac': mac,
                            'device_type': device_type,
                            'new': True,
                            'scan_count': 1,
                            'discovered_via': 'gateway_expansion'
                        }
                        
                        self.active_hosts[host_ip_str] = host_info
                        self.cumulative_data['hosts'][host_ip_str] = host_info
                        self.save_host_to_db(host_info, True, 'gateway_expansion')
                        discovered += 1
            
            if discovered > 0:
                self.emit_update('subnet_hosts_found', {
                    'gateway': gateway_ip,
                    'discovered': discovered
                })
                self._build_cumulative_topology()
                
        except Exception as e:
            print(f"Error expanding subnet for gateway {gateway_ip}: {e}")
    
    def capture_network_traffic(self):
        """Capture real-time network traffic and emit to frontend - FIXED for Windows"""
        print("Starting traffic capture with host discovery...")
        self.traffic_capture_active = True
        
        # Start discovery processing thread
        self.discovery_thread = threading.Thread(target=self.process_discovery_queue)
        self.discovery_thread.daemon = True
        self.discovery_thread.start()
        
        try:
            if sys.platform.startswith('win'):
                # FIXED: Try windump (WinPcap) or tshark for Windows
                # Try windump first (more lightweight)
                try:
                    cmd = ['windump', '-n', '-l', '-q', '-i', 'any']
                    self.traffic_process = subprocess.Popen(
                        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        text=True, bufsize=1
                    )
                    print("Using windump for traffic capture")
                except FileNotFoundError:
                    # Fall back to tshark
                    cmd = ['tshark', '-i', 'Wi-Fi', '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst', 
                           '-e', 'frame.protocols', '-e', 'frame.len', '-l', '-Y', 'ip']
                    self.traffic_process = subprocess.Popen(
                        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        text=True, bufsize=1
                    )
                    print("Using tshark for traffic capture")
            else:
                # Linux/Mac - requires tcpdump with proper permissions
                cmd = ['tcpdump', '-i', 'any', '-n', '-l', '-q']
                self.traffic_process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, bufsize=1
                )
                print("Using tcpdump for traffic capture")
            
            # Read packets from the process
            for line in self.traffic_process.stdout:
                if not self.traffic_capture_active:
                    self.traffic_process.terminate()
                    break
                
                # Parse traffic data
                traffic_data = self.parse_traffic_line(line)
                if traffic_data:
                    # Add hosts to discovery queue
                    for ip in [traffic_data['source'], traffic_data['target']]:
                        if self._is_private_ip(ip) and ip not in self.cumulative_data['hosts']:
                            self.discovery_queue.put(ip)
                    
                    # Find actual path for packet visualization
                    path = self._find_packet_path(traffic_data['source'], traffic_data['target'])
                    traffic_data['path'] = path
                    
                    self.emit_update('traffic_packet', traffic_data)
                    
        except FileNotFoundError:
            error_msg = "Traffic capture tool not found.\n"
            if sys.platform.startswith('win'):
                error_msg += "Install WinPcap and windump, or Wireshark with tshark"
            else:
                error_msg += "Install tcpdump: sudo apt-get install tcpdump (Linux) or brew install tcpdump (Mac)"
            print(error_msg)
            self.emit_update('traffic_capture_error', {'error': error_msg})
            self.traffic_capture_active = False
        except PermissionError:
            error_msg = "Permission denied for packet capture.\n"
            if sys.platform.startswith('win'):
                error_msg += "Run as Administrator"
            else:
                error_msg += "Try: sudo chmod +x /usr/bin/tcpdump && sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump"
            print(error_msg)
            self.emit_update('traffic_capture_error', {'error': error_msg})
            self.traffic_capture_active = False
        except Exception as e:
            print(f"Traffic capture error: {e}")
            self.emit_update('traffic_capture_error', {'error': str(e)})
            self.traffic_capture_active = False
    
    def _is_private_ip(self, ip):
        """Check if IP is private/local"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False
    
    def _find_packet_path(self, source_ip, target_ip):
        """Find the network path between source and target for packet visualization"""
        path = []
        
        # Check if we have route information for either endpoint
        if source_ip in self.host_routes:
            route = self.host_routes[source_ip]
            path = [hop['ip'] for hop in route if hop['ip'] != '*']
        elif target_ip in self.host_routes:
            route = self.host_routes[target_ip]
            path = [hop['ip'] for hop in route if hop['ip'] != '*']
        else:
            # Try to find from database
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Check for target route
                cursor.execute('''
                    SELECT hop_ip FROM routes 
                    WHERE target_ip = ? 
                    ORDER BY hop_number
                ''', (target_ip,))
                
                route_rows = cursor.fetchall()
                if route_rows:
                    path = [row[0] for row in route_rows if row[0] != '*']
                
                conn.close()
            except:
                pass
        
        # If no path found, assume direct connection
        if not path:
            path = [source_ip, target_ip]
        
        return path
    
    def parse_traffic_line(self, line):
        """Parse tcpdump/tshark/windump output line"""
        try:
            # Parse tcpdump format: timestamp IP src > dst: protocol
            ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            matches = re.findall(ip_pattern, line)
            
            if len(matches) >= 2:
                src_ip = matches[0]
                dst_ip = matches[1]
                
                # Determine protocol
                protocol = 'TCP'
                if 'UDP' in line.upper():
                    protocol = 'UDP'
                elif 'ICMP' in line.upper():
                    protocol = 'ICMP'
                elif ':53' in line or '.53' in line:  # DNS port
                    protocol = 'DNS'
                elif ':80' in line or '.80' in line:
                    protocol = 'HTTP'
                elif ':443' in line or '.443' in line:
                    protocol = 'HTTPS'
                
                # Estimate packet size
                size = 64
                size_match = re.search(r'length (\d+)', line)
                if size_match:
                    size = int(size_match.group(1))
                
                return {
                    'source': src_ip,
                    'target': dst_ip,
                    'protocol': protocol,
                    'size': size,
                    'timestamp': time.time()
                }
        except Exception as e:
            print(f"Parse error: {e}")
        
        return None
    
    def start_traffic_capture(self):
        """Start traffic capture in separate thread"""
        if not self.traffic_capture_active:
            self.traffic_discovered_hosts.clear()
            self.processed_gateways.clear()
            capture_thread = threading.Thread(target=self.capture_network_traffic)
            capture_thread.daemon = True
            capture_thread.start()
    
    def stop_traffic_capture(self):
        """Stop traffic capture"""
        self.traffic_capture_active = False
        if self.traffic_process:
            self.traffic_process.terminate()
            self.traffic_process = None
        
        # Wait for discovery thread to finish
        if self.discovery_thread and self.discovery_thread.is_alive():
            self.discovery_thread.join(timeout=2)
        
        self.emit_update('traffic_capture_stopped', {'message': 'Traffic capture stopped'})
    
    def discover_subnet(self, network: str):
        """Subnet discovery with cumulative results"""
        scan_start_time = datetime.now().isoformat()
        
        try:
            net = ipaddress.IPv4Network(network, strict=False)
            self.emit_update('scan_status', {
                'message': f'Analyzing network {network} ({net.num_addresses:,} possible addresses) - Cumulative Mode'
            })

            if net.prefixlen == 16:
                self.emit_update('scan_status', {
                    'message': f'/16 detected. Splitting into 256 /24 subnets for scanning'
                })
                for sub in net.subnets(new_prefix=24):
                    if not self.scan_active:
                        break
                    self.emit_update('scan_status', {'message': f'Scanning subnet {sub}'})
                    hosts_to_scan = list(sub.hosts())
                    self._scan_hosts_batch(hosts_to_scan)
            else:
                hosts_to_scan = list(net.hosts())
                self._scan_hosts_batch(hosts_to_scan)
            
            new_hosts_count = len([ip for ip in self.active_hosts.keys() 
                                 if ip not in self.cumulative_data['hosts']])
            self.save_scan_record(network, scan_start_time, len(self.active_hosts), new_hosts_count)
            
            self.cumulative_data['scan_history'].insert(0, {
                'network': network,
                'start_time': scan_start_time,
                'end_time': datetime.now().isoformat(),
                'hosts_found': len(self.active_hosts),
                'new_hosts': new_hosts_count,
                'status': 'completed'
            })

        except Exception as e:
            self.emit_update('scan_error', {'error': str(e)})
    
    def _scan_hosts_batch(self, hosts):
        """Scan hosts in batches with cumulative merging"""
        total = len(hosts)
        found_hosts = []

        max_threads = min(100, total if total > 0 else 1)
        chunk_size = 200
        chunks = [hosts[i:i + chunk_size] for i in range(0, len(hosts), chunk_size)]
        
        total_completed = 0
        for chunk_idx, chunk in enumerate(chunks):
            if not self.scan_active:
                break
            
            self.emit_update('scan_status', {
                'message': f'Processing batch {chunk_idx + 1}/{len(chunks)} ({len(chunk)} addresses)'
            })
            
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                future_to_ip = {executor.submit(self.ping_host, str(ip)): str(ip) for ip in chunk}
                for future in as_completed(future_to_ip):
                    if not self.scan_active:
                        break
                    ip = future_to_ip[future]
                    total_completed += 1
                    try:
                        is_alive, rtt = future.result()
                        if is_alive:
                            found_hosts.append(ip)
                            
                            is_new = ip not in self.cumulative_data['hosts']
                            status = 'NEW' if is_new else 'EXISTING'
                            
                            self.emit_update('host_found', {
                                'ip': ip, 
                                'rtt': rtt, 
                                'status': status,
                                'new': is_new
                            })
                            
                        if total_completed % 20 == 0:
                            progress = (total_completed / total) * 100
                            self.emit_update('scan_progress', {'progress': progress})
                    except:
                        pass
            time.sleep(0.05)

        if self.scan_active:
            self._analyze_found_hosts(found_hosts)
    
    def _analyze_found_hosts(self, found_hosts):
        """Analyze hosts and merge with cumulative data"""
        self.emit_update('scan_status', {'message': f'Analyzing {len(found_hosts)} hosts for cumulative topology...'})
        
        new_hosts_count = 0
        
        for i, ip in enumerate(found_hosts):
            if not self.scan_active:
                break
                
            hostname = self.get_hostname(ip)
            mac = self.get_mac_via_arp(ip)
            device_type = self._detect_device_type(hostname, ip)
            
            is_new = ip not in self.cumulative_data['hosts']
            if is_new:
                new_hosts_count += 1
            
            host_info = {
                'ip': ip,
                'hostname': hostname,
                'mac': mac,
                'device_type': device_type,
                'new': is_new,
                'scan_count': 1 if is_new else self.cumulative_data['hosts'][ip].get('scan_count', 0) + 1,
                'discovered_via': 'scan'
            }
            
            self.active_hosts[ip] = host_info
            self.cumulative_data['hosts'][ip] = host_info
            
            self.save_host_to_db(host_info, is_new)
            
            self.emit_update('host_analyzed', {
                **host_info,
                'cumulative_total': len(self.cumulative_data['hosts'])
            })
            
            progress = ((i + 1) / len(found_hosts)) * 50
            self.emit_update('analysis_progress', {'progress': progress})
        
        self.emit_update('scan_status', {'message': 'Mapping network paths (cumulative mode)...'})
        
        priority_hosts = []
        regular_hosts = []
        
        for ip in found_hosts:
            if not self.scan_active:
                break
            host_info = self.active_hosts[ip]
            if host_info['device_type'] in ['gateway', 'router'] or host_info.get('new', False):
                priority_hosts.append(ip)
            else:
                regular_hosts.append(ip)
        
        hosts_to_trace = priority_hosts + regular_hosts[:15]
        
        for i, ip in enumerate(hosts_to_trace):
            if not self.scan_active:
                break
            self.emit_update('scan_status', {'message': f'Tracing route to {ip}...'})
            route = self.traceroute_to_host(ip)
            if route:
                self.host_routes[ip] = route
                self.save_route_to_db(ip, route)
            progress = 50 + ((i + 1) / len(hosts_to_trace)) * 50
            self.emit_update('analysis_progress', {'progress': progress})
        
        self._build_cumulative_topology()
        
        self.emit_update('scan_summary', {
            'total_hosts_found': len(found_hosts),
            'new_hosts': new_hosts_count,
            'existing_hosts': len(found_hosts) - new_hosts_count,
            'cumulative_total': len(self.cumulative_data['hosts'])
        })
    
    def _detect_device_type(self, hostname, ip):
        hostname_lower = hostname.lower()
        if any(w in hostname_lower for w in ['router', 'gateway', 'gw']):
            return 'router'
        elif any(w in hostname_lower for w in ['switch', 'sw']):
            return 'switch'
        elif any(w in hostname_lower for w in ['ap', 'wifi']):
            return 'ap'
        elif ip.endswith('.1') or ip.endswith('.254'):
            return 'gateway'
        return 'host'
    
    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def _build_cumulative_topology(self):
        """Build topology using all cumulative data"""
        self.emit_update('scan_status', {'message': 'Building cumulative network topology...'})
        topology = {'nodes': [], 'links': []}
        added_nodes = set()
        
        local_ip = self._get_local_ip()
        
        local_pos = self.cumulative_data['node_positions'].get(local_ip, {})
        
        topology['nodes'].append({
            'id': local_ip,
            'ip': local_ip,
            'hostname': socket.gethostname(),
            'device_type': 'local_machine',
            'mac': None,
            'hop_distance': 0,
            'discovered': True,
            'cumulative': True,
            'scan_count': 999,
            'discovered_via': 'local',
            'x': local_pos.get('x'),
            'y': local_pos.get('y'),
            'fixed': local_pos.get('fixed', False)
        })
        added_nodes.add(local_ip)

        self.emit_update('scan_status', {'message': 'Mapping internet path...'})
        internet_hops = self.traceroute_to_host("8.8.8.8")
        
        if internet_hops:
            prev_node = local_ip
            for hop_info in internet_hops:
                hop_ip = hop_info['ip']
                hop_distance = hop_info['hop']
                
                if hop_ip not in added_nodes:
                    node_type = 'wildcard' if hop_ip == '*' else 'intermediate'
                    hop_pos = self.cumulative_data['node_positions'].get(hop_ip, {})
                    
                    topology['nodes'].append({
                        'id': hop_ip,
                        'ip': hop_ip,
                        'hostname': hop_info['hostname'],
                        'device_type': node_type,
                        'mac': None,
                        'hop_distance': hop_distance,
                        'discovered': False,
                        'rtt': hop_info['rtt'],
                        'cumulative': True,
                        'discovered_via': 'traceroute',
                        'x': hop_pos.get('x'),
                        'y': hop_pos.get('y'),
                        'fixed': hop_pos.get('fixed', False)
                    })
                    added_nodes.add(hop_ip)
                
                topology['links'].append({
                    'source': prev_node, 
                    'target': hop_ip, 
                    'type': 'internet_path',
                    'hop_number': hop_distance,
                    'rtt': hop_info['rtt'],
                    'cumulative': True
                })
                prev_node = hop_ip
            
            internet_pos = self.cumulative_data['node_positions'].get("internet", {})
            topology['nodes'].append({
                'id': "internet",
                'ip': "8.8.8.8",
                'hostname': "Internet (8.8.8.8)",
                'device_type': 'internet',
                'mac': None,
                'hop_distance': len(internet_hops) + 1,
                'discovered': False,
                'cumulative': True,
                'discovered_via': 'traceroute',
                'x': internet_pos.get('x'),
                'y': internet_pos.get('y'),
                'fixed': internet_pos.get('fixed', False)
            })
            topology['links'].append({
                'source': prev_node, 
                'target': "internet", 
                'type': 'internet_path',
                'cumulative': True
            })

        for ip, host_info in self.cumulative_data['hosts'].items():
            if ip in added_nodes:
                continue
                
            in_current_scan = ip in self.active_hosts
            
            route = self.host_routes.get(ip, [])
            if not route:
                try:
                    conn = sqlite3.connect(self.db_path)
                    cursor = conn.cursor()
                    cursor.execute('''
                        SELECT hop_number, hop_ip, hop_hostname, rtt 
                        FROM routes WHERE target_ip = ? 
                        ORDER BY hop_number
                    ''', (ip,))
                    route_rows = cursor.fetchall()
                    if route_rows:
                        route = [
                            {'hop': row[0], 'ip': row[1], 'hostname': row[2], 'rtt': row[3]}
                            for row in route_rows
                        ]
                    conn.close()
                except Exception as e:
                    print(f"Error loading route from DB: {e}")
            
            host_pos = self.cumulative_data['node_positions'].get(ip, {})
            
            if route:
                prev_node = local_ip
                for hop_info in route[:-1]:
                    hop_ip = hop_info['ip']
                    if hop_ip not in added_nodes:
                        node_type = 'wildcard' if hop_ip == '*' else 'intermediate'
                        hop_pos = self.cumulative_data['node_positions'].get(hop_ip, {})
                        
                        topology['nodes'].append({
                            'id': hop_ip,
                            'ip': hop_ip,
                            'hostname': hop_info['hostname'],
                            'device_type': node_type,
                            'mac': None,
                            'hop_distance': hop_info['hop'],
                            'discovered': False,
                            'rtt': hop_info['rtt'],
                            'cumulative': True,
                            'discovered_via': 'traceroute',
                            'x': hop_pos.get('x'),
                            'y': hop_pos.get('y'),
                            'fixed': hop_pos.get('fixed', False)
                        })
                        added_nodes.add(hop_ip)
                    
                    topology['links'].append({
                        'source': prev_node,
                        'target': hop_ip,
                        'type': 'traced_path',
                        'hop_number': hop_info['hop'],
                        'rtt': hop_info['rtt'],
                        'cumulative': True
                    })
                    prev_node = hop_ip
                
                final_hop = len(route)
                topology['nodes'].append({
                    'id': ip,
                    'ip': ip,
                    'hostname': host_info['hostname'],
                    'device_type': host_info['device_type'],
                    'mac': host_info['mac'],
                    'hop_distance': final_hop,
                    'discovered': True,
                    'new': host_info.get('new', False),
                    'current_scan': in_current_scan,
                    'scan_count': host_info.get('scan_count', 1),
                    'cumulative': True,
                    'discovered_via': host_info.get('discovered_via', 'scan'),
                    'x': host_pos.get('x'),
                    'y': host_pos.get('y'),
                    'fixed': host_pos.get('fixed', False)
                })
                
                topology['links'].append({
                    'source': prev_node,
                    'target': ip,
                    'type': 'traced_path',
                    'hop_number': final_hop,
                    'current_scan': in_current_scan,
                    'cumulative': True
                })
            else:
                topology['nodes'].append({
                    'id': ip,
                    'ip': ip,
                    'hostname': host_info['hostname'],
                    'device_type': host_info['device_type'],
                    'mac': host_info['mac'],
                    'hop_distance': 1,
                    'discovered': True,
                    'new': host_info.get('new', False),
                    'current_scan': in_current_scan,
                    'scan_count': host_info.get('scan_count', 1),
                    'cumulative': True,
                    'discovered_via': host_info.get('discovered_via', 'scan'),
                    'x': host_pos.get('x'),
                    'y': host_pos.get('y'),
                    'fixed': host_pos.get('fixed', False)
                })
                topology['links'].append({
                    'source': local_ip,
                    'target': ip,
                    'type': 'direct',
                    'hop_number': 1,
                    'current_scan': in_current_scan,
                    'cumulative': True
                })
        
        self.emit_update('cumulative_topology_ready', topology)
    
    def start_scan(self, network):
        self.scan_active = True
        self.active_hosts = {}
        self.host_routes = {}
        scan_thread = threading.Thread(target=self.discover_subnet, args=(network,))
        scan_thread.daemon = True
        scan_thread.start()
    
    def stop_scan(self):
        self.scan_active = False
    
    def clear_cumulative_data(self):
        """Clear all cumulative data"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM hosts')
            cursor.execute('DELETE FROM routes')
            cursor.execute('DELETE FROM links')
            cursor.execute('DELETE FROM scans')
            cursor.execute('DELETE FROM node_positions')
            conn.commit()
            conn.close()
            
            self.cumulative_data = {
                'hosts': {},
                'routes': {},
                'links': [],
                'scan_history': [],
                'node_positions': {}
            }
            
            self.traffic_discovered_hosts.clear()
            self.processed_gateways.clear()
            
            self.emit_update('cumulative_cleared', {'message': 'All cumulative data cleared'})
            
        except Exception as e:
            self.emit_update('scan_error', {'error': f'Error clearing data: {str(e)}'})

scanner = CumulativeTopologyScanner()

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/export')
def export_data():
    """Export scan data as JSON file"""
    try:
        include_positions = request.args.get('positions', 'true').lower() == 'true'
        export_data = scanner.export_scan_data(include_positions)
        
        if export_data is None:
            return jsonify({'error': 'Failed to export data'}), 500
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(export_data, f, indent=2)
            temp_path = f.name
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'network_topology_export_{timestamp}.json'
        
        return send_file(temp_path, as_attachment=True, download_name=filename, mimetype='application/json')
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/import', methods=['POST'])
def import_data():
    """Import scan data from JSON file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        merge_mode = request.form.get('merge', 'true').lower() == 'true'
        
        file_content = file.read().decode('utf-8')
        import_data = json.loads(file_content)
        
        result = scanner.import_scan_data(import_data, merge=merge_mode)
        
        if result['success']:
            return jsonify({
                'success': True,
                'message': f'Successfully imported {result["imported_hosts"]} hosts, {result["imported_routes"]} routes, {result["imported_scans"]} scans',
                'total_hosts': result['total_hosts']
            })
        else:
            return jsonify({'error': result['error']}), 400
            
    except json.JSONDecodeError:
        return jsonify({'error': 'Invalid JSON file format'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@socketio.on('start_scan')
def handle_start_scan(data):
    target = data.get('target', '192.168.1.0/24')
    scanner.start_scan(target)
    emit('scan_started', {'target': target})

@socketio.on('stop_scan')
def handle_stop_scan():
    scanner.stop_scan()
    emit('scan_stopped')

@socketio.on('clear_cumulative')
def handle_clear_cumulative():
    scanner.clear_cumulative_data()

@socketio.on('save_node_position')
def handle_save_node_position(data):
    """Save node position when dragged"""
    ip = data.get('ip')
    x = data.get('x')
    y = data.get('y')
    fixed = data.get('fixed', True)
    
    if ip and x is not None and y is not None:
        scanner.save_node_position(ip, x, y, fixed)

@socketio.on('start_traffic_capture')
def handle_start_traffic_capture():
    """Start real-time traffic capture"""
    scanner.start_traffic_capture()
    emit('traffic_capture_started', {'message': 'Traffic capture started with auto-discovery'})

@socketio.on('stop_traffic_capture')
def handle_stop_traffic_capture():
    """Stop real-time traffic capture"""
    scanner.stop_traffic_capture()

@socketio.on('connect')
def handle_connect():
    emit('connected')
    emit('cumulative_loaded', {
        'total_hosts': len(scanner.cumulative_data['hosts']),
        'scan_history': scanner.cumulative_data['scan_history']
    })

if __name__ == '__main__':
    os.makedirs('templates', exist_ok=True)
    print("Enhanced Cumulative Network Topology Scanner with Traffic Visualization and Auto-Discovery")
    print("=" * 90)
    print("Features:")
    print("- Cumulative scan results (like Zenmap)")
    print("- Persistent SQLite database storage")
    print("- Historical scan tracking")
    print("- Visual distinction between new/existing hosts")
    print("- Export/Import scan data functionality")
    print("- Draggable nodes with persistent positions")
    print("- Zoom and pan capabilities")
    print("- Real-time network traffic visualization")
    print("- AUTO-DISCOVERY: Hosts found in traffic are automatically added to topology")
    print("- GATEWAY EXPANSION: Automatically discovers subnet hosts when gateway is found")
    print("- PATH-AWARE TRAFFIC: Packet animations follow actual network paths")
    print("")
    print("Make sure dashboard.html is in templates/ folder")
    print("Database will be created as: network_topology.db")
    print("Starting server on http://localhost:5000")
    print("")
    print("Export/Import endpoints:")
    print("- GET /export?positions=true - Export scan data")
    print("- POST /import - Import scan data (multipart/form-data)")
    print("")
    print("Traffic Capture Requirements:")
    print("Linux/Mac: tcpdump (may require sudo or capabilities)")
    print("  Setup: sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump")
    print("Windows: windump or tshark (requires WinPcap/Npcap)")
    print("  Install: https://www.winpcap.org/ or https://nmap.org/npcap/")
    print("")
    print("NEW FEATURES:")
    print("- Traffic capture now discovers and adds new hosts automatically")
    print("- Gateway detection (.1/.254) triggers subnet expansion")
    print("- Traffic particles follow actual discovered network paths")
    print("")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
