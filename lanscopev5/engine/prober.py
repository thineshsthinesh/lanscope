# lanscope/engine/prober.py - Enhanced Version for /16 Networks

import asyncio
import logging
import time
import socket
from ipaddress import ip_address, AddressValueError, IPv4Address
from typing import Optional, List, Dict, Tuple
import subprocess
import struct

# Scapy imports with error handling
try:
    from scapy.all import conf, ARP
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, TCP, ICMP
    from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6ND_NS, ICMPv6ND_NA
    from scapy.sendrecv import sr1, sr
    SCAPY_AVAILABLE = True
except ImportError:
    logging.warning("Scapy not available, using fallback methods")
    SCAPY_AVAILABLE = False

if SCAPY_AVAILABLE:
    conf.verb = 0
    try:
        conf.use_pcap = True
    except:
        conf.use_pcap = False

# Enhanced device fingerprinting database for /16 networks
PORT_FINGERPRINTS = {
    # Web servers and HTTP services
    80: 'web_server', 443: 'web_server', 8080: 'web_server', 8443: 'web_server',
    8000: 'web_server', 8888: 'web_server', 9000: 'web_server',
    
    # SSH and remote access
    22: 'linux_server', 3389: 'windows_server', 5900: 'vnc_server', 5901: 'vnc_server',
    
    # File services
    21: 'ftp_server', 445: 'file_server', 139: 'file_server', 2049: 'nfs_server',
    135: 'windows_server', 137: 'windows_server', 138: 'windows_server',
    
    # Mail services
    25: 'mail_server', 110: 'mail_server', 143: 'mail_server', 993: 'mail_server', 995: 'mail_server',
    587: 'mail_server', 465: 'mail_server',
    
    # Network infrastructure
    53: 'dns_server', 67: 'dhcp_server', 68: 'dhcp_server', 123: 'ntp_server',
    179: 'router', 520: 'router', 521: 'router',
    
    # Database services
    3306: 'mysql_server', 5432: 'postgres_server', 1521: 'oracle_server', 1433: 'mssql_server',
    6379: 'redis_server', 27017: 'mongodb_server',
    
    # Printers and devices
    631: 'printer', 9100: 'printer', 515: 'printer', 161: 'printer',
    
    # Monitoring and management
    161: 'snmp_device', 162: 'snmp_device', 623: 'ipmi_device',
    
    # Container and virtualization
    2375: 'docker_host', 2376: 'docker_host', 6443: 'kubernetes_master',
    8001: 'kubernetes_node', 10250: 'kubernetes_node',
    
    # IoT and smart devices
    1883: 'iot_device', 8883: 'iot_device', 5683: 'iot_device',
    
    # Enterprise applications
    1099: 'java_server', 8009: 'java_server', 9080: 'java_server',
    1521: 'oracle_server', 1830: 'oracle_server'
}

class ActiveProber:
    def __init__(self, timeout=2):
        self.timeout = timeout
        
        # Port lists optimized for /16 network scanning
        self.minimal_ports = [22, 80, 443]  # Ultra-fast scan
        self.quick_ports = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 3389]  # Quick scan
        self.common_tcp_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
                                993, 995, 3389, 5900, 8080, 631, 9100]  # Standard scan
        self.comprehensive_ports = list(PORT_FINGERPRINTS.keys())  # Full scan
        
        # Connection pooling for efficiency
        self._socket_pool = {}
        
    async def resolve_mac(self, target_ip: str) -> Optional[str]:
        """Enhanced MAC address resolution with caching and multiple methods."""
        if not SCAPY_AVAILABLE:
            return await self._resolve_mac_fallback(target_ip)
            
        try:
            addr = ip_address(target_ip)
            
            if isinstance(addr, IPv4Address):
                # Use broadcast ARP for better success rate in /16 networks
                packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
                # Reduce timeout for /16 scanning
                response = await asyncio.to_thread(sr1, packet, timeout=min(self.timeout, 1), verbose=False)
                
                if response and response.haslayer(ARP):
                    return response.hwsrc.lower()
            else:
                # IPv6 neighbor discovery with reduced timeout
                packet = Ether(dst="33:33:ff:" + target_ip[-7:]) / IPv6(dst=target_ip) / ICMPv6ND_NS(tgt=target_ip)
                response = await asyncio.to_thread(sr1, packet, timeout=min(self.timeout, 1), verbose=False)
                
                if response and response.haslayer(ICMPv6ND_NA):
                    return response.lladdr.lower()
                    
        except Exception as e:
            logging.debug(f"MAC resolution for {target_ip} failed: {e}")
        
        return None

    async def _resolve_mac_fallback(self, target_ip: str) -> Optional[str]:
        """Optimized fallback MAC resolution for /16 networks."""
        try:
            # Skip ping for /16 networks to save time, go straight to ARP lookup
            proc = await asyncio.create_subprocess_exec(
                'arp', '-n', target_ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=1)
            
            if proc.returncode == 0:
                lines = stdout.decode().strip().split('\n')
                for line in lines:
                    if target_ip in line and ':' in line:
                        parts = line.split()
                        for part in parts:
                            if ':' in part and len(part) == 17:
                                return part.lower()
                                
        except Exception as e:
            logging.debug(f"Fallback MAC resolution failed for {target_ip}: {e}")
        
        return None

    async def batch_tcp_probe(self, target_ip: str, ports: List[int]) -> List[Tuple[str, int, str]]:
        """Optimized batch TCP probing for /16 networks."""
        if SCAPY_AVAILABLE:
            return await self._batch_tcp_probe_scapy(target_ip, ports)
        else:
            return await self._batch_tcp_probe_socket(target_ip, ports)

    async def _batch_tcp_probe_scapy(self, target_ip: str, ports: List[int]) -> List[Tuple[str, int, str]]:
        """Batch TCP SYN scanning with Scapy - optimized for speed."""
        results = []
        try:
            addr = ip_address(target_ip)
            base_packet = IPv6(dst=target_ip) if not isinstance(addr, IPv4Address) else IP(dst=target_ip)
            
            # Create all SYN packets at once
            syn_packets = [base_packet / TCP(dport=port, flags='S') for port in ports]
            
            # Send all packets and collect responses with reduced timeout
            responses = await asyncio.to_thread(sr, syn_packets, timeout=min(self.timeout, 0.8), verbose=False)
            answered, unanswered = responses
            
            # Process responses
            for send_packet, recv_packet in answered:
                if recv_packet.haslayer(TCP):
                    port = send_packet[TCP].dport
                    flags = recv_packet[TCP].flags
                    if flags == 0x12:  # SYN-ACK
                        results.append((target_ip, port, 'open'))
                        # Send RST to clean up
                        rst_packet = base_packet / TCP(dport=port, sport=recv_packet[TCP].dport, 
                                                     seq=recv_packet[TCP].ack, flags='R')
                        await asyncio.to_thread(sr1, rst_packet, timeout=0.1, verbose=False)
                    elif flags & 0x4:  # RST
                        results.append((target_ip, port, 'closed'))
                        
        except Exception as e:
            logging.debug(f"Batch Scapy TCP probe to {target_ip} failed: {e}")
        
        return results

    async def _batch_tcp_probe_socket(self, target_ip: str, ports: List[int]) -> List[Tuple[str, int, str]]:
        """Fast socket-based batch TCP probing."""
        results = []
        tasks = []
        
        for port in ports:
            task = self._single_socket_probe(target_ip, port)
            tasks.append(task)
        
        # Run all probes concurrently with timeout
        try:
            probe_results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=self.timeout * 2
            )
            
            for result in probe_results:
                if isinstance(result, tuple):
                    results.append(result)
                    
        except asyncio.TimeoutError:
            logging.debug(f"Batch socket probe to {target_ip} timed out")
        
        return results

    async def _single_socket_probe(self, target_ip: str, port: int) -> Optional[Tuple[str, int, str]]:
        """Single socket probe with connection pooling."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(min(self.timeout, 0.5))  # Aggressive timeout for /16
            
            result = await asyncio.to_thread(sock.connect_ex, (target_ip, port))
            sock.close()
            
            if result == 0:
                return (target_ip, port, 'open')
            else:
                return (target_ip, port, 'closed')
                
        except Exception as e:
            logging.debug(f"Socket probe to {target_ip}:{port} failed: {e}")
        
        return None

    async def probe_icmp_echo(self, target_ip: str) -> bool:
        """Ultra-fast ICMP probe for /16 networks."""
        if SCAPY_AVAILABLE:
            return await self._probe_icmp_scapy_fast(target_ip)
        else:
            return await self._probe_icmp_ping_fast(target_ip)

    async def _probe_icmp_scapy_fast(self, target_ip: str) -> bool:
        """Fast Scapy ICMP probe with aggressive timeout."""
        try:
            addr = ip_address(target_ip)
            
            if isinstance(addr, IPv4Address):
                packet = IP(dst=target_ip) / ICMP()
            else:
                packet = IPv6(dst=target_ip) / ICMPv6EchoRequest()
                
            response = await asyncio.to_thread(sr1, packet, timeout=min(self.timeout, 0.3), verbose=False)
            return response is not None
            
        except Exception as e:
            logging.debug(f"Fast Scapy ICMP probe to {target_ip} failed: {e}")
        
        return False

    async def _probe_icmp_ping_fast(self, target_ip: str) -> bool:
        """Ultra-fast ping probe for /16 networks."""
        try:
            proc = await asyncio.create_subprocess_exec(
                'ping', '-c', '1', '-W', '1', '-i', '0.2', target_ip,  # Very aggressive timing
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            returncode = await asyncio.wait_for(proc.wait(), timeout=1.5)
            return returncode == 0
            
        except Exception as e:
            logging.debug(f"Fast ping probe to {target_ip} failed: {e}")
        
        return False

    async def quick_host_discovery(self, target_ip: str) -> Dict:
        """Ultra-quick host discovery for /16 initial sweep."""
        scan_start = time.time()
        results = {
            'ip': target_ip,
            'status': 'down',
            'method': 'quick',
            'scan_time': scan_start
        }

        # Try the fastest methods first
        methods = [
            ('mac', self.resolve_mac(target_ip)),
            ('icmp', self.probe_icmp_echo(target_ip)),
            ('tcp', self.batch_tcp_probe(target_ip, self.minimal_ports))
        ]

        # Run methods concurrently but stop at first success
        for method_name, coro in methods:
            try:
                result = await asyncio.wait_for(coro, timeout=0.5)
                if method_name == 'mac' and result:
                    results['status'] = 'up'
                    results['mac'] = result
                    break
                elif method_name == 'icmp' and result:
                    results['status'] = 'up'
                    break
                elif method_name == 'tcp' and result:
                    open_ports = [r for r in result if r[2] == 'open']
                    if open_ports:
                        results['status'] = 'up'
                        results['open_ports'] = [{'port': r[1], 'protocol': 'tcp', 'state': 'open'} for r in open_ports]
                        break
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logging.debug(f"Quick discovery method {method_name} failed for {target_ip}: {e}")
                continue

        results['scan_duration'] = time.time() - scan_start
        return results

    async def comprehensive_scan(self, target_ip: str, quick_scan: bool = False) -> Dict:
        """Enhanced comprehensive scan with adaptive port selection."""
        scan_start = time.time()
        results = {
            'ip': target_ip,
            'status': 'down',
            'mac': None,
            'open_ports': [],
            'scan_time': scan_start,
            'scan_type': 'quick' if quick_scan else 'comprehensive'
        }

        # For /16 networks, use quick scan by default for most hosts
        if quick_scan:
            return await self.quick_host_discovery(target_ip)

        # Step 1: Try to resolve MAC address (fastest indicator)
        mac_address = await self.resolve_mac(target_ip)
        if mac_address:
            results['status'] = 'up'
            results['mac'] = mac_address

        # Step 2: ICMP ping if MAC resolution failed
        if results['status'] == 'down':
            if await self.probe_icmp_echo(target_ip):
                results['status'] = 'up'

        # Step 3: TCP port scanning for live hosts
        if results['status'] == 'up':
            # Select port list based on scan type
            ports_to_scan = self.quick_ports if quick_scan else self.common_tcp_ports
            
            # Batch TCP probe for efficiency
            tcp_results = await self.batch_tcp_probe(target_ip, ports_to_scan)
            
            open_ports = []
            for result in tcp_results:
                if result and result[2] == 'open':
                    port_info = {
                        'port': result[1],
                        'protocol': 'tcp',
                        'state': 'open',
                        'service': self.get_service_info(result[1])
                    }
                    open_ports.append(port_info)
            
            results['open_ports'] = open_ports
            
            # Enhanced device fingerprinting
            results['device_type'] = self.fingerprint_device_enhanced(results)
            
            # If we found interesting services, do a more detailed scan
            if len(open_ports) > 3 and not quick_scan:
                additional_ports = [p for p in self.comprehensive_ports if p not in ports_to_scan][:10]
                if additional_ports:
                    additional_results = await self.batch_tcp_probe(target_ip, additional_ports)
                    for result in additional_results:
                        if result and result[2] == 'open':
                            port_info = {
                                'port': result[1],
                                'protocol': 'tcp',
                                'state': 'open',
                                'service': self.get_service_info(result[1])
                            }
                            results['open_ports'].append(port_info)
                    
                    # Re-fingerprint with additional port info
                    results['device_type'] = self.fingerprint_device_enhanced(results)

        results['scan_duration'] = time.time() - scan_start
        return results

    def fingerprint_device_enhanced(self, scan_result: Dict) -> str:
        """Enhanced device fingerprinting with better accuracy for /16 networks."""
        open_ports = scan_result.get('open_ports', [])
        mac = scan_result.get('mac', '')
        
        # Port-based fingerprinting with scoring system
        device_scores = {}
        service_indicators = {}
        
        for port_info in open_ports:
            port = port_info.get('port')
            if port in PORT_FINGERPRINTS:
                device_type = PORT_FINGERPRINTS[port]
                device_scores[device_type] = device_scores.get(device_type, 0) + 1
                
                # Track specific service indicators
                service = port_info.get('service', {}).get('service', '')
                if service:
                    service_indicators[service] = service_indicators.get(service, 0) + 1

        # Enhanced scoring based on port combinations
        if device_scores:
            # Special logic for common combinations
            port_numbers = [p['port'] for p in open_ports]
            
            # Web server detection
            if any(p in [80, 443, 8080, 8443] for p in port_numbers):
                if any(p in [22, 3389] for p in port_numbers):
                    return 'web_server'
            
            # Database server detection
            db_ports = [3306, 5432, 1521, 1433, 6379, 27017]
            if any(p in db_ports for p in port_numbers):
                return next((PORT_FINGERPRINTS[p] for p in port_numbers if p in db_ports), 'database_server')
            
            # Network infrastructure
            if 53 in port_numbers and len(port_numbers) <= 3:
                return 'dns_server'
            
            # Return highest scoring device type
            return max(device_scores, key=device_scores.get)

        # MAC-based fingerprinting fallback
        if mac:
            mac_prefix = mac[:8].lower()
            vendor_device_map = {
                '00:0c:29': 'virtual_machine',  # VMware
                '08:00:27': 'virtual_machine',  # VirtualBox
                'b8:27:eb': 'embedded_device',  # Raspberry Pi
                '00:1b:0d': 'router',           # Cisco
                '00:04:23': 'router',           # Netgear
                '18:b4:30': 'smart_device',     # Amazon
                '00:17:88': 'smart_device',     # Philips
            }
            
            if mac_prefix in vendor_device_map:
                return vendor_device_map[mac_prefix]

        # Default classification based on scan characteristics
        if scan_result.get('status') == 'up':
            port_count = len(open_ports)
            if port_count == 0:
                return 'firewall_device'
            elif port_count == 1:
                return 'specialized_device'
            elif port_count <= 3:
                return 'computer'
            else:
                return 'server'

        return 'unknown'

    async def traceroute_optimized(self, target_ip: str, max_hops: int = 10) -> List[str]:
        """Optimized traceroute for /16 networks with reduced overhead."""
        if not SCAPY_AVAILABLE:
            return await self._traceroute_system_fast(target_ip, max_hops)
            
        hops = []
        try:
            addr = ip_address(target_ip)
            if not isinstance(addr, IPv4Address):
                return []

            # Use smaller timeout and fewer hops for /16 networks
            for ttl in range(1, min(max_hops, 8) + 1):
                packet = IP(dst=target_ip, ttl=ttl) / ICMP()
                response = await asyncio.to_thread(sr1, packet, timeout=0.3, verbose=False)

                if response is None:
                    continue
                    
                if response.haslayer(ICMP):
                    icmp_type = response[ICMP].type
                    icmp_code = response[ICMP].code
                    
                    # Time exceeded (router response)
                    if icmp_type == 11 and icmp_code == 0:
                        router_ip = response.src
                        if router_ip not in hops and router_ip != target_ip:
                            hops.append(router_ip)
                        continue
                        
                    # Echo reply (reached destination)
                    elif icmp_type == 0:
                        if response.src not in hops:
                            hops.append(response.src)
                        break
                        
        except Exception as e:
            logging.debug(f"Optimized traceroute to {target_ip} failed: {e}")
        
        return hops

    async def _traceroute_system_fast(self, target_ip: str, max_hops: int) -> List[str]:
        """Fast system traceroute with aggressive timeouts."""
        hops = []
        try:
            proc = await asyncio.create_subprocess_exec(
                'traceroute', '-n', '-m', str(max_hops), '-w', '1', '-q', '1', target_ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=max_hops + 5)
            
            if proc.returncode == 0:
                lines = stdout.decode().strip().split('\n')[1:]  # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 2:
                        hop_ip = parts[1]
                        if self._is_valid_ip(hop_ip) and hop_ip not in hops:
                            hops.append(hop_ip)
                            
        except Exception as e:
            logging.debug(f"Fast system traceroute to {target_ip} failed: {e}")
        
        return hops

    def _is_valid_ip(self, ip_str: str) -> bool:
        """Check if string is a valid IP address."""
        try:
            ip_address(ip_str)
            return True
        except ValueError:
            return False

    def get_service_info(self, port: int) -> Dict:
        """Get enhanced service information for a given port."""
        service_info = {
            # Web services
            80: {'service': 'HTTP', 'description': 'Web Server', 'category': 'web'},
            443: {'service': 'HTTPS', 'description': 'Secure Web Server', 'category': 'web'},
            8080: {'service': 'HTTP-Alt', 'description': 'Alternative Web Server', 'category': 'web'},
            8443: {'service': 'HTTPS-Alt', 'description': 'Alternative Secure Web', 'category': 'web'},
            
            # Remote access
            22: {'service': 'SSH', 'description': 'Secure Shell', 'category': 'remote'},
            3389: {'service': 'RDP', 'description': 'Remote Desktop', 'category': 'remote'},
            5900: {'service': 'VNC', 'description': 'Virtual Network Computing', 'category': 'remote'},
            
            # File services
            21: {'service': 'FTP', 'description': 'File Transfer Protocol', 'category': 'file'},
            445: {'service': 'SMB', 'description': 'Windows File Sharing', 'category': 'file'},
            2049: {'service': 'NFS', 'description': 'Network File System', 'category': 'file'},
            
            # Mail services
            25: {'service': 'SMTP', 'description': 'Mail Server', 'category': 'mail'},
            587: {'service': 'SMTP-Sub', 'description': 'Mail Submission', 'category': 'mail'},
            993: {'service': 'IMAPS', 'description': 'Secure IMAP', 'category': 'mail'},
            
            # Databases
            3306: {'service': 'MySQL', 'description': 'MySQL Database', 'category': 'database'},
            5432: {'service': 'PostgreSQL', 'description': 'PostgreSQL Database', 'category': 'database'},
            1521: {'service': 'Oracle', 'description': 'Oracle Database', 'category': 'database'},
            
            # Network services
            53: {'service': 'DNS', 'description': 'Domain Name System', 'category': 'network'},
            67: {'service': 'DHCP', 'description': 'Dynamic Host Config', 'category': 'network'},
            161: {'service': 'SNMP', 'description': 'Network Management', 'category': 'network'}
        }
        
        return service_info.get(port, {
            'service': f'Port {port}', 
            'description': 'Unknown Service',
            'category': 'unknown'
        })