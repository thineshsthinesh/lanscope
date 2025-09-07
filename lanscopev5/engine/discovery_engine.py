# lanscope/engine/discovery_engine.py - Enhanced Version with Full Network Scanning

import asyncio
import logging
import time
from ipaddress import ip_network, ip_address
import random
import math
from collections import defaultdict
from .prober import ActiveProber

class DiscoveryEngine:
    def __init__(self, socketio, interface: str, subnet: str, full_scan: bool = True, max_hosts: int = 65535):
        self.socketio = socketio
        self.interface = interface
        self.subnet = ip_network(subnet)
        self.prober = ActiveProber(timeout=0.5)
        self.is_running = False
        self.is_cancelled = False
        self.discovered_devices = {}
        self.scan_start_time = None
        self.topology_map = {}
        self.scan_phase = "initializing"
        self.total_hosts_to_scan = 0
        self.hosts_scanned = 0
        self.full_scan = full_scan
        self.max_hosts = max_hosts
        
        # Full scan configuration - no limitations
        self.config = self._get_full_scan_config()
        
        try:
            # Use the network address as gateway (first host IP)
            self.gateway_ip = str(next(self.subnet.hosts()))
        except StopIteration:
            self.gateway_ip = str(self.subnet.network_address)

    def _get_full_scan_config(self):
        """Get configuration for full network scanning without limitations."""
        subnet_size = self.subnet.num_addresses
        
        if self.full_scan:
            # Full scan configuration - scan ALL hosts
            return {
                'max_hosts': min(self.max_hosts, subnet_size - 2),  # All hosts except network and broadcast
                'concurrent_limit': 150,  # Increased for faster scanning
                'progress_update_interval': 100,  # Update every 100 hosts
                'batch_size': 500,  # Larger batches for efficiency
                'use_intelligent_sampling': False,
                'scan_all_hosts': True
            }
        else:
            # Quick scan fallback
            return {
                'max_hosts': min(5000, subnet_size - 2),
                'concurrent_limit': 75,
                'progress_update_interval': 50,
                'batch_size': 200,
                'use_intelligent_sampling': True,
                'scan_all_hosts': False
            }

    def _get_device_icon_data(self, device_type: str) -> str:
        """Get SVG icon data URI for device type."""
        icons = {
            'router': 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0yMSw3SDE4VjJIMTZWN0gzVjlIMTZWMTJIMTNWMTRIMTBWMTlIOFYxNEg1VjEySDNWMTdIMjFWMTVIMThWMTJIMjFWMTBIMTZWOUgyMVY3WiIvPjwvc3ZnPg==',
            'gateway': 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xNSwxOFYyMEg5VjE4SDE1TTIxLDE2SDNWNEgyMVYxNk0yMSwySDNDMS44OSwyIDEsMi44OSAxLDRWMTZDMSwxNy4xMSAxLjg5LDE4IDMsMThaIi8+PC9zdmc+',
            'computer': 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0yMCwxOEg0VjZIMjBNMjAsNEg0QTIsMiAwIDAsMCAyLDZWMThBMiwyIDAgMCwwIDQsMjBIMjBBMiwyIDAgMCwwIDIyLDE4VjZBMiwyIDAgMCwwIDIwLDRaIi8+PC9zdmc+',
            'web_server': 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik00LDE2VjEzSDExVjE2UzExLDE4IDEzLDE4IDEzLDE2IDEzLDE2VjEzSDIwVjE2UzIwLDE4IDIyLDE4UzIyLDE2IDIyLDE2VjEzQTIsMiAwIDAsMCAyMCwxMUgxOFY5QzE4LDYuNzkgMTYuMjEsNSAxNCw1SDEwQzEyLjc5LDUgMTUsNi43OSAxNSw5VjExSDEzVjlIMTFWMTFIOUM2Ljc5LDExIDUsMTIuNzkgNSwxNVoiLz48L3N2Zz4=',
            'printer': 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xOCwzSDZWN0gxOE0xOSwxMkExLDEgMCAwLDEgMTgsMTFBMSwxIDAgMCwxIDE5LDEwQTEsMSAwIDAsMSAyMCwxMUExLDEgMCAwLDEgMTksMTJNMTYsMTlIOFYxNEgxNk0xOSw4SDVBM0EzIDAgMCwwIDIsMTFWMTdINlYyMUgxOFYxN0gyMlYxMUEzLDMgMCAwLDAgMTksOFoiLz48L3N2Zz4=',
            'linux_server': 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xNC42MiwxMi41QzE0LjIxLDEyLjMxIDEzLjc2LDEyLjQ0IDEzLjU3LDEyLjg1QzEzLjM4LDEzLjI3IDEzLjUxLDEzLjcxIDEzLjkyLDEzLjlMMTYuNDcsMTVDMTYuNzYsMTUuMTEgMTcuMDMsMTUuMDEgMTcuMjIsMTQuODAyTDE4LjgyLDEzQzE4LjkzLDEyLjg0IDE4Ljk0LDEyLjY0IDE4Ljg0LDEyLjQ3QzE4Ljc0LDEyLjMxIDE4LjU1LDEyLjIzIDE4LjM2LDEyLjI5TDE0LjYyLDEyLjVaTTEyLDE2QzEwLjM0LDE2IDkuNSwxNC42NSA5LjUsMTNTMTAuMzQsMTAgMTIsMTBTMTQuNSwxMS4zNSAxNC41LDEzUzEzLjY2LDE2IDEyLDE2WiIvPjwvc3ZnPg==',
            'windows_server': 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0zLDEyVjYuNzVMMTAuNSw5LjVWMTZMMywxMy4yNVYxMk0yMSw2Ljc1VjEyTDEzLjUsMTZWOS41TDIxLDYuNzVaIi8+PC9zdmc+',
            'smart_device': 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xNywxN0g3VjdIMTdNMTQsM0g1QzMuODksMyAzLDMuODkgMyw1VjE5QTIsIDIgMCAwLDAgNSwyMUgxOUEyLDIgMCAwLDAgMjEsMTlWMTBMMTQsM1oiLz48L3N2Zz4=',
            'unknown': 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xMSwySDEzVjRIMTFNMTIsNy41QTQuNSw0LjUgMCAwLDEgMTYuNSwxMkE0LjUsNC41IDAgMCwxIDEyLDE2LjVBNC41LDQuNSAwIDAsMSA3LjUsMTJBNC41LDQuNSAwIDAsMSAxMiw3LjVNMTIsMTNBMSwxIDAgMCwwIDEzLDEyQTEsMSAwIDAsMCAxMiwxMUExLDEgMCAwLDAgMTEsMTJBMSwxIDAgMCwwIDEyLDEzWiIvPjwvc3ZnPg=='
        }
        return icons.get(device_type, icons['unknown'])

    def _get_all_hosts_to_scan(self):
        """Get ALL hosts to scan - no sampling, no limitations."""
        if self.config['scan_all_hosts']:
            # Get ALL hosts in the subnet
            all_hosts = list(self.subnet.hosts())
            total_hosts = len(all_hosts)
            
            # Apply max_hosts limit if specified and less than total
            if self.config['max_hosts'] < total_hosts:
                hosts_to_scan = all_hosts[:self.config['max_hosts']]
                logging.info(f"Full scan limited to first {self.config['max_hosts']} hosts of {total_hosts} total")
            else:
                hosts_to_scan = all_hosts
                logging.info(f"Full network scan: scanning ALL {len(hosts_to_scan)} hosts")
            
            # Sort by IP address for systematic scanning
            hosts_to_scan.sort(key=lambda ip: int(ip_address(str(ip))))
            
            return hosts_to_scan
        else:
            # Fallback to intelligent sampling if full scan is disabled
            return self._intelligent_subnet_sampling(self.subnet, self.config['max_hosts'])

    def _intelligent_subnet_sampling(self, subnet, max_hosts=5000):
        """Fallback intelligent sampling - only used if full_scan is False."""
        all_hosts = list(subnet.hosts())
        total_hosts = len(all_hosts)
        
        if total_hosts <= max_hosts:
            return all_hosts
            
        logging.info(f"Using intelligent sampling: {max_hosts} hosts from {total_hosts} total")
        
        # Simple intelligent sampling
        sample_hosts = set()
        
        # Priority 1: First 100 hosts (infrastructure)
        sample_hosts.update(all_hosts[:100])
        
        # Priority 2: Last 100 hosts (high-value range)
        sample_hosts.update(all_hosts[-100:])
        
        # Priority 3: Random sampling for remainder
        remaining_quota = max_hosts - len(sample_hosts)
        if remaining_quota > 0:
            remaining_hosts = [h for h in all_hosts if h not in sample_hosts]
            if remaining_hosts:
                additional_samples = random.sample(
                    remaining_hosts, 
                    min(remaining_quota, len(remaining_hosts))
                )
                sample_hosts.update(additional_samples)
        
        sample_list = list(sample_hosts)
        sample_list.sort(key=lambda ip: int(ip_address(str(ip))))
        
        return sample_list

    def _build_hierarchical_topology(self, scan_result: dict, hops: list):
        """Build hierarchical network topology."""
        ip = scan_result.get('ip')
        if not ip:
            return []
        
        elements = []
        
        # Create subnet-based hierarchy
        try:
            ip_obj = ip_address(ip)
            subnet_24 = ip_network(f"{ip}/24", strict=False)
            subnet_gateway = str(next(subnet_24.hosts()))
            
            # Create subnet identifier for grouping
            subnet_id = str(subnet_24.network_address)
            
            # Add subnet gateway if not exists
            if subnet_gateway not in self.topology_map:
                elements.append({
                    'group': 'nodes',
                    'data': {
                        'id': subnet_gateway,
                        'label': f"GW\n.{subnet_gateway.split('.')[-1]}",
                        'device_type': 'gateway',
                        'status': 'inferred',
                        'subnet': str(subnet_24),
                        'subnet_gateway': True,
                        'icon': self._get_device_icon_data('gateway')
                    }
                })
                
                # Connect subnet gateway to main gateway if different subnets
                main_subnet = ip_network(f"{self.gateway_ip}/24", strict=False)
                if subnet_24 != main_subnet:
                    elements.append({
                        'group': 'edges',
                        'data': {
                            'id': f"{self.gateway_ip}-{subnet_gateway}",
                            'source': self.gateway_ip,
                            'target': subnet_gateway,
                            'connection_type': 'inter_subnet',
                            'label': 'L3',
                            'subnet_connection': True
                        }
                    })
                
                self.topology_map[subnet_gateway] = subnet_24
            
            # Connect device to its subnet gateway
            if ip != subnet_gateway:
                elements.append({
                    'group': 'edges',
                    'data': {
                        'id': f"{subnet_gateway}-{ip}",
                        'source': subnet_gateway,
                        'target': ip,
                        'connection_type': 'subnet_local',
                        'label': 'L2'
                    }
                })
            
        except Exception as e:
            logging.debug(f"Topology building error for {ip}: {e}")
            # Fallback to direct connection
            elements.append({
                'group': 'edges',
                'data': {
                    'id': f"{self.gateway_ip}-{ip}",
                    'source': self.gateway_ip,
                    'target': ip,
                    'connection_type': 'direct',
                    'label': 'Direct'
                }
            })
        
        return elements

    def _format_scan_result(self, scan_result: dict, hops: list) -> list:
        """Format scan results with enhanced device information."""
        elements = []
        ip = scan_result.get('ip')
        
        if not ip:
            return elements

        # Store device info
        self.discovered_devices[ip] = scan_result

        # Create device node
        device_type = scan_result.get('device_type', 'computer')
        device_label = self._create_device_label(scan_result)
        
        elements.append({
            'group': 'nodes',
            'data': {
                'id': ip,
                'label': device_label,
                'status': scan_result.get('status', 'down'),
                'mac': scan_result.get('mac'),
                'open_ports': scan_result.get('open_ports', []),
                'device_type': device_type,
                'last_seen': time.time(),
                'scan_duration': scan_result.get('scan_duration', 0),
                'subnet_info': self._get_subnet_info(ip),
                'icon': self._get_device_icon_data(device_type)
            }
        })

        # Build topology
        topology_elements = self._build_hierarchical_topology(scan_result, hops)
        elements.extend(topology_elements)

        return elements

    def _create_device_label(self, scan_result: dict) -> str:
        """Create device labels."""
        ip = scan_result.get('ip', 'Unknown')
        device_type = scan_result.get('device_type', 'computer')
        
        # Show last octet for most devices
        octets = ip.split('.')
        if len(octets) == 4:
            short_ip = octets[3]
            
            if device_type == 'gateway':
                return f"GW\n{short_ip}"
            elif device_type == 'router':
                return f"RTR\n{short_ip}"
            elif device_type in ['web_server', 'linux_server', 'windows_server']:
                return f"SRV\n{short_ip}"
            else:
                return short_ip
        
        return ip.split('.')[-1] if '.' in ip else ip

    def _get_subnet_info(self, ip: str) -> dict:
        """Get subnet information for an IP address."""
        try:
            ip_obj = ip_address(ip)
            subnet_24 = ip_network(f"{ip}/24", strict=False)
            return {
                'subnet_24': str(subnet_24),
                'third_octet': ip.split('.')[2],
                'fourth_octet': ip.split('.')[3]
            }
        except:
            return {}

    async def _scan_host_and_emit(self, ip, scan_type='comprehensive'):
        """Scan individual host and emit results."""
        ip_str = str(ip)
        scan_start = time.time()
        
        try:
            # Check for cancellation
            if self.is_cancelled:
                return
                
            # Progress reporting
            self.hosts_scanned += 1
            if self.hosts_scanned % self.config['progress_update_interval'] == 0:
                progress_pct = (self.hosts_scanned / self.total_hosts_to_scan) * 100
                subnet_info = self._get_subnet_info(ip_str)
                
                self.socketio.emit('scan_progress', {
                    'current_ip': ip_str,
                    'subnet': subnet_info.get('subnet_24', 'Unknown'),
                    'progress_percentage': progress_pct,
                    'hosts_scanned': self.hosts_scanned,
                    'total_hosts': self.total_hosts_to_scan,
                    'devices_found': len(self.discovered_devices),
                    'phase': self.scan_phase,
                    'message': f'Full scan: {self.hosts_scanned}/{self.total_hosts_to_scan} hosts'
                })
            
            # Perform comprehensive scan on every host
            result = await self.prober.comprehensive_scan(ip_str, quick_scan=False)
            scan_duration = time.time() - scan_start
            result['scan_duration'] = scan_duration
            
            if result.get('status') == 'up':
                logging.info(f"Found live host: {ip_str} ({result.get('device_type', 'unknown')})")
                
                # Traceroute for topology mapping
                hops = []
                if len(result.get('open_ports', [])) > 0 or result.get('device_type') in ['router', 'gateway']:
                    hops = await self.prober.traceroute_optimized(ip_str, max_hops=8)
                
                # Format and emit results
                scan_elements = self._format_scan_result(result, hops)
                
                if scan_elements:
                    self.socketio.emit('update_graph', scan_elements)
                    
                    # Emit device discovered event
                    subnet_info = self._get_subnet_info(ip_str)
                    self.socketio.emit('device_discovered', {
                        'ip': ip_str,
                        'device_type': result.get('device_type'),
                        'status': result.get('status'),
                        'ports': len(result.get('open_ports', [])),
                        'scan_duration': scan_duration,
                        'subnet': subnet_info.get('subnet_24'),
                        'subnet_position': f"{subnet_info.get('third_octet', '?')}.{subnet_info.get('fourth_octet', '?')}"
                    })
                    
        except Exception as e:
            logging.error(f"Error scanning host {ip_str}: {e}")

    async def _full_network_scan(self):
        """Full network scanning without limitations."""
        self.scan_start_time = time.time()
        
        # Get ALL hosts to scan
        hosts_to_scan = self._get_all_hosts_to_scan()
        self.total_hosts_to_scan = len(hosts_to_scan)
        
        logging.info(f"Starting FULL network scan for {self.subnet} "
                    f"({self.total_hosts_to_scan} hosts)")
        
        # Emit scan start event
        self.socketio.emit('scan_started', {
            'subnet': str(self.subnet),
            'total_hosts': self.total_hosts_to_scan,
            'total_possible_hosts': self.subnet.num_addresses - 2,
            'start_time': self.scan_start_time,
            'scan_type': 'full_comprehensive',
            'full_scan': True,
            'expected_duration': math.ceil(self.total_hosts_to_scan / self.config['concurrent_limit'] * 0.5)
        })

        # Add main gateway
        gateway_element = {
            'group': 'nodes',
            'data': {
                'id': self.gateway_ip,
                'label': f"Main GW\n{self.gateway_ip.split('.')[3]}",
                'device_type': 'gateway',
                'status': 'up',
                'is_main_gateway': True,
                'subnet_info': self._get_subnet_info(self.gateway_ip),
                'icon': self._get_device_icon_data('gateway')
            }
        }
        self.socketio.emit('update_graph', [gateway_element])

        # Full comprehensive scan of ALL hosts
        self.scan_phase = "full_network_scan"
        
        logging.info(f"Comprehensive scan of ALL {len(hosts_to_scan)} hosts")
        await self._concurrent_scan_batch(hosts_to_scan, 'comprehensive')

        # Final statistics
        await self._emit_final_statistics()

    async def _concurrent_scan_batch(self, hosts, scan_type):
        """Process host scanning in concurrent batches."""
        semaphore = asyncio.Semaphore(self.config['concurrent_limit'])
        
        async def limited_scan(ip):
            async with semaphore:
                if not self.is_cancelled:
                    await self._scan_host_and_emit(ip, scan_type)
        
        # Process in batches to avoid overwhelming the system
        batch_size = self.config['batch_size']
        
        for i in range(0, len(hosts), batch_size):
            if self.is_cancelled:
                break
                
            batch = hosts[i:i + batch_size]
            tasks = [limited_scan(ip) for ip in batch]
            
            # Process batch with cancellation support
            try:
                for task in asyncio.as_completed(tasks):
                    if self.is_cancelled:
                        break
                    await task
            except Exception as e:
                logging.error(f"Batch scan task failed: {e}")
            
            # Small delay between batches
            if i + batch_size < len(hosts) and not self.is_cancelled:
                await asyncio.sleep(0.05)

    async def _emit_final_statistics(self):
        """Emit comprehensive final statistics."""
        scan_duration = time.time() - self.scan_start_time
        online_devices = len([d for d in self.discovered_devices.values() if d.get('status') == 'up'])
        total_ports = sum(len(d.get('open_ports', [])) for d in self.discovered_devices.values())
        
        # Calculate subnet distribution
        subnet_distribution = defaultdict(int)
        device_type_distribution = defaultdict(int)
        
        for device in self.discovered_devices.values():
            if device.get('status') == 'up':
                subnet_info = self._get_subnet_info(device.get('ip', ''))
                subnet_24 = subnet_info.get('subnet_24', 'unknown')
                subnet_distribution[subnet_24] += 1
                
                device_type = device.get('device_type', 'unknown')
                device_type_distribution[device_type] += 1

        # Find most active subnets
        top_subnets = sorted(subnet_distribution.items(), key=lambda x: x[1], reverse=True)[:10]
        
        self.socketio.emit('scan_completed', {
            'duration': scan_duration,
            'total_scanned': self.total_hosts_to_scan,
            'total_possible_hosts': self.subnet.num_addresses - 2,
            'devices_found': len(self.discovered_devices),
            'online_devices': online_devices,
            'total_open_ports': total_ports,
            'scan_efficiency': f"{online_devices}/{self.total_hosts_to_scan}",
            'hosts_per_second': self.total_hosts_to_scan / scan_duration,
            'subnet_distribution': dict(subnet_distribution),
            'device_type_distribution': dict(device_type_distribution),
            'top_active_subnets': top_subnets,
            'coverage_percentage': 100.0 if self.config['scan_all_hosts'] else (self.total_hosts_to_scan / (self.subnet.num_addresses - 2)) * 100,
            'end_time': time.time(),
            'scan_type': 'full_comprehensive',
            'network_summary': {
                'subnet_prefix': str(self.subnet),
                'subnets_with_devices': len(subnet_distribution),
                'average_devices_per_active_subnet': online_devices / max(len(subnet_distribution), 1),
                'total_hosts_scanned': self.total_hosts_to_scan,
                'scan_was_comprehensive': True
            }
        })

        status_msg = "CANCELLED" if self.is_cancelled else "COMPLETED"
        logging.info(f"Full network scan {status_msg} in {scan_duration:.2f}s - "
                    f"Scanned {self.hosts_scanned}/{self.total_hosts_to_scan} hosts, "
                    f"found {online_devices} devices across {len(subnet_distribution)} subnets")

    def cancel_scan(self):
        """Cancel the running scan."""
        logging.info("Scan cancellation requested")
        self.is_cancelled = True

    def run(self):
        """Run the full network discovery engine."""
        if self.is_running:
            logging.warning("Discovery engine is already running")
            return

        self.is_running = True
        self.is_cancelled = False
        
        try:
            asyncio.run(self._full_network_scan())
        except Exception as e:
            logging.error(f"Critical error in discovery engine: {e}")
            self.socketio.emit('scan_error', {'error': f'Discovery engine failed: {str(e)}'})
        finally:
            self.is_running = False
            logging.info("Full network discovery engine scan completed")