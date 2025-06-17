import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import ARP, Ether
import threading
import time
from datetime import datetime
from typing import Dict, List, Any, Callable, Optional
import logging
import psutil
import socket

class PacketSniffer:
    def __init__(self, config: Dict[str, Any], mongo_handler, rule_engine=None, anomaly_detector=None, cve_checker=None):
        self.config = config
        self.mongo_handler = mongo_handler
        self.rule_engine = rule_engine
        self.anomaly_detector = anomaly_detector
        self.cve_checker = cve_checker
        
        self.interface = config.get('sniffing', {}).get('interface', 'auto')
        self.packet_limit = config.get('sniffing', {}).get('packet_limit', 10000)
        self.timeout = config.get('sniffing', {}).get('timeout', 30)
        
        self.is_running = False
        self.sniff_thread = None
        self.packet_count = 0
        self.callbacks = []
        
        self.logger = logging.getLogger(__name__)
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'protocols': {},
            'src_ips': {},
            'dst_ips': {},
            'ports': {},
            'alerts': 0,
            'anomalies': 0
        }
        
        # ARP table for spoofing detection
        self.arp_table = {}
        
        # Connection tracking for port scan detection
        self.connections = {}
        self.connection_timeout = 300  # 5 minutes
    
    def get_available_interfaces(self) -> List[str]:
        """Get list of available network interfaces"""
        try:
            interfaces = []
            for interface_name, interface_info in psutil.net_if_addrs().items():
                if any(addr.family == socket.AF_INET for addr in interface_info):
                    interfaces.append(interface_name)
            return interfaces
        except Exception as e:
            self.logger.error(f"Error getting interfaces: {e}")
            return ['eth0', 'wlan0', 'lo']  # Default fallback
    
    def auto_select_interface(self) -> str:
        """Automatically select the best network interface"""
        try:
            # Get interface statistics
            stats = psutil.net_io_counters(pernic=True)
            
            # Find interface with most traffic (excluding loopback)
            best_interface = None
            max_bytes = 0
            
            for interface_name, interface_stats in stats.items():
                if interface_name.startswith('lo'):
                    continue
                
                total_bytes = interface_stats.bytes_sent + interface_stats.bytes_recv
                if total_bytes > max_bytes:
                    max_bytes = total_bytes
                    best_interface = interface_name
            
            return best_interface or 'eth0'
            
        except Exception as e:
            self.logger.error(f"Error auto-selecting interface: {e}")
            return 'eth0'
    
    def add_callback(self, callback: Callable[[Dict[str, Any]], None]):
        """Add callback function to be called for each packet"""
        self.callbacks.append(callback)
    
    def start_sniffing(self, interface: str = None):
        """Start packet sniffing in a separate thread"""
        if self.is_running:
            self.logger.warning("Packet sniffing is already running")
            return
        
        if interface:
            self.interface = interface
        elif self.interface == 'auto':
            self.interface = self.auto_select_interface()
        
        self.is_running = True
        self.packet_count = 0
        
        self.logger.info(f"Starting packet sniffing on interface: {self.interface}")
        
        self.sniff_thread = threading.Thread(target=self._sniff_packets, daemon=True)
        self.sniff_thread.start()
    
    def stop_sniffing(self):
        """Stop packet sniffing"""
        self.is_running = False
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=5)
        self.logger.info("Packet sniffing stopped")
    
    def _sniff_packets(self):
        """Main packet sniffing loop"""
        try:
            scapy.sniff(
                iface=self.interface,
                prn=self._process_packet,
                stop_filter=lambda x: not self.is_running,
                timeout=self.timeout,
                count=self.packet_limit if self.packet_limit > 0 else 0
            )
        except Exception as e:
            self.logger.error(f"Error during packet sniffing: {e}")
        finally:
            self.is_running = False
    
    def _process_packet(self, packet):
        """Process individual packet"""
        try:
            self.packet_count += 1
            self.stats['total_packets'] += 1
            
            # Extract packet data
            packet_data = self._extract_packet_data(packet)
            
            if packet_data:
                # Update statistics
                self._update_statistics(packet_data)
                
                # Store packet in MongoDB
                packet_id = self.mongo_handler.insert_packet(packet_data)
                packet_data['_id'] = packet_id
                
                # Check rules
                if self.rule_engine:
                    alerts = self.rule_engine.check_packet(packet_data)
                    for alert in alerts:
                        self.mongo_handler.insert_alert(alert)
                        self.stats['alerts'] += 1
                
                # Check for anomalies
                if self.anomaly_detector and self.anomaly_detector.is_trained():
                    if self.anomaly_detector.is_anomaly(packet_data):
                        anomaly_data = {
                            'packet_id': packet_id,
                            'packet_data': packet_data,
                            'anomaly_score': self.anomaly_detector.get_anomaly_score(packet_data),
                            'type': 'traffic_anomaly'
                        }
                        self.mongo_handler.insert_anomaly(anomaly_data)
                        self.stats['anomalies'] += 1
                
                # Check for CVEs
                if self.cve_checker:
                    cve_alerts = self.cve_checker.check_packet_for_cves(packet_data)
                    for cve_alert in cve_alerts:
                        self.mongo_handler.insert_alert(cve_alert)
                        self.stats['alerts'] += 1
                
                # Call registered callbacks
                for callback in self.callbacks:
                    try:
                        callback(packet_data)
                    except Exception as e:
                        self.logger.error(f"Error in packet callback: {e}")
                
                # Clean up old connections
                self._cleanup_connections()
        
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def _extract_packet_data(self, packet) -> Optional[Dict[str, Any]]:
        """Extract relevant data from packet"""
        try:
            packet_data = {
                'timestamp': datetime.utcnow(),
                'size': len(packet),
                'protocol': 'UNKNOWN',
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None,
                'flags': [],
                'payload_size': 0,
                'headers': {}
            }
            
            # Ethernet layer
            if packet.haslayer(Ether):
                ether = packet[Ether]
                packet_data['src_mac'] = ether.src
                packet_data['dst_mac'] = ether.dst
            
            # IP layer
            if packet.haslayer(IP):
                ip = packet[IP]
                packet_data['src_ip'] = ip.src
                packet_data['dst_ip'] = ip.dst
                packet_data['ttl'] = ip.ttl
                packet_data['protocol'] = 'IP'
                
                # TCP layer
                if packet.haslayer(TCP):
                    tcp = packet[TCP]
                    packet_data['protocol'] = 'TCP'
                    packet_data['src_port'] = tcp.sport
                    packet_data['dst_port'] = tcp.dport
                    packet_data['flags'] = self._get_tcp_flags(tcp.flags)
                    packet_data['seq'] = tcp.seq
                    packet_data['ack'] = tcp.ack
                    
                    # Track connections for port scan detection
                    self._track_connection(packet_data)
                    
                    # HTTP layer
                    if packet.haslayer(HTTPRequest):
                        http_req = packet[HTTPRequest]
                        packet_data['protocol'] = 'HTTP'
                        packet_data['http_method'] = http_req.Method.decode() if http_req.Method else None
                        packet_data['http_path'] = http_req.Path.decode() if http_req.Path else None
                        packet_data['user_agent'] = http_req.User_Agent.decode() if http_req.User_Agent else None
                        packet_data['host'] = http_req.Host.decode() if http_req.Host else None
                    
                    elif packet.haslayer(HTTPResponse):
                        http_resp = packet[HTTPResponse]
                        packet_data['protocol'] = 'HTTP'
                        packet_data['http_status'] = http_resp.Status_Code.decode() if http_resp.Status_Code else None
                        packet_data['server'] = http_resp.Server.decode() if http_resp.Server else None
                
                # UDP layer
                elif packet.haslayer(UDP):
                    udp = packet[UDP]
                    packet_data['protocol'] = 'UDP'
                    packet_data['src_port'] = udp.sport
                    packet_data['dst_port'] = udp.dport
                    
                    # DNS layer
                    if packet.haslayer(DNS):
                        dns = packet[DNS]
                        packet_data['protocol'] = 'DNS'
                        packet_data['dns_id'] = dns.id
                        packet_data['dns_qr'] = dns.qr
                        packet_data['dns_opcode'] = dns.opcode
                        packet_data['dns_rcode'] = dns.rcode
                        
                        if packet.haslayer(DNSQR):
                            dnsqr = packet[DNSQR]
                            packet_data['dns_query'] = dnsqr.qname.decode() if dnsqr.qname else None
                            packet_data['dns_qtype'] = dnsqr.qtype
                
                # ICMP layer
                elif packet.haslayer(ICMP):
                    icmp = packet[ICMP]
                    packet_data['protocol'] = 'ICMP'
                    packet_data['icmp_type'] = icmp.type
                    packet_data['icmp_code'] = icmp.code
            
            # ARP layer
            elif packet.haslayer(ARP):
                arp = packet[ARP]
                packet_data['protocol'] = 'ARP'
                packet_data['arp_op'] = arp.op
                packet_data['src_ip'] = arp.psrc
                packet_data['dst_ip'] = arp.pdst
                packet_data['src_mac'] = arp.hwsrc
                packet_data['dst_mac'] = arp.hwdst
                
                # Check for ARP spoofing
                self._check_arp_spoofing(arp, packet_data)
            
            # Calculate payload size
            if packet.haslayer(scapy.Raw):
                packet_data['payload_size'] = len(packet[scapy.Raw].load)
                # Sample of payload for analysis (first 100 bytes)
                packet_data['payload_sample'] = packet[scapy.Raw].load[:100].hex()
            
            return packet_data
        
        except Exception as e:
            self.logger.error(f"Error extracting packet data: {e}")
            return None
    
    def _get_tcp_flags(self, flags: int) -> List[str]:
        """Convert TCP flags integer to list of flag names"""
        flag_names = []
        flag_map = {
            0x01: 'FIN',
            0x02: 'SYN',
            0x04: 'RST',
            0x08: 'PSH',
            0x10: 'ACK',
            0x20: 'URG',
            0x40: 'ECE',
            0x80: 'CWR'
        }
        
        for flag_bit, flag_name in flag_map.items():
            if flags & flag_bit:
                flag_names.append(flag_name)
        
        return flag_names
    
    def _track_connection(self, packet_data: Dict[str, Any]):
        """Track connections for port scan detection"""
        try:
            src_ip = packet_data.get('src_ip')
            dst_ip = packet_data.get('dst_ip')
            dst_port = packet_data.get('dst_port')
            flags = packet_data.get('flags', [])
            
            if not (src_ip and dst_ip and dst_port):
                return
            
            current_time = time.time()
            
            # Initialize connection tracking for source IP
            if src_ip not in self.connections:
                self.connections[src_ip] = {}
            
            # Track unique destination ports
            connection_key = f"{dst_ip}:{dst_port}"
            
            if 'SYN' in flags and 'ACK' not in flags:
                # SYN packet - potential connection attempt
                self.connections[src_ip][connection_key] = {
                    'timestamp': current_time,
                    'attempts': self.connections[src_ip].get(connection_key, {}).get('attempts', 0) + 1
                }
        
        except Exception as e:
            self.logger.error(f"Error tracking connection: {e}")
    
    def _check_arp_spoofing(self, arp, packet_data: Dict[str, Any]):
        """Check for ARP spoofing attacks"""
        try:
            if arp.op == 2:  # ARP reply
                ip_addr = arp.psrc
                mac_addr = arp.hwsrc
                
                if ip_addr in self.arp_table:
                    if self.arp_table[ip_addr] != mac_addr:
                        # Potential ARP spoofing detected
                        alert_data = {
                            'type': 'arp_spoofing',
                            'severity': 'critical',
                            'description': f'ARP spoofing detected: IP {ip_addr} claimed by both {self.arp_table[ip_addr]} and {mac_addr}',
                            'src_ip': ip_addr,
                            'old_mac': self.arp_table[ip_addr],
                            'new_mac': mac_addr,
                            'packet_data': packet_data
                        }
                        
                        if self.mongo_handler:
                            self.mongo_handler.insert_alert(alert_data)
                        
                        self.stats['alerts'] += 1
                        self.logger.warning(f"ARP spoofing detected for IP {ip_addr}")
                
                self.arp_table[ip_addr] = mac_addr
        
        except Exception as e:
            self.logger.error(f"Error checking ARP spoofing: {e}")
    
    def _cleanup_connections(self):
        """Clean up old connection tracking data"""
        try:
            current_time = time.time()
            
            for src_ip in list(self.connections.keys()):
                connections_to_remove = []
                
                for connection_key, connection_data in self.connections[src_ip].items():
                    if current_time - connection_data['timestamp'] > self.connection_timeout:
                        connections_to_remove.append(connection_key)
                
                for connection_key in connections_to_remove:
                    del self.connections[src_ip][connection_key]
                
                # Remove empty source IP entries
                if not self.connections[src_ip]:
                    del self.connections[src_ip]
        
        except Exception as e:
            self.logger.error(f"Error cleaning up connections: {e}")
    
    def _update_statistics(self, packet_data: Dict[str, Any]):
        """Update packet statistics"""
        try:
            protocol = packet_data.get('protocol', 'UNKNOWN')
            src_ip = packet_data.get('src_ip')
            dst_ip = packet_data.get('dst_ip')
            dst_port = packet_data.get('dst_port')
            
            # Protocol statistics
            self.stats['protocols'][protocol] = self.stats['protocols'].get(protocol, 0) + 1
            
            # IP statistics
            if src_ip:
                self.stats['src_ips'][src_ip] = self.stats['src_ips'].get(src_ip, 0) + 1
            if dst_ip:
                self.stats['dst_ips'][dst_ip] = self.stats['dst_ips'].get(dst_ip, 0) + 1
            
            # Port statistics
            if dst_port:
                self.stats['ports'][dst_port] = self.stats['ports'].get(dst_port, 0) + 1
        
        except Exception as e:
            self.logger.error(f"Error updating statistics: {e}")
    
    def get_port_scan_alerts(self) -> List[Dict[str, Any]]:
        """Get port scan alerts based on connection tracking"""
        alerts = []
        current_time = time.time()
        
        try:
            for src_ip, connections in self.connections.items():
                # Count unique ports accessed in the last minute
                recent_ports = []
                for connection_key, connection_data in connections.items():
                    if current_time - connection_data['timestamp'] <= 60:
                        port = connection_key.split(':')[1]
                        if port not in recent_ports:
                            recent_ports.append(port)
                
                # If more than 10 unique ports in 1 minute, consider it a port scan
                if len(recent_ports) > 10:
                    alert_data = {
                        'type': 'port_scan',
                        'severity': 'medium',
                        'description': f'Port scan detected from {src_ip}: {len(recent_ports)} ports scanned in 60 seconds',
                        'src_ip': src_ip,
                        'ports_scanned': recent_ports,
                        'port_count': len(recent_ports)
                    }
                    alerts.append(alert_data)
        
        except Exception as e:
            self.logger.error(f"Error getting port scan alerts: {e}")
        
        return alerts
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current packet statistics"""
        return self.stats.copy()
    
    def reset_statistics(self):
        """Reset packet statistics"""
        self.stats = {
            'total_packets': 0,
            'protocols': {},
            'src_ips': {},
            'dst_ips': {},
            'ports': {},
            'alerts': 0,
            'anomalies': 0
        }
    
    def is_sniffing(self) -> bool:
        """Check if packet sniffing is currently active"""
        return self.is_running
