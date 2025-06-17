import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging
import re

class RuleEngine:
    def __init__(self, config: Dict[str, Any], mongo_handler):
        self.config = config
        self.mongo_handler = mongo_handler
        self.rules = []
        self.logger = logging.getLogger(__name__)
        
        # Load rules from file
        self.load_rules()
        
        # Rule matching statistics
        self.rule_stats = {}
        
        # Time-based tracking for threshold rules
        self.tracking_data = {}
        self.tracking_timeout = 3600  # 1 hour
    
    def load_rules(self, rules_file: str = None):
        """Load rules from JSON file"""
        try:
            if not rules_file:
                rules_file = 'data/rules.json'
            
            with open(rules_file, 'r') as f:
                self.rules = json.load(f)
            
            self.logger.info(f"Loaded {len(self.rules)} rules from {rules_file}")
            
            # Initialize rule statistics
            for rule in self.rules:
                rule_id = rule.get('id', 'unknown')
                self.rule_stats[rule_id] = {
                    'matches': 0,
                    'last_match': None
                }
        
        except Exception as e:
            self.logger.error(f"Error loading rules: {e}")
            self.rules = []
    
    def save_rules(self, rules_file: str = None):
        """Save rules to JSON file"""
        try:
            if not rules_file:
                rules_file = 'data/rules.json'
            
            with open(rules_file, 'w') as f:
                json.dump(self.rules, f, indent=2)
            
            self.logger.info(f"Saved {len(self.rules)} rules to {rules_file}")
            return True
        
        except Exception as e:
            self.logger.error(f"Error saving rules: {e}")
            return False
    
    def add_rule(self, rule: Dict[str, Any]) -> bool:
        """Add a new rule"""
        try:
            # Validate rule structure
            if not self._validate_rule(rule):
                return False
            
            # Check for duplicate rule ID
            rule_id = rule.get('id')
            if any(r.get('id') == rule_id for r in self.rules):
                self.logger.error(f"Rule with ID {rule_id} already exists")
                return False
            
            self.rules.append(rule)
            
            # Initialize statistics for new rule
            self.rule_stats[rule_id] = {
                'matches': 0,
                'last_match': None
            }
            
            self.logger.info(f"Added new rule: {rule_id}")
            return True
        
        except Exception as e:
            self.logger.error(f"Error adding rule: {e}")
            return False
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID"""
        try:
            self.rules = [r for r in self.rules if r.get('id') != rule_id]
            
            if rule_id in self.rule_stats:
                del self.rule_stats[rule_id]
            
            self.logger.info(f"Removed rule: {rule_id}")
            return True
        
        except Exception as e:
            self.logger.error(f"Error removing rule: {e}")
            return False
    
    def update_rule(self, rule_id: str, updated_rule: Dict[str, Any]) -> bool:
        """Update an existing rule"""
        try:
            if not self._validate_rule(updated_rule):
                return False
            
            for i, rule in enumerate(self.rules):
                if rule.get('id') == rule_id:
                    self.rules[i] = updated_rule
                    self.logger.info(f"Updated rule: {rule_id}")
                    return True
            
            self.logger.error(f"Rule with ID {rule_id} not found")
            return False
        
        except Exception as e:
            self.logger.error(f"Error updating rule: {e}")
            return False
    
    def check_packet(self, packet_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check packet against all enabled rules"""
        alerts = []
        
        try:
            for rule in self.rules:
                if not rule.get('enabled', True):
                    continue
                
                if self._match_rule(rule, packet_data):
                    alert = self._create_alert(rule, packet_data)
                    alerts.append(alert)
                    
                    # Update rule statistics
                    rule_id = rule.get('id', 'unknown')
                    self.rule_stats[rule_id]['matches'] += 1
                    self.rule_stats[rule_id]['last_match'] = datetime.utcnow()
                    
                    self.logger.info(f"Rule triggered: {rule.get('name', rule_id)}")
        
        except Exception as e:
            self.logger.error(f"Error checking packet against rules: {e}")
        
        # Clean up old tracking data
        self._cleanup_tracking_data()
        
        return alerts
    
    def _validate_rule(self, rule: Dict[str, Any]) -> bool:
        """Validate rule structure"""
        required_fields = ['id', 'name', 'type', 'conditions']
        
        for field in required_fields:
            if field not in rule:
                self.logger.error(f"Rule missing required field: {field}")
                return False
        
        # Validate rule type
        valid_types = ['threshold', 'pattern', 'blacklist', 'whitelist']
        if rule.get('type') not in valid_types:
            self.logger.error(f"Invalid rule type: {rule.get('type')}")
            return False
        
        return True
    
    def _match_rule(self, rule: Dict[str, Any], packet_data: Dict[str, Any]) -> bool:
        """Check if packet matches rule conditions"""
        try:
            rule_type = rule.get('type')
            conditions = rule.get('conditions', {})
            
            if rule_type == 'threshold':
                return self._match_threshold_rule(rule, packet_data, conditions)
            elif rule_type == 'pattern':
                return self._match_pattern_rule(rule, packet_data, conditions)
            elif rule_type == 'blacklist':
                return self._match_blacklist_rule(rule, packet_data, conditions)
            elif rule_type == 'whitelist':
                return self._match_whitelist_rule(rule, packet_data, conditions)
            
            return False
        
        except Exception as e:
            self.logger.error(f"Error matching rule {rule.get('id')}: {e}")
            return False
    
    def _match_threshold_rule(self, rule: Dict[str, Any], packet_data: Dict[str, Any], conditions: Dict[str, Any]) -> bool:
        """Match threshold-based rules (e.g., port scan, brute force)"""
        try:
            rule_id = rule.get('id')
            src_ip = packet_data.get('src_ip')
            dst_ip = packet_data.get('dst_ip')
            dst_port = packet_data.get('dst_port')
            
            current_time = time.time()
            
            # Initialize tracking for this rule if not exists
            if rule_id not in self.tracking_data:
                self.tracking_data[rule_id] = {}
            
            # Port scan detection
            if 'source_ip_connections' in conditions:
                threshold_config = conditions['source_ip_connections']
                threshold = threshold_config.get('threshold', 20)
                time_window = threshold_config.get('time_window', 60)
                
                if src_ip:
                    # Track connections per source IP
                    if src_ip not in self.tracking_data[rule_id]:
                        self.tracking_data[rule_id][src_ip] = []
                    
                    # Add current connection
                    connection_key = f"{dst_ip}:{dst_port}"
                    self.tracking_data[rule_id][src_ip].append({
                        'connection': connection_key,
                        'timestamp': current_time
                    })
                    
                    # Clean old entries
                    self.tracking_data[rule_id][src_ip] = [
                        entry for entry in self.tracking_data[rule_id][src_ip]
                        if current_time - entry['timestamp'] <= time_window
                    ]
                    
                    # Count unique connections
                    unique_connections = set(entry['connection'] for entry in self.tracking_data[rule_id][src_ip])
                    
                    return len(unique_connections) >= threshold
            
            # SSH brute force detection
            if 'failed_attempts' in conditions and dst_port == conditions.get('destination_port'):
                threshold_config = conditions['failed_attempts']
                threshold = threshold_config.get('threshold', 5)
                time_window = threshold_config.get('time_window', 300)
                
                # Check for TCP RST flag (failed connection)
                flags = packet_data.get('flags', [])
                if 'RST' in flags and src_ip:
                    tracking_key = f"{src_ip}:{dst_ip}:{dst_port}"
                    
                    if tracking_key not in self.tracking_data[rule_id]:
                        self.tracking_data[rule_id][tracking_key] = []
                    
                    self.tracking_data[rule_id][tracking_key].append(current_time)
                    
                    # Clean old entries
                    self.tracking_data[rule_id][tracking_key] = [
                        timestamp for timestamp in self.tracking_data[rule_id][tracking_key]
                        if current_time - timestamp <= time_window
                    ]
                    
                    return len(self.tracking_data[rule_id][tracking_key]) >= threshold
            
            # DNS query frequency
            if 'dns_query_frequency' in conditions and packet_data.get('protocol') == 'DNS':
                threshold_config = conditions['dns_query_frequency']
                threshold = threshold_config.get('threshold', 100)
                time_window = threshold_config.get('time_window', 60)
                
                if src_ip:
                    tracking_key = f"dns_{src_ip}"
                    
                    if tracking_key not in self.tracking_data[rule_id]:
                        self.tracking_data[rule_id][tracking_key] = []
                    
                    self.tracking_data[rule_id][tracking_key].append(current_time)
                    
                    # Clean old entries
                    self.tracking_data[rule_id][tracking_key] = [
                        timestamp for timestamp in self.tracking_data[rule_id][tracking_key]
                        if current_time - timestamp <= time_window
                    ]
                    
                    return len(self.tracking_data[rule_id][tracking_key]) >= threshold
            
            return False
        
        except Exception as e:
            self.logger.error(f"Error matching threshold rule: {e}")
            return False
    
    def _match_pattern_rule(self, rule: Dict[str, Any], packet_data: Dict[str, Any], conditions: Dict[str, Any]) -> bool:
        """Match pattern-based rules"""
        try:
            # DNS tunneling detection
            if 'dns_query_length' in conditions and packet_data.get('protocol') == 'DNS':
                min_length = conditions['dns_query_length'].get('min_length', 50)
                dns_query = packet_data.get('dns_query', '')
                
                if len(dns_query) >= min_length:
                    return True
            
            # ARP spoofing detection
            if 'arp_type' in conditions and packet_data.get('protocol') == 'ARP':
                required_arp_type = conditions.get('arp_type')
                arp_op = packet_data.get('arp_op')
                
                # ARP reply = 2
                if required_arp_type == 'reply' and arp_op == 2:
                    return conditions.get('duplicate_ip_mac', False)  # This would be set by packet sniffer
            
            # Custom regex patterns
            if 'regex_pattern' in conditions:
                pattern = conditions['regex_pattern']
                target_field = conditions.get('target_field', 'payload_sample')
                
                if target_field in packet_data:
                    field_value = str(packet_data[target_field])
                    if re.search(pattern, field_value, re.IGNORECASE):
                        return True
            
            return False
        
        except Exception as e:
            self.logger.error(f"Error matching pattern rule: {e}")
            return False
    
    def _match_blacklist_rule(self, rule: Dict[str, Any], packet_data: Dict[str, Any], conditions: Dict[str, Any]) -> bool:
        """Match blacklist-based rules"""
        try:
            # Suspicious User-Agent detection
            if 'user_agent_patterns' in conditions:
                user_agent = packet_data.get('user_agent', '').lower()
                patterns = conditions['user_agent_patterns']
                
                for pattern in patterns:
                    if pattern.lower() in user_agent:
                        return True
            
            # IP blacklist
            if 'blacklisted_ips' in conditions:
                src_ip = packet_data.get('src_ip')
                dst_ip = packet_data.get('dst_ip')
                blacklisted_ips = conditions['blacklisted_ips']
                
                if src_ip in blacklisted_ips or dst_ip in blacklisted_ips:
                    return True
            
            # Domain blacklist
            if 'blacklisted_domains' in conditions:
                dns_query = packet_data.get('dns_query', '').lower()
                host = packet_data.get('host', '').lower()
                blacklisted_domains = conditions['blacklisted_domains']
                
                for domain in blacklisted_domains:
                    if domain.lower() in dns_query or domain.lower() in host:
                        return True
            
            # Port blacklist
            if 'blacklisted_ports' in conditions:
                dst_port = packet_data.get('dst_port')
                blacklisted_ports = conditions['blacklisted_ports']
                
                if dst_port in blacklisted_ports:
                    return True
            
            return False
        
        except Exception as e:
            self.logger.error(f"Error matching blacklist rule: {e}")
            return False
    
    def _match_whitelist_rule(self, rule: Dict[str, Any], packet_data: Dict[str, Any], conditions: Dict[str, Any]) -> bool:
        """Match whitelist-based rules (alert if NOT in whitelist)"""
        try:
            # IP whitelist
            if 'whitelisted_ips' in conditions:
                src_ip = packet_data.get('src_ip')
                dst_ip = packet_data.get('dst_ip')
                whitelisted_ips = conditions['whitelisted_ips']
                
                # Alert if traffic is NOT from/to whitelisted IPs
                if src_ip and src_ip not in whitelisted_ips and dst_ip and dst_ip not in whitelisted_ips:
                    return True
            
            # Domain whitelist
            if 'whitelisted_domains' in conditions:
                dns_query = packet_data.get('dns_query', '').lower()
                host = packet_data.get('host', '').lower()
                whitelisted_domains = conditions['whitelisted_domains']
                
                # Alert if domain is NOT in whitelist
                domain_found = False
                for domain in whitelisted_domains:
                    if domain.lower() in dns_query or domain.lower() in host:
                        domain_found = True
                        break
                
                if not domain_found and (dns_query or host):
                    return True
            
            return False
        
        except Exception as e:
            self.logger.error(f"Error matching whitelist rule: {e}")
            return False
    
    def _create_alert(self, rule: Dict[str, Any], packet_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create alert data structure"""
        return {
            'type': 'rule_match',
            'rule_id': rule.get('id'),
            'rule_name': rule.get('name'),
            'severity': rule.get('severity', 'medium'),
            'description': rule.get('description', ''),
            'action': rule.get('action', 'alert'),
            'src_ip': packet_data.get('src_ip'),
            'dst_ip': packet_data.get('dst_ip'),
            'src_port': packet_data.get('src_port'),
            'dst_port': packet_data.get('dst_port'),
            'protocol': packet_data.get('protocol'),
            'packet_size': packet_data.get('size'),
            'packet_data': packet_data,
            'timestamp': datetime.utcnow()
        }
    
    def _cleanup_tracking_data(self):
        """Clean up old tracking data"""
        try:
            current_time = time.time()
            
            for rule_id in list(self.tracking_data.keys()):
                rule_data = self.tracking_data[rule_id]
                
                for tracking_key in list(rule_data.keys()):
                    if isinstance(rule_data[tracking_key], list):
                        # Clean timestamp-based tracking
                        rule_data[tracking_key] = [
                            item for item in rule_data[tracking_key]
                            if (isinstance(item, (int, float)) and current_time - item <= self.tracking_timeout) or
                               (isinstance(item, dict) and 'timestamp' in item and current_time - item['timestamp'] <= self.tracking_timeout)
                        ]
                        
                        # Remove empty tracking keys
                        if not rule_data[tracking_key]:
                            del rule_data[tracking_key]
                
                # Remove empty rule tracking
                if not rule_data:
                    del self.tracking_data[rule_id]
        
        except Exception as e:
            self.logger.error(f"Error cleaning up tracking data: {e}")
    
    def get_rule_statistics(self) -> Dict[str, Any]:
        """Get rule matching statistics"""
        return self.rule_stats.copy()
    
    def get_rules(self) -> List[Dict[str, Any]]:
        """Get all rules"""
        return self.rules.copy()
    
    def get_rule_by_id(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Get specific rule by ID"""
        for rule in self.rules:
            if rule.get('id') == rule_id:
                return rule.copy()
        return None
    
    def enable_rule(self, rule_id: str) -> bool:
        """Enable a specific rule"""
        for rule in self.rules:
            if rule.get('id') == rule_id:
                rule['enabled'] = True
                self.logger.info(f"Enabled rule: {rule_id}")
                return True
        return False
    
    def disable_rule(self, rule_id: str) -> bool:
        """Disable a specific rule"""
        for rule in self.rules:
            if rule.get('id') == rule_id:
                rule['enabled'] = False
                self.logger.info(f"Disabled rule: {rule_id}")
                return True
        return False
    
    def reset_statistics(self):
        """Reset rule statistics"""
        for rule_id in self.rule_stats:
            self.rule_stats[rule_id] = {
                'matches': 0,
                'last_match': None
            }
