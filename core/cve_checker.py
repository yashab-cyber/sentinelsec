import requests
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging
import re

class CVEChecker:
    def __init__(self, config: Dict[str, Any], mongo_handler):
        self.config = config
        self.mongo_handler = mongo_handler
        self.api_key = config.get('nvd_api_key', '')
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cache_duration = config.get('cve', {}).get('cache_duration', 86400)
        self.results_per_page = config.get('cve', {}).get('results_per_page', 20)
        self.logger = logging.getLogger(__name__)
        
        # Common software patterns to detect from traffic
        self.software_patterns = {
            'apache': r'Apache[/\s]+([0-9\.]+)',
            'nginx': r'nginx[/\s]+([0-9\.]+)',
            'openssh': r'OpenSSH[_\s]+([0-9\.]+)',
            'mysql': r'MySQL[/\s]+([0-9\.]+)',
            'php': r'PHP[/\s]+([0-9\.]+)',
            'iis': r'Microsoft-IIS[/\s]+([0-9\.]+)',
            'wordpress': r'WordPress[/\s]+([0-9\.]+)',
            'joomla': r'Joomla[!/\s]+([0-9\.]+)',
            'drupal': r'Drupal[/\s]+([0-9\.]+)',
        }
        
        # Port to software mapping
        self.port_software_map = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            27017: 'MongoDB'
        }
    
    def fetch_cve_data(self, keyword: str = None, cve_id: str = None, 
                      start_date: str = None, end_date: str = None) -> List[Dict[str, Any]]:
        """Fetch CVE data from NVD API"""
        try:
            headers = {}
            if self.api_key:
                headers['apiKey'] = self.api_key
            
            params = {
                'resultsPerPage': self.results_per_page
            }
            
            if keyword:
                params['keywordSearch'] = keyword
            if cve_id:
                params['cveId'] = cve_id
            if start_date:
                params['pubStartDate'] = start_date
            if end_date:
                params['pubEndDate'] = end_date
            
            self.logger.info(f"Fetching CVE data for: {keyword or cve_id}")
            response = requests.get(self.base_url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                processed_cves = []
                for vuln in vulnerabilities:
                    cve_data = self._process_cve_data(vuln)
                    if cve_data:
                        processed_cves.append(cve_data)
                        # Cache in MongoDB
                        self.mongo_handler.insert_cve_data(cve_data)
                
                self.logger.info(f"Fetched {len(processed_cves)} CVE records")
                return processed_cves
            
            elif response.status_code == 403:
                self.logger.error("API key invalid or rate limit exceeded")
                return []
            else:
                self.logger.error(f"API request failed: {response.status_code} - {response.text}")
                return []
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Network error fetching CVE data: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Error fetching CVE data: {e}")
            return []
    
    def _process_cve_data(self, vuln_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process raw CVE data from NVD API"""
        try:
            cve = vuln_data.get('cve', {})
            cve_id = cve.get('id', '')
            
            # Extract descriptions
            descriptions = cve.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Extract CVSS scores
            cvss_data = {}
            metrics = cve.get('metrics', {})
            
            # Try CVSS v3.1 first, then v3.0, then v2.0
            for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if version in metrics and metrics[version]:
                    metric = metrics[version][0]
                    cvss_data = {
                        'version': version.replace('cvssMetricV', '').replace('31', '3.1').replace('30', '3.0'),
                        'score': metric.get('cvssData', {}).get('baseScore', 0),
                        'severity': metric.get('cvssData', {}).get('baseSeverity', 'UNKNOWN'),
                        'vector': metric.get('cvssData', {}).get('vectorString', '')
                    }
                    break
            
            # Extract references
            references = []
            ref_data = cve.get('references', [])
            for ref in ref_data[:5]:  # Limit to first 5 references
                references.append({
                    'url': ref.get('url', ''),
                    'source': ref.get('source', ''),
                    'tags': ref.get('tags', [])
                })
            
            # Extract affected configurations
            configurations = []
            config_data = cve.get('configurations', [])
            for config in config_data:
                nodes = config.get('nodes', [])
                for node in nodes:
                    cpe_matches = node.get('cpeMatch', [])
                    for cpe in cpe_matches:
                        if cpe.get('vulnerable', False):
                            configurations.append({
                                'cpe23Uri': cpe.get('criteria', ''),
                                'versionStartIncluding': cpe.get('versionStartIncluding'),
                                'versionEndExcluding': cpe.get('versionEndExcluding')
                            })
            
            # Extract publication and modification dates
            published = cve.get('published', '')
            last_modified = cve.get('lastModified', '')
            
            processed_cve = {
                'cve_id': cve_id,
                'description': description,
                'cvss': cvss_data,
                'references': references,
                'configurations': configurations,
                'published': published,
                'last_modified': last_modified,
                'cached_at': datetime.utcnow()
            }
            
            return processed_cve
            
        except Exception as e:
            self.logger.error(f"Error processing CVE data: {e}")
            return None
    
    def check_packet_for_cves(self, packet_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check packet data for potential CVE matches"""
        try:
            cve_alerts = []
            
            # Check for software versions in HTTP headers
            if packet_data.get('protocol') == 'HTTP':
                user_agent = packet_data.get('user_agent', '')
                server_header = packet_data.get('server', '')
                
                # Check User-Agent for software versions
                software_found = self._extract_software_versions(user_agent)
                software_found.update(self._extract_software_versions(server_header))
                
                for software, version in software_found.items():
                    cves = self._get_cached_cves_for_software(software, version)
                    for cve in cves:
                        cve_alert = {
                            'type': 'cve_match',
                            'cve_id': cve['cve_id'],
                            'software': software,
                            'version': version,
                            'cvss_score': cve.get('cvss', {}).get('score', 0),
                            'severity': cve.get('cvss', {}).get('severity', 'UNKNOWN'),
                            'description': cve['description'][:200] + '...',
                            'source_ip': packet_data.get('src_ip'),
                            'destination_ip': packet_data.get('dst_ip'),
                            'packet_id': packet_data.get('_id')
                        }
                        cve_alerts.append(cve_alert)
            
            # Check for service vulnerabilities based on ports
            dst_port = packet_data.get('dst_port')
            if dst_port and dst_port in self.port_software_map:
                service = self.port_software_map[dst_port]
                cves = self._get_cached_cves_for_software(service.lower())
                
                for cve in cves[:3]:  # Limit to top 3 CVEs per service
                    cve_alert = {
                        'type': 'service_vulnerability',
                        'cve_id': cve['cve_id'],
                        'service': service,
                        'port': dst_port,
                        'cvss_score': cve.get('cvss', {}).get('score', 0),
                        'severity': cve.get('cvss', {}).get('severity', 'UNKNOWN'),
                        'description': cve['description'][:200] + '...',
                        'source_ip': packet_data.get('src_ip'),
                        'destination_ip': packet_data.get('dst_ip'),
                        'packet_id': packet_data.get('_id')
                    }
                    cve_alerts.append(cve_alert)
            
            return cve_alerts
            
        except Exception as e:
            self.logger.error(f"Error checking packet for CVEs: {e}")
            return []
    
    def _extract_software_versions(self, text: str) -> Dict[str, str]:
        """Extract software names and versions from text using regex patterns"""
        software_found = {}
        
        for software, pattern in self.software_patterns.items():
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                version = match.group(1) if match.groups() else 'unknown'
                software_found[software] = version
        
        return software_found
    
    def _get_cached_cves_for_software(self, software: str, version: str = None) -> List[Dict[str, Any]]:
        """Get cached CVE data for specific software"""
        try:
            # Check if cached data is still valid
            cutoff_time = datetime.utcnow() - timedelta(seconds=self.cache_duration)
            
            cves = self.mongo_handler.get_cve_data(software=software)
            
            # Filter out expired cache entries
            valid_cves = []
            for cve in cves:
                cached_at = cve.get('cached_at')
                if isinstance(cached_at, str):
                    cached_at = datetime.fromisoformat(cached_at.replace('Z', '+00:00'))
                
                if cached_at and cached_at > cutoff_time:
                    # If version is specified, check if it's affected
                    if version and not self._is_version_affected(cve, version):
                        continue
                    valid_cves.append(cve)
            
            # If no valid cached data, fetch fresh data
            if not valid_cves:
                self.logger.info(f"No valid cached CVE data for {software}, fetching fresh data")
                fresh_cves = self.fetch_cve_data(keyword=software)
                return fresh_cves
            
            return valid_cves[:10]  # Limit to top 10 CVEs
            
        except Exception as e:
            self.logger.error(f"Error getting cached CVEs for {software}: {e}")
            return []
    
    def _is_version_affected(self, cve_data: Dict[str, Any], version: str) -> bool:
        """Check if a specific version is affected by the CVE"""
        try:
            configurations = cve_data.get('configurations', [])
            
            for config in configurations:
                cpe_uri = config.get('cpe23Uri', '')
                version_start = config.get('versionStartIncluding')
                version_end = config.get('versionEndExcluding')
                
                # Simple version comparison (can be enhanced)
                if version_start and self._compare_versions(version, version_start) < 0:
                    continue
                if version_end and self._compare_versions(version, version_end) >= 0:
                    continue
                
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking version affected: {e}")
            return True  # Assume affected if we can't determine
    
    def _compare_versions(self, version1: str, version2: str) -> int:
        """Simple version comparison (-1: v1 < v2, 0: v1 == v2, 1: v1 > v2)"""
        try:
            v1_parts = [int(x) for x in version1.split('.')]
            v2_parts = [int(x) for x in version2.split('.')]
            
            # Pad shorter version with zeros
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            for i in range(max_len):
                if v1_parts[i] < v2_parts[i]:
                    return -1
                elif v1_parts[i] > v2_parts[i]:
                    return 1
            
            return 0
            
        except Exception:
            return 0  # Assume equal if comparison fails
    
    def sync_recent_cves(self, days: int = 7) -> int:
        """Sync recent CVEs from the last N days"""
        try:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            
            start_str = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
            end_str = end_date.strftime('%Y-%m-%dT%H:%M:%S.000')
            
            cves = self.fetch_cve_data(start_date=start_str, end_date=end_str)
            
            self.logger.info(f"Synced {len(cves)} recent CVEs from last {days} days")
            return len(cves)
            
        except Exception as e:
            self.logger.error(f"Error syncing recent CVEs: {e}")
            return 0
    
    def get_cve_statistics(self) -> Dict[str, Any]:
        """Get CVE cache statistics"""
        try:
            total_cves = len(self.mongo_handler.get_cve_data())
            
            # Get severity breakdown
            severity_stats = {}
            cves = self.mongo_handler.get_cve_data()
            
            for cve in cves:
                severity = cve.get('cvss', {}).get('severity', 'UNKNOWN')
                severity_stats[severity] = severity_stats.get(severity, 0) + 1
            
            return {
                'total_cves': total_cves,
                'severity_breakdown': severity_stats,
                'cache_size_mb': total_cves * 0.001  # Rough estimate
            }
            
        except Exception as e:
            self.logger.error(f"Error getting CVE statistics: {e}")
            return {}
