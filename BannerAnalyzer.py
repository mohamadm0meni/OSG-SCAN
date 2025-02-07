import re
import json
import logging
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime
import threading
from collections import defaultdict
import os

class BannerAnalyzer:
    def __init__(self, vuln_db_path: str = "vulnerability_db.json"):
        self.logger = logging.getLogger(__name__)
        self.lock = threading.Lock()
        
        # Load vulnerability database
        self.vuln_db = self._load_vuln_db(vuln_db_path)
        
        # Enhanced version pattern matching
        self.version_patterns = {
            'web_servers': {
                'apache': [
                    rb'Apache(?:/([0-9][0-9\.\-_]+))?',
                    rb'Server: Apache/([0-9][0-9\.\-_]+)',
                    rb'mod_ssl/([0-9][0-9\.\-_]+)',
                    rb'OpenSSL/([0-9][0-9\.\-_]+)',
                    rb'PHP/([0-9][0-9\.\-_]+)'
                ],
                'nginx': [
                    rb'nginx/([0-9][0-9\.\-_]+)',
                    rb'Server: nginx/([0-9][0-9\.\-_]+)',
                    rb'OpenSSL/([0-9][0-9\.\-_]+)'
                ],
                'iis': [
                    rb'Microsoft-IIS/([0-9][0-9\.\-_]+)',
                    rb'ASP\.NET\s+([0-9][0-9\.\-_]+)',
                    rb'X-AspNet-Version:\s*([0-9][0-9\.\-_]+)'
                ]
            },
            'databases': {
                'mysql': [
                    rb'MySQL\s*v?([0-9][0-9\.\-_]+)',
                    rb'MariaDB-([0-9][0-9\.\-_]+)',
                    rb'protocol_version\s*=\s*([0-9][0-9\.\-_]+)'
                ],
                'postgresql': [
                    rb'PostgreSQL\s+([0-9][0-9\.\-_]+)',
                    rb'PGSQL\s*v?([0-9][0-9\.\-_]+)'
                ],
                'mongodb': [
                    rb'MongoDB\s*/?\s*v?([0-9][0-9\.\-_]+)',
                    rb'db version\s*v?([0-9][0-9\.\-_]+)'
                ]
            },
            'mail_servers': {
                'postfix': [
                    rb'Postfix\s*v?([0-9][0-9\.\-_]+)',
                    rb'ESMTP\s+Postfix\s*v?([0-9][0-9\.\-_]+)'
                ],
                'exchange': [
                    rb'Microsoft\s+Exchange\s+Server\s+([0-9][0-9\.\-_]+)',
                    rb'Exchange\s+Server\s+([0-9][0-9\.\-_]+)'
                ],
                'dovecot': [
                    rb'Dovecot\s*v?([0-9][0-9\.\-_]+)',
                    rb'IMAP\s+Dovecot\s*v?([0-9][0-9\.\-_]+)'
                ]
            },
            'ssh': {
                'openssh': [
                    rb'OpenSSH[_-]([0-9][0-9\.\-_]+)',
                    rb'SSH-2\.0-OpenSSH_([0-9][0-9\.\-_]+)'
                ],
                'dropbear': [
                    rb'dropbear[_-]([0-9][0-9\.\-_]+)',
                    rb'SSH-2\.0-dropbear_([0-9][0-9\.\-_]+)'
                ]
            }
        }

        # OS Detection patterns
        self.os_patterns = {
            'linux': {
                'ubuntu': [
                    rb'Ubuntu[/-]([0-9\.]+)',
                    rb'Debian-([0-9]+ubuntu[0-9\.]+)'
                ],
                'debian': [
                    rb'Debian[/-]([0-9\.]+)',
                    rb'debian\s+([0-9\.]+)'
                ],
                'centos': [
                    rb'CentOS[/-]([0-9\.]+)',
                    rb'Red Hat Enterprise Linux[/-]([0-9\.]+)'
                ]
            },
            'windows': {
                'server': [
                    rb'Windows Server (\d{4})',
                    rb'Win32|Win64',
                    rb'Microsoft Windows \[Version ([0-9\.]+)\]'
                ],
                'iis': [
                    rb'Microsoft-IIS/([0-9\.]+)',
                    rb'ASP\.NET'
                ]
            },
            'bsd': {
                'freebsd': [
                    rb'FreeBSD[/-]([0-9\.]+)',
                    rb'BSD-([0-9\.]+)'
                ],
                'openbsd': [
                    rb'OpenBSD[/-]([0-9\.]+)'
                ]
            }
        }

        # Security issue patterns
        self.security_patterns = {
            'information_disclosure': {
                'stack_trace': [
                    rb'at [\w\.$]+\([\w:]+\.(?:java|php|py|rb):\d+\)',
                    rb'(?:Exception|Error|Stack trace|DEBUG)\s+at\s+',
                    rb'([A-Za-z]:\\[^\n]+\.(?:cs|vb|aspx|php|jsp):\d+)',
                    rb'in\s+[A-Za-z]:\\[^\n]+\s+on\s+line\s+\d+'
                ],
                'internal_paths': [
                    rb'(?:[A-Za-z]:\\[^\n]+|/(?:var|etc|usr|home)/[^\n]+)',
                    rb'(?:/[\w\-\.]+)+\.(?:php|jsp|asp|aspx|rb|py|java|xml|conf|ini)',
                    rb'[A-Za-z]:\\[\w\-\\]+\.(?:php|asp|aspx|config|ini|xml)'
                ],
                'server_tokens': [
                    rb'Server:\s*[^\r\n]+',
                    rb'X-Powered-By:\s*[^\r\n]+',
                    rb'X-AspNet-Version:\s*[^\r\n]+'
                ]
            },
            'debug_info': {
                'debug_messages': [
                    rb'(?i)debug[:/]\s*.*?(?:\r|\n)',
                    rb'(?i)warning[:/]\s*.*?(?:\r|\n)',
                    rb'(?i)notice[:/]\s*.*?(?:\r|\n)'
                ],
                'development_info': [
                    rb'(?i)development\s+(?:server|mode|environment)',
                    rb'(?i)staging\s+(?:server|environment)',
                    rb'(?i)test\s+(?:server|environment)'
                ]
            },
            'sensitive_data': {
                'credentials': [
                    rb'(?i)(?:password|passwd|pwd)[\s:=]+[^\s]+',
                    rb'(?i)(?:username|user|uid)[\s:=]+[^\s]+',
                    rb'(?i)(?:api[_-]?key|access[_-]?token)[\s:=]+[^\s]+'
                ],
                'email_addresses': [
                    rb'[\w\.-]+@[\w\.-]+\.\w+',
                    rb'mailto:[\w\.-]+@[\w\.-]+\.\w+'
                ],
                'private_keys': [
                    rb'-----BEGIN (?:RSA |DSA )?PRIVATE KEY-----',
                    rb'-----BEGIN CERTIFICATE-----'
                ]
            }
        }

        # Protocol-specific patterns
        self.protocol_patterns = {
            'http': {
                'methods': [
                    rb'GET|POST|HEAD|PUT|DELETE|OPTIONS|TRACE|CONNECT',
                    rb'HTTP/[0-9\.]+'
                ],
                'headers': [
                    rb'Content-Type:|Content-Length:|Set-Cookie:|Location:',
                    rb'X-Frame-Options:|X-XSS-Protection:|X-Content-Type-Options:'
                ]
            },
            'smtp': {
                'commands': [
                    rb'HELO|EHLO|MAIL FROM:|RCPT TO:|DATA|QUIT',
                    rb'AUTH\s+(?:PLAIN|LOGIN|CRAM-MD5)'
                ],
                'responses': [
                    rb'2\d{2}[- ]',
                    rb'5\d{2}[- ]'
                ]
            },
            'ftp': {
                'commands': [
                    rb'USER|PASS|ACCT|CWD|CDUP|SMNT|QUIT|REIN|PORT',
                    rb'PASV|TYPE|STRU|MODE|RETR|STOR|STOU|APPE|ALLO'
                ],
                'responses': [
                    rb'2\d{2}[- ]',
                    rb'5\d{2}[- ]'
                ]
            }
        }

        # Initialize statistics tracking
        self.stats = defaultdict(int)
        
    def _load_vuln_db(self, db_path: str) -> Dict:
        """Load vulnerability database from JSON file"""
        try:
            if os.path.exists(db_path):
                with open(db_path, 'r') as f:
                    return json.load(f)
            else:
                self.logger.warning(f"Vulnerability database not found at {db_path}")
                return {}
        except Exception as e:
            self.logger.error(f"Error loading vulnerability database: {e}")
            return {}

    def analyze_banner(self, banner: bytes, port: int = None) -> Dict:
        """Comprehensive banner analysis"""
        try:
            banner_str = banner.decode('utf-8', errors='ignore')
            
            result = {
                'timestamp': datetime.now().isoformat(),
                'port': port,
                'service_info': self._identify_service(banner),
                'os_info': self._detect_os(banner),
                'versions': self._extract_versions(banner),
                'protocols': self._identify_protocols(banner),
                'security_issues': self._check_security_issues(banner),
                'vulnerabilities': self._check_vulnerabilities(banner, port),
                'metadata': self._extract_metadata(banner, port),
                'confidence_score': self._calculate_confidence(banner),
                'raw_banner': self._clean_banner(banner_str)
            }

            # Update statistics
            with self.lock:
                self.stats['total_analyzed'] += 1
                if result['service_info'].get('service'):
                    self.stats['services_identified'] += 1
                if result['vulnerabilities']:
                    self.stats['vulnerabilities_found'] += len(result['vulnerabilities'])

            return result

        except Exception as e:
            self.logger.error(f"Error analyzing banner: {e}")
            return {
                'error': str(e),
                'raw_banner': self._clean_banner(banner.decode('utf-8', errors='ignore'))
            }

    def _identify_service(self, banner: bytes) -> Dict:
        """Identify service and extract detailed information"""
        result = {
            'service': None,
            'product': None,
            'version': None,
            'extra_info': {}
        }

        # Check each service category
        for category, services in self.version_patterns.items():
            for service, patterns in services.items():
                for pattern in patterns:
                    match = re.search(pattern, banner)
                    if match:
                        result['service'] = service
                        if match.groups():
                            result['version'] = match.group(1).decode()
                        
                        # Extract additional information
                        if service in ['apache', 'nginx', 'iis']:
                            result['product'] = 'web_server'
                            result['extra_info'].update(
                                self._extract_web_server_info(banner)
                            )
                        elif service in ['mysql', 'postgresql', 'mongodb']:
                            result['product'] = 'database'
                            result['extra_info'].update(
                                self._extract_database_info(banner)
                            )
                        elif service in ['postfix', 'exchange', 'dovecot']:
                            result['product'] = 'mail_server'
                            result['extra_info'].update(
                                self._extract_mail_server_info(banner)
                            )
                        break

                if result['service']:
                    break

            if result['service']:
                break

        return result

    def _detect_os(self, banner: bytes) -> Dict:
        """Enhanced OS detection from banner"""
        result = {
            'os_family': None,
            'os_name': None,
            'version': None,
            'confidence': 0
        }

        # Check each OS family
        for family, types in self.os_patterns.items():
            for os_type, patterns in types.items():
                for pattern in patterns:
                    match = re.search(pattern, banner)
                    if match:
                        result['os_family'] = family
                        result['os_name'] = os_type
                        if match.groups():
                            result['version'] = match.group(1).decode()
                        result['confidence'] += 1

        # Normalize confidence score
        if result['confidence'] > 0:
            result['confidence'] = min(result['confidence'] * 25, 100)

        return result

    def _extract_versions(self, banner: bytes) -> List[Dict]:
        """Extract all version information from banner"""
        versions = []
        version_pattern = rb'(?i)(?:version|v)?[:\s/_-]+([0-9][0-9\.\-_]+)'
        
        # Find all version numbers
        for match in re.finditer(version_pattern, banner):
            try:
                version = match.group(1).decode()
                if self._validate_version_format(version):
                    versions.append({
                        'version': version,
                        'position': match.start(),
                        'context': banner[max(0, match.start()-10):
                                      min(len(banner), match.end()+10)].decode()
                    })
            except:
                continue

        return versions

    def _identify_protocols(self, banner: bytes) -> List[Dict]:
        """Identify protocols and their characteristics"""
        protocols = []

        for protocol, patterns in self.protocol_patterns.items():
            protocol_info = {
                'protocol': protocol,
                'features': [],
                'commands': [],
                'confidence': 0
            }

            # Check each feature category
            for category, category_patterns in patterns.items():
                for pattern in category_patterns:
                    matches = re.findall(pattern, banner)
                    if matches:
                        protocol_info['features'].extend(
                            [m.decode() if isinstance(m, bytes) else m
                            for m in matches]
                        )
                        protocol_info['confidence'] += 1

            if protocol_info['features']:
                protocols.append(protocol_info)

        # Sort by confidence  
        protocols.sort(key=lambda x: x['confidence'], reverse=True)
        return protocols
        
        # Sort by confidence
        protocols.sort(key=lambda x: x['confidence'], reverse=True)
        return protocols

    def _check_security_issues(self, banner: bytes) -> List[Dict]:
        """Check for security issues in banner"""
        issues = []

        for category, subcategories in self.security_patterns.items():
            for subcategory, patterns in subcategories.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, banner)
                    for match in matches:
                        issue = {
                            'category': category,
                            'type': subcategory,
                            'pattern': pattern.decode(),
                            'matched_text': match.group().decode(),
                            'position': match.start(),
                            'severity': self._determine_severity(category, subcategory),
                            'risk_description': self._get_risk_description(category, subcategory)
                        }
                        issues.append(issue)

        return issues

    def _check_vulnerabilities(self, banner: bytes, port: int) -> List[Dict]:
        """Check for known vulnerabilities"""
        vulns = []
        service_info = self._identify_service(banner)

        if not service_info['service'] or not service_info['version']:
            return vulns

        # Check vulnerability database
        service = service_info['service']
        version = service_info['version']

        for vuln_type, vuln_info in self.vuln_db.get('signatures', {}).get(service, {}).get('vulnerabilities', {}).items():
            if self._check_version_vulnerable(version, vuln_type):
                vuln = {
                    'service': service,
                    'version': version,
                    'cve_id': vuln_info.get('cve'),
                    'severity': vuln_info.get('severity', 'UNKNOWN'),
                    'description': vuln_info.get('description'),
                    'port': port,
                    'confidence': self._calculate_vuln_confidence(banner, vuln_info)
                }
                vulns.append(vuln)

        return vulns

    def _extract_metadata(self, banner: bytes, port: int) -> Dict:
        """Extract additional metadata from banner"""
        metadata = {
            'length': len(banner),
            'encoding': self._detect_encoding(banner),
            'contains_binary': not all(c < 128 for c in banner),
            'line_count': len(banner.split(b'\n')),
            'unique_chars': len(set(banner)),
            'port_info': self._get_port_info(port),
            'timestamp': datetime.now().isoformat()
        }

        # Additional protocol-specific metadata
        if b'HTTP/' in banner:
            metadata.update(self._extract_http_metadata(banner))
        elif b'SSH-' in banner:
            metadata.update(self._extract_ssh_metadata(banner))
        elif b'SMTP' in banner:
            metadata.update(self._extract_smtp_metadata(banner))

        return metadata

    def _calculate_confidence(self, banner: bytes) -> int:
        """Calculate confidence score for analysis"""
        score = 0
        
        # Service identification
        service_info = self._identify_service(banner)
        if service_info['service']:
            score += 30
            if service_info['version']:
                score += 20

        # OS detection
        os_info = self._detect_os(banner)
        if os_info['os_family']:
            score += 15
            if os_info['version']:
                score += 10

        # Protocol identification
        protocols = self._identify_protocols(banner)
        if protocols:
            score += len(protocols) * 5

        # Security issues
        security_issues = self._check_security_issues(banner)
        if security_issues:
            score += min(len(security_issues) * 2, 10)

        return min(score, 100)

    def _clean_banner(self, banner_str: str) -> str:
        """Clean sensitive information from banner"""
        # Replace sensitive patterns
        for category in self.security_patterns['sensitive_data'].values():
            for pattern in category:
                banner_str = re.sub(
                    pattern.decode(), 
                    '[REDACTED]', 
                    banner_str, 
                    flags=re.IGNORECASE
                )

        # Clean up whitespace
        banner_str = re.sub(r'\s+', ' ', banner_str).strip()
        return banner_str

    def _extract_web_server_info(self, banner: bytes) -> Dict:
        """Extract detailed web server information"""
        info = {
            'modules': [],
            'technologies': [],
            'headers': {}
        }

        # Extract HTTP headers
        header_pattern = rb'^([^:\r\n]+):\s*([^\r\n]+)'
        for match in re.finditer(header_pattern, banner, re.MULTILINE):
            key = match.group(1).decode().strip()
            value = match.group(2).decode().strip()
            info['headers'][key] = value

        # Detect modules and technologies
        module_patterns = [
            rb'mod_([a-zA-Z0-9_]+)',
            rb'PHP/([0-9\.]+)',
            rb'OpenSSL/([0-9\.]+)',
            rb'(FastCGI|CGI|WSGI|SCGI)',
            rb'(Python|Ruby|Perl|Node\.js)'
        ]

        for pattern in module_patterns:
            matches = re.finditer(pattern, banner)
            for match in matches:
                if match.groups():
                    info['modules'].append(match.group(1).decode())

        return info

    def _extract_database_info(self, banner: bytes) -> Dict:
        """Extract detailed database information"""
        info = {
            'protocol_version': None,
            'capabilities': [],
            'authentication': None,
            'connection_id': None
        }

        # Extract protocol version
        proto_match = re.search(rb'protocol_version\s*=?\s*([0-9\.]+)', banner)
        if proto_match:
            info['protocol_version'] = proto_match.group(1).decode()

        # Detect capabilities
        capability_patterns = [
            rb'compression',
            rb'SSL',
            rb'authentication',
            rb'unicode',
            rb'transactions'
        ]

        for pattern in capability_patterns:
            if re.search(pattern, banner, re.IGNORECASE):
                info['capabilities'].append(pattern.decode().lower())

        # Extract connection info
        conn_match = re.search(rb'connection[_-]id[:=]\s*(\d+)', banner, re.IGNORECASE)
        if conn_match:
            info['connection_id'] = int(conn_match.group(1))

        return info

    def _extract_mail_server_info(self, banner: bytes) -> Dict:
        """Extract detailed mail server information"""
        info = {
            'protocols': [],
            'auth_methods': [],
            'features': [],
            'domain': None
        }

        # Detect supported protocols
        protocol_patterns = [
            rb'ESMTP',
            rb'SMTP',
            rb'POP3',
            rb'IMAP',
            rb'TLS'
        ]

        for pattern in protocol_patterns:
            if re.search(pattern, banner):
                info['protocols'].append(pattern.decode())

        # Detect authentication methods
        auth_patterns = [
            rb'AUTH(?:\s+|=)([A-Z0-9-]+(?:\s+[A-Z0-9-]+)*)',
            rb'PLAIN',
            rb'LOGIN',
            rb'CRAM-MD5',
            rb'DIGEST-MD5'
        ]

        for pattern in auth_patterns:
            match = re.search(pattern, banner)
            if match:
                if match.groups():
                    methods = match.group(1).decode().split()
                    info['auth_methods'].extend(methods)
                else:
                    info['auth_methods'].append(pattern.decode())

        # Extract domain
        domain_match = re.search(rb'@([a-zA-Z0-9.-]+)', banner)
        if domain_match:
            info['domain'] = domain_match.group(1).decode()

        return info

    def _determine_severity(self, category: str, subcategory: str) -> str:
        """Determine severity level for security issues"""
        severity_matrix = {
            'information_disclosure': {
                'stack_trace': 'HIGH',
                'internal_paths': 'MEDIUM',
                'server_tokens': 'LOW'
            },
            'debug_info': {
                'debug_messages': 'MEDIUM',
                'development_info': 'MEDIUM'
            },
            'sensitive_data': {
                'credentials': 'CRITICAL',
                'email_addresses': 'MEDIUM',
                'private_keys': 'CRITICAL'
            }
        }

        return severity_matrix.get(category, {}).get(subcategory, 'MEDIUM')

    def _get_risk_description(self, category: str, subcategory: str) -> str:
        """Get risk description for security issues"""
        risk_descriptions = {
            'information_disclosure': {
                'stack_trace': 'Stack traces may reveal sensitive implementation details',
                'internal_paths': 'Internal paths may expose server file structure',
                'server_tokens': 'Server tokens reveal software versions'
            },
            'debug_info': {
                'debug_messages': 'Debug messages may contain sensitive information',
                'development_info': 'Development information may aid attackers'
            },
            'sensitive_data': {
                'credentials': 'Exposed credentials pose immediate security risk',
                'email_addresses': 'Email addresses may be used for targeted attacks',
                'private_keys': 'Exposed private keys compromise security'
            }
        }

        return risk_descriptions.get(category, {}).get(
            subcategory, 
            'Unknown security risk'
        )

    def _check_version_vulnerable(self, version: str, vuln_type: str) -> bool:
        """Check if version is vulnerable"""
        try:
            if not version or not vuln_type:
                return False

            # Parse version numbers
            ver_parts = [int(x) for x in version.split('.')]
            vuln_parts = [int(x) for x in vuln_type.split('.')]

            # Compare version numbers
            for i in range(max(len(ver_parts), len(vuln_parts))):
                ver_num = ver_parts[i] if i < len(ver_parts) else 0
                vuln_num = vuln_parts[i] if i < len(vuln_parts) else 0

                if ver_num < vuln_num:
                    return True
                elif ver_num > vuln_num:
                    return False

            return True

        except Exception as e:
            self.logger.debug(f"Error comparing versions: {e}")
            return False

    def _calculate_vuln_confidence(self, banner: bytes, vuln_info: Dict) -> int:
        """Calculate confidence score for vulnerability detection"""
        confidence = 0

        # Version match increases confidence
        if vuln_info.get('version_regex'):
            if re.search(
                vuln_info['version_regex'].encode(), 
                banner
            ):
                confidence += 40

        # Additional indicators increase confidence
        if vuln_info.get('indicators'):
            for indicator in vuln_info['indicators']:
                if re.search(indicator.encode(), banner):
                    confidence += 20

        return min(confidence, 100)

    def _validate_version_format(self, version: str) -> bool:
        """Validate version number format"""
        return bool(re.match(r'^[0-9][0-9\.\-_]+$', version))

    def _detect_encoding(self, banner: bytes) -> str:
        """Detect banner encoding"""
        try:
            banner.decode('ascii')
            return 'ascii'
        except UnicodeDecodeError:
            try:
                banner.decode('utf-8')
                return 'utf-8'
            except UnicodeDecodeError:
                return 'binary'

    def _get_port_info(self, port: int) -> Dict:
        """Get information about port number"""
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            465: 'SMTPS',
            587: 'Submission',
            993: 'IMAPS',
            995: 'POP3S',
            3306: 'MySQL',
            5432: 'PostgreSQL'
        }

        return {
            'port': port,
            'is_well_known': port < 1024,
            'is_registered': 1024 <= port <= 49151,
            'is_dynamic': port > 49151,
            'common_service': common_ports.get(port, 'Unknown')
        }

    def _extract_http_metadata(self, banner: bytes) -> Dict:
        """Extract HTTP-specific metadata"""
        metadata = {
            'status_code': None,
            'headers': {},
            'server_software': None
        }

        # Extract status code
        status_match = re.search(rb'HTTP/\d\.\d (\d{3})', banner)
        if status_match:
            metadata['status_code'] = int(status_match.group(1))

        # Extract headers
        header_pattern = rb'^([^:\r\n]+):\s*([^\r\n]+)'
        for match in re.finditer(header_pattern, banner, re.MULTILINE):
            key = match.group(1).decode().strip()
            value = match.group(2).decode().strip()
            metadata['headers'][key] = value

        # Extract server software
        if metadata['headers'].get('Server'):
            metadata['server_software'] = metadata['headers']['Server']

        return metadata

    def _extract_ssh_metadata(self, banner: bytes) -> Dict:
        """Extract SSH-specific metadata"""
        metadata = {
            'protocol_version': None,
            'software': None,
            'os_info': None
        }

        # Extract SSH version and software
        ssh_match = re.search(rb'SSH-(\d\.\d)-([^\s\r\n]+)', banner)
        if ssh_match:
            metadata['protocol_version'] = ssh_match.group(1).decode()
            metadata['software'] = ssh_match.group(2).decode()

        # Extract OS information
        os_match = re.search(rb'SSH.*?([A-Za-z]+(?:OS|BSD|Linux)[^\s\r\n]*)', banner)
        if os_match:
            metadata['os_info'] = os_match.group(1).decode()

        return metadata
        
        def _extract_smtp_metadata(self, banner: bytes) -> Dict:
            """Extract SMTP-specific metadata"""
        metadata = {
            'greeting': None,
            'domain': None,
            'features': []
        }

        # Extract greeting
        greeting_match = re.search(rb'220[- ]([^\r\n]+)', banner)
        if greeting_match:
            metadata['greeting'] = greeting_match.group(1).decode()

        # Extract domain
        domain_match = re.search(rb'(?:@|[^a-zA-Z])([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}})', banner)
        if domain_match:
            metadata['domain'] = domain_match.group(1).decode()

        # Extract SMTP features
        feature_patterns = [
            rb'STARTTLS',
            rb'AUTH\s+[^\r\n]+',
            rb'SIZE\s+\d+',
            rb'PIPELINING',
            rb'SMTPUTF8',
            rb'8BITMIME'
        ]

        for pattern in feature_patterns:
            if re.search(pattern, banner):
                match = re.search(pattern, banner)
                metadata['features'].append(match.group().decode())

        return metadata
    
        def get_analysis_stats(self) -> Dict:
            """Get statistics about banner analysis"""
        with self.lock:
            return {
                'total_analyzed': self.stats['total_analyzed'],
                'services_identified': self.stats['services_identified'],
                'vulnerabilities_found': self.stats['vulnerabilities_found'],
                'last_update': datetime.now().isoformat()
            }

    def scan_vulnerabilities(self, banner: bytes, port: int = None) -> List[Dict]:
        """Dedicated vulnerability scanner"""
        vulnerabilities = []
        service_info = self._identify_service(banner)

        if not service_info['service'] or not service_info['version']:
            return vulnerabilities

        # Known vulnerability checks
        for vuln_type, vuln_info in self.vuln_db.get('signatures', {}).get(service_info['service'], {}).get('vulnerabilities', {}).items():
            if self._check_version_vulnerable(service_info['version'], vuln_type):
                vuln = {
                    'type': 'known_vulnerability',
                    'service': service_info['service'],
                    'version': service_info['version'],
                    'cve_id': vuln_info.get('cve'),
                    'severity': vuln_info.get('severity', 'UNKNOWN'),
                    'description': vuln_info.get('description'),
                    'port': port,
                    'confidence': self._calculate_vuln_confidence(banner, vuln_info)
                }
                vulnerabilities.append(vuln)

        # Configuration vulnerabilities
        config_vulns = self._check_config_vulnerabilities(banner, service_info['service'])
        vulnerabilities.extend(config_vulns)

        # Protocol-specific vulnerabilities
        protocol_vulns = self._check_protocol_vulnerabilities(banner, service_info['service'])
        vulnerabilities.extend(protocol_vulns)

        return vulnerabilities

    def _check_config_vulnerabilities(self, banner: bytes, service: str) -> List[Dict]:
        """Check for configuration-based vulnerabilities"""
        vulns = []

        # Common security headers check for web servers
        if service in ['apache', 'nginx', 'iis']:
            headers = {
                'X-Frame-Options': 'Missing clickjacking protection',
                'X-Content-Type-Options': 'Missing MIME-type protection',
                'X-XSS-Protection': 'Missing XSS protection',
                'Strict-Transport-Security': 'Missing HSTS',
                'Content-Security-Policy': 'Missing CSP'
            }

            for header, description in headers.items():
                if header.encode() not in banner:
                    vulns.append({
                        'type': 'missing_security_header',
                        'header': header,
                        'description': description,
                        'severity': 'MEDIUM',
                        'confidence': 90
                    })

        # Default credentials check
        default_creds_patterns = [
            rb'admin:admin',
            rb'root:root',
            rb'guest:guest',
            rb'test:test'
        ]

        for pattern in default_creds_patterns:
            if re.search(pattern, banner):
                vulns.append({
                    'type': 'default_credentials',
                    'description': 'Default credentials detected',
                    'severity': 'CRITICAL',
                    'confidence': 95
                })

        # Debug mode check
        debug_patterns = [
            rb'[Dd]ebug[_ ]mode',
            rb'DEVELOPMENT[_ ]MODE',
            rb'[Tt]est[_ ]mode'
        ]

        for pattern in debug_patterns:
            if re.search(pattern, banner):
                vulns.append({
                    'type': 'debug_mode',
                    'description': 'Debug/Development mode enabled',
                    'severity': 'HIGH',
                    'confidence': 85
                })

        return vulns

    def _check_protocol_vulnerabilities(self, banner: bytes, service: str) -> List[Dict]:
        """Check for protocol-specific vulnerabilities"""
        vulns = []

        if service == 'ssh':
            # Check for weak SSH algorithms
            weak_algos = [
                rb'arcfour',
                rb'des',
                rb'md5',
                rb'diffie-hellman-group1'
            ]

            for algo in weak_algos:
                if re.search(algo, banner, re.IGNORECASE):
                    vulns.append({
                        'type': 'weak_algorithm',
                        'algorithm': algo.decode(),
                        'description': f'Weak SSH algorithm detected: {algo.decode()}',
                        'severity': 'HIGH',
                        'confidence': 90
                    })

        elif service in ['smtp', 'pop3', 'imap']:
            # Check for clear-text authentication
            if not re.search(rb'STARTTLS', banner, re.IGNORECASE):
                vulns.append({
                    'type': 'missing_encryption',
                    'description': 'Clear-text authentication possible (STARTTLS not advertised)',
                    'severity': 'HIGH',
                    'confidence': 85
                })

        elif service in ['http', 'https']:
            # Check for weak SSL/TLS configurations
            weak_ssl = [
                rb'SSLv2',
                rb'SSLv3',
                rb'TLSv1\.0',
                rb'TLSv1\.1'
            ]

            for protocol in weak_ssl:
                if re.search(protocol, banner):
                    vulns.append({
                        'type': 'weak_ssl_protocol',
                        'protocol': protocol.decode(),
                        'description': f'Weak SSL/TLS protocol detected: {protocol.decode()}',
                        'severity': 'HIGH',
                        'confidence': 90
                    })

        return vulns

    def _load_cpe_database(self) -> Dict:
        """Load CPE (Common Platform Enumeration) database"""
        cpe_db = {}
        try:
            with open('cpe_database.json', 'r') as f:
                cpe_db = json.load(f)
        except Exception as e:
            self.logger.error(f"Error loading CPE database: {e}")
        return cpe_db

    def _generate_cpe(self, service_info: Dict) -> str:
        """Generate CPE identifier"""
        try:
            if not service_info.get('service') or not service_info.get('version'):
                return None

            service = service_info['service']
            version = service_info['version']

            cpe = f"cpe:/a:"
            
            if service == 'apache':
                cpe += f"apache:http_server:{version}"
            elif service == 'nginx':
                cpe += f"nginx:nginx:{version}"
            elif service == 'openssh':
                cpe += f"openbsd:openssh:{version}"
            elif service == 'mysql':
                cpe += f"mysql:mysql:{version}"
            elif service == 'postgresql':
                cpe += f"postgresql:postgresql:{version}"
            else:
                return None

            return cpe

        except Exception as e:
            self.logger.error(f"Error generating CPE: {e}")
            return None

    def _generate_html_report(self, analysis_results: Dict) -> str:
        """Generate HTML report of analysis results"""
        html = """
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; }
                .vulnerability { color: red; }
                .warning { color: orange; }
                .info { color: blue; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
        """

        # Add summary section
        html += "<h2>Analysis Summary</h2>"
        html += f"<p>Timestamp: {analysis_results['timestamp']}</p>"
        if analysis_results['port']:
            html += f"<p>Port: {analysis_results['port']}</p>"

        # Add service information
        if analysis_results['service_info']:
            html += "<h3>Service Information</h3>"
            html += "<table>"
            for key, value in analysis_results['service_info'].items():
                html += f"<tr><th>{key}</th><td>{value}</td></tr>"
            html += "</table>"

        # Add vulnerabilities section
        if analysis_results['vulnerabilities']:
            html += "<h3>Vulnerabilities</h3>"
            html += "<table>"
            html += "<tr><th>Type</th><th>Severity</th><th>Description</th></tr>"
            for vuln in analysis_results['vulnerabilities']:
                html += f"""
                <tr class="vulnerability">
                    <td>{vuln['type']}</td>
                    <td>{vuln['severity']}</td>
                    <td>{vuln['description']}</td>
                </tr>
                """
            html += "</table>"

        # Add security issues section
        if analysis_results['security_issues']:
            html += "<h3>Security Issues</h3>"
            html += "<table>"
            html += "<tr><th>Category</th><th>Type</th><th>Severity</th></tr>"
            for issue in analysis_results['security_issues']:
                html += f"""
                <tr class="warning">
                    <td>{issue['category']}</td>
                    <td>{issue['type']}</td>
                    <td>{issue['severity']}</td>
                </tr>
                """
            html += "</table>"

        html += "</body></html>"
        return html

    def save_results(self, analysis_results: Dict, output_format: str = 'json') -> None:
        """Save analysis results to file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"banner_analysis_{timestamp}"

        try:
            if output_format == 'json':
                with open(f"{filename}.json", 'w') as f:
                    json.dump(analysis_results, f, indent=2)
            elif output_format == 'html':
                html_report = self._generate_html_report(analysis_results)
                with open(f"{filename}.html", 'w') as f:
                    f.write(html_report)
            elif output_format == 'txt':
                with open(f"{filename}.txt", 'w') as f:
                    self._write_text_report(f, analysis_results)
        except Exception as e:
            self.logger.error(f"Error saving results: {e}")

    def _write_text_report(self, file, results: Dict) -> None:
        """Write analysis results in text format"""
        file.write("Banner Analysis Report\n")
        file.write("=" * 50 + "\n\n")

        file.write(f"Timestamp: {results['timestamp']}\n")
        if results['port']:
            file.write(f"Port: {results['port']}\n")
        file.write("\n")

        if results['service_info']:
            file.write("Service Information\n")
            file.write("-" * 20 + "\n")
            for key, value in results['service_info'].items():
                file.write(f"{key}: {value}\n")
            file.write("\n")

        if results['vulnerabilities']:
            file.write("Vulnerabilities\n")
            file.write("-" * 20 + "\n")
            for vuln in results['vulnerabilities']:
                file.write(f"Type: {vuln['type']}\n")
                file.write(f"Severity: {vuln['severity']}\n")
                file.write(f"Description: {vuln['description']}\n")
                file.write("-" * 20 + "\n")
            file.write("\n")

        if results['security_issues']:
            file.write("Security Issues\n")
            file.write("-" * 20 + "\n")
            for issue in results['security_issues']:
                file.write(f"Category: {issue['category']}\n")
                file.write(f"Type: {issue['type']}\n")
                file.write(f"Severity: {issue['severity']}\n")
                file.write("-" * 20 + "\n")
                
    
    def analyze_vulnerabilities(self, banner: bytes, port: int = None) -> List[Dict]:
        """Analyze banner for vulnerabilities"""
        vulns = []
        service_info = self._identify_service(banner)
        
        if service_info.get('service') and service_info.get('version'):
            # Check known vulnerabilities
            if service_info['service'] in self.vuln_db.get('signatures', {}):
                service_vulns = self.vuln_db['signatures'][service_info['service']].get('vulnerabilities', {})
                for vuln_id, vuln_info in service_vulns.items():
                    if self._check_version_vulnerable(service_info['version'], vuln_info.get('affected_versions', [])):
                        vulns.append({
                            'type': 'known_vulnerability',
                            'service': service_info['service'],
                            'version': service_info['version'],
                            'vuln_id': vuln_id,
                            'description': vuln_info.get('description'),
                            'severity': vuln_info.get('severity', 'UNKNOWN'),
                            'cve': vuln_info.get('cve'),
                            'port': port
                        })
                        
        return vulns