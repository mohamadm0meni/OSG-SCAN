import socket
import ssl
import time
import random
from typing import Dict, Optional, List
from Config import Config
import re

class MailProtocolTester:
    """Advanced class for testing email protocols"""

    def __init__(self):
        self.config = Config()
        self.ssl_context = self._create_ssl_context()
        
        # Advanced test settings
        self.test_settings = {
            'verify_starttls': True,
            'check_auth_methods': True,
            'test_capabilities': True,
            'verify_banner': True,
            'analyze_security': True
        }

        # Server version detection patterns
        self.version_patterns = {
            'postfix': rb'Postfix \(([^\)]+)\)',
            'exchange': rb'Microsoft Exchange Server ([0-9\.]+)',
            'dovecot': rb'Dovecot \(([^\)]+)\)',
            'sendmail': rb'Sendmail ([0-9\.]+)',
            'exim': rb'Exim ([0-9\.]+)'
        }

        # Known vulnerabilities
        self.known_vulnerabilities = {
            'postfix': {
                '2.': {'cve': 'CVE-2019-10799', 'severity': 'MEDIUM'},
                '3.1.': {'cve': 'CVE-2020-7016', 'severity': 'HIGH'}
            },
            'exchange': {
                '2013': {'cve': 'CVE-2020-0688', 'severity': 'CRITICAL'},
                '2016': {'cve': 'CVE-2021-26855', 'severity': 'CRITICAL'}
            }
        }

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context with secure settings"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers('ALL:@SECLEVEL=1')
        return ctx

    def test_smtp(self, sock: socket.socket, use_ssl: bool = False) -> Dict:
        """Advanced test for SMTP service"""
        result = {
            'service': 'SMTP',
            'protocol': 'tcp/ssl' if use_ssl else 'tcp',
            'banner': None,
            'capabilities': [],
            'auth_methods': [],
            'security_features': {},
            'vulnerabilities': []
        }

        try:
            if use_ssl:
                sock = self.ssl_context.wrap_socket(sock)

            # Receive initial banner
            banner = sock.recv(1024)
            result['banner'] = banner
            
            if not banner or not self._validate_smtp_banner(banner):
                return {}

            # Analyze banner and server version
            server_info = self._analyze_smtp_banner(banner)
            result.update(server_info)

            # Test EHLO
            capabilities = self._test_smtp_capabilities(sock)
            result.update(capabilities)

            # Test STARTTLS if supported
            if 'STARTTLS' in result.get('capabilities', []):
                starttls_result = self._test_smtp_starttls(sock)
                result['security_features']['starttls'] = starttls_result

            # Test authentication methods
            if self.test_settings['check_auth_methods']:
                auth_methods = self._check_smtp_auth(sock)
                result['auth_methods'] = auth_methods

            # Security analysis
            self._analyze_smtp_security(result)

        except Exception as e:
            result['error'] = str(e)

        return result

    def test_pop3(self, sock: socket.socket, use_ssl: bool = False) -> Dict:
        """Advanced test for POP3 service"""
        result = {
            'service': 'POP3',
            'protocol': 'tcp/ssl' if use_ssl else 'tcp',
            'banner': None,
            'capabilities': [],
            'security_features': {},
            'vulnerabilities': []
        }

        try:
            if use_ssl:
                sock = self.ssl_context.wrap_socket(sock)

            # Receive initial banner
            banner = sock.recv(1024)
            if not banner or not self._validate_pop3_banner(banner):
                return {}

            result['banner'] = banner
            
            # Analyze banner and server version
            server_info = self._analyze_pop3_banner(banner)
            result.update(server_info)

            # Test capabilities
            sock.send(b'CAPA\r\n')
            capa_response = sock.recv(1024)
            if b'+OK' in capa_response:
                capabilities = self._parse_pop3_capabilities(capa_response)
                result['capabilities'] = capabilities

                # Test STLS if supported
                if 'STLS' in capabilities:
                    stls_result = self._test_pop3_stls(sock)
                    result['security_features']['stls'] = stls_result

            # Security analysis
            self._analyze_pop3_security(result)

        except Exception as e:
            result['error'] = str(e)

        return result

    def test_imap(self, sock: socket.socket, use_ssl: bool = False) -> Dict:
        """Advanced test for IMAP service"""
        result = {
            'service': 'IMAP',
            'protocol': 'tcp/ssl' if use_ssl else 'tcp',
            'banner': None,
            'capabilities': [],
            'security_features': {},
            'vulnerabilities': []
        }

        try:
            if use_ssl:
                sock = self.ssl_context.wrap_socket(sock)

            # Receive initial banner
            banner = sock.recv(1024)
            if not banner or not self._validate_imap_banner(banner):
                return {}

            result['banner'] = banner
            
            # Analyze banner and server version
            server_info = self._analyze_imap_banner(banner)
            result.update(server_info)

            # Test capabilities
            sock.send(b'a001 CAPABILITY\r\n')
            cap_response = sock.recv(1024)
            if b'* CAPABILITY' in cap_response:
                capabilities = self._parse_imap_capabilities(cap_response)
                result['capabilities'] = capabilities

                # Test STARTTLS if supported
                if 'STARTTLS' in capabilities:
                    starttls_result = self._test_imap_starttls(sock)
                    result['security_features']['starttls'] = starttls_result

            # Security analysis
            self._analyze_imap_security(result)

        except Exception as e:
            result['error'] = str(e)

        return result

    def _validate_smtp_banner(self, banner: bytes) -> bool:
        """Validate SMTP banner"""
        return (banner.startswith(b'220') and 
                (b'SMTP' in banner or b'ESMTP' in banner))

    def _analyze_smtp_banner(self, banner: bytes) -> Dict:
        """Analyze SMTP banner and detect version"""
        info = {'server_type': 'unknown', 'version': None}
        
        for server_type, pattern in self.version_patterns.items():
            match = re.search(pattern, banner)
            if match:
                info['server_type'] = server_type
                info['version'] = match.group(1).decode()
                break

        return info

    def _test_smtp_capabilities(self, sock: socket.socket) -> Dict:
        """Test SMTP capabilities"""
        capabilities = []
        try:
            sock.send(b'EHLO test.local\r\n')
            response = self._receive_all(sock)
            
            if b'250' in response:
                for line in response.split(b'\r\n'):
                    if line.startswith(b'250-'):
                        cap = line[4:].decode().strip()
                        capabilities.append(cap)

        except Exception:
            pass

        return {'capabilities': capabilities}

    def _test_smtp_starttls(self, sock: socket.socket) -> Dict:
        """Test STARTTLS in SMTP"""
        result = {'supported': False, 'successful': False}
        
        try:
            sock.send(b'STARTTLS\r\n')
            response = sock.recv(1024)
            
            if b'220' in response:
                result['supported'] = True
                ssl_sock = self.ssl_context.wrap_socket(sock)
                ssl_sock.do_handshake()
                result['successful'] = True
                result['protocol'] = ssl_sock.version()
                result['cipher'] = ssl_sock.cipher()
        except:
            pass

        return result

    def _analyze_smtp_security(self, result: Dict) -> None:
        """Security analysis for SMTP service"""
        # Check SSL/TLS settings
        if not result.get('security_features', {}).get('starttls', {}).get('supported'):
            result['vulnerabilities'].append({
                'type': 'missing_starttls',
                'severity': 'HIGH',
                'description': 'STARTTLS is not supported'
            })

        # Check authentication methods
        auth_methods = result.get('auth_methods', [])
        if 'PLAIN' in auth_methods:
            result['vulnerabilities'].append({
                'type': 'weak_auth',
                'severity': 'MEDIUM',
                'description': 'Plain text authentication is enabled'
            })

        # Check for vulnerable versions
        server_type = result.get('server_type')
        version = result.get('version')
        if server_type and version:
            for ver_prefix, vuln_info in self.known_vulnerabilities.get(server_type, {}).items():
                if version.startswith(ver_prefix):
                    result['vulnerabilities'].append({
                        'type': 'version_vulnerability',
                        'severity': vuln_info['severity'],
                        'cve': vuln_info['cve'],
                        'description': f'Known vulnerability in {server_type} version {version}'
                    })

    def verify_mail_service(self, sock: socket.socket, port: int) -> Dict:
        """Detect and test the type of email service"""
        # Detect service type based on port
        if port in [25, 587]:
            return self.test_smtp(sock)
        elif port == 465:
            return self.test_smtp(sock, use_ssl=True)
        elif port == 110:
            return self.test_pop3(sock)
        elif port == 995:
            return self.test_pop3(sock, use_ssl=True)
        elif port == 143:
            return self.test_imap(sock)
        elif port == 993:
            return self.test_imap(sock, use_ssl=True)
            
        return {}
        
    def _receive_all(self, sock: socket.socket, timeout: float = 2.0) -> bytes:
        """Receive all data from the socket"""
        sock.settimeout(timeout)
        data = []
        try:
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                data.append(chunk)
        except socket.timeout:
            pass
        
        return b''.join(data)
