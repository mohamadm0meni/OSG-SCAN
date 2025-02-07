import socket
import ssl
import re
import logging
from typing import Dict, Optional, List, Tuple
from concurrent.futures import ThreadPoolExecutor
import struct
import random
import threading
from collections import defaultdict

class ServiceDetector:
    def __init__(self, target: str):
        self.target = target
        self.ssl_context = self._create_ssl_context()
        self.logger = logging.getLogger(__name__)
        self.lock = threading.Lock()
        
        # Enhanced protocol signatures for major services
        self.web_signatures = {
            'http': {
                'patterns': [
                    rb'HTTP/[0-9\.]+ [0-9]{3}',
                    rb'Server:',
                    rb'<html',
                    rb'<!DOCTYPE',
                    rb'Content-Type:',
                    rb'Set-Cookie:',
                    rb'Location:',
                    rb'X-Powered-By:',
                    rb'ETag:',
                    rb'Apache',
                    rb'nginx',
                    rb'Microsoft-IIS'
                ],
                'probes': [
                    b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n',
                    b'HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n',
                    b'OPTIONS / HTTP/1.1\r\nHost: localhost\r\n\r\n'
                ]
            }
        }
        
        self.db_signatures = {
            'mysql': {
                'patterns': [
                    rb'\x4a\x00\x00\x00',  # Protocol v10
                    rb'mysql_native_password',
                    rb'MariaDB',
                    rb'\x00\x00\x00\x0a'   # Handshake packet
                ],
                'probes': [
                    b'\x00\x00\x01\x85\xa6\x3f\x20',  # Handshake probe
                ]
            },
            'postgresql': {
                'patterns': [
                    rb'PostgreSQL',
                    rb'PGSQL',
                    rb'Invalid packet length'
                ],
                'probes': [
                    b'\x00\x00\x00\x08\x04\xd2\x16\x2f'  # Startup message
                ]
            }
        }
        
        self.mail_signatures = {
            'smtp': {
                'patterns': [
                    rb'^220.*SMTP',
                    rb'^220.*Postfix',
                    rb'^220.*Exim',
                    rb'^220.*Exchange'
                ],
                'probes': [
                    b'EHLO test\r\n',
                    b'HELO test\r\n'
                ]
            },
            'pop3': {
                'patterns': [
                    rb'\+OK',
                    rb'POP3',
                    rb'ready',
                    rb'Dovecot'
                ],
                'probes': [
                    b'CAPA\r\n',
                    b'USER test\r\n'
                ]
            }
        }
        
        self.ssh_signatures = {
            'patterns': [
                rb'SSH-[12]\.[0-9]',
                rb'OpenSSH',
                rb'^SSH-2\.0-',
                rb'dropbear'
            ],
            'probes': [
                b'SSH-2.0-OpenSSH_8.2p1\r\n'
            ]
        }

        self.ftp_signatures = {
            'patterns': [
                rb'^220.*FTP',
                rb'^230.*login',
                rb'vsFTPd',
                rb'FileZilla'
            ],
            'probes': [
                b'USER anonymous\r\n',
                b'SYST\r\n'
            ]
        }

        # Additional service probes
        self.probes = {
            'http': [
                {
                    'send': b'GET / HTTP/1.0\r\n\r\n',
                    'expect': rb'HTTP/[0-9\.]+'
                },
                {
                    'send': b'HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n',
                    'expect': rb'Server:'
                }
            ],
            'https': [
                {
                    'ssl': True,
                    'send': b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n',
                    'expect': rb'HTTP/[0-9\.]+'
                }
            ],
            'ssh': [
                {
                    'send': b'SSH-2.0-OpenSSH_8.2p1\r\n',
                    'expect': rb'SSH-2\.0-'
                }
            ]
        }

        # Service-specific timeouts
        self.timeouts = {
            'http': 5,
            'https': 7,
            'ssh': 3,
            'smtp': 5,
            'mysql': 3,
            'postgresql': 3
        }

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context with enhanced security options"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers('ALL:@SECLEVEL=1')
        ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
        return ctx

    def detect_service(self, port: int) -> Optional[Dict]:
        """Enhanced service detection with multiple probes and fallback"""
        result = {
            'service': None,
            'version': None,
            'banner': None,
            'protocol': 'tcp',
            'ssl': False,
            'hostname': self.target,
            'products': [],
            'cpe': None
        }

        try:
            # Try SSL first for known HTTPS ports
            if port in [443, 8443, 4443]:
                ssl_result = self._test_ssl_service(port)
                if ssl_result:
                    return ssl_result

            # Try regular connection
            sock = self._create_socket(port)
            if not sock:
                return None

            # First try without sending data (banner grab)
            try:
                banner = sock.recv(2048)
                if banner:
                    result['banner'] = banner
                    service_info = self._identify_service_from_banner(banner, port)
                    if service_info:
                        result.update(service_info)
            except:
                pass

            # If no service identified, try probes
            if not result['service']:
                result.update(self._probe_service(sock, port))

            # Try SSL upgrade if not identified
            if not result['service'] and self._test_ssl(sock):
                result['ssl'] = True
                ssl_sock = self.ssl_context.wrap_socket(sock)
                ssl_result = self._probe_service(ssl_sock, port)
                if ssl_result:
                    result.update(ssl_result)

            # Additional protocol-specific tests
            if result['service']:
                details = self._get_service_details(sock, result['service'], port)
                result.update(details)

            return result

        except Exception as e:
            self.logger.error(f"Error detecting service on port {port}: {e}")
            return None
        finally:
            if 'sock' in locals():
                self._close_socket(sock)

    def _test_ssl_service(self, port: int) -> Optional[Dict]:
        """Test for SSL/TLS service"""
        try:
            sock = self._create_socket(port)
            if not sock:
                return None

            ssl_sock = self.ssl_context.wrap_socket(sock)
            
            # Get SSL details
            result = {
                'service': 'https',
                'ssl': True,
                'protocol': 'tcp',
                'ssl_details': {
                    'version': ssl_sock.version(),
                    'cipher': ssl_sock.cipher(),
                    'cert': self._get_cert_info(ssl_sock)
                }
            }

            # Try HTTP probe over SSL
            http_result = self._probe_http(ssl_sock)
            if http_result:
                result.update(http_result)

            return result

        except Exception as e:
            self.logger.debug(f"SSL test failed on port {port}: {e}")
            return None
        finally:
            if 'sock' in locals():
                self._close_socket(sock)

    def _probe_service(self, sock: socket.socket, port: int) -> Dict:
        """Send multiple probes to identify service"""
        result = {}

        # Try protocol-specific probes
        for service, probe_list in self.probes.items():
            for probe in probe_list:
                try:
                    if probe.get('ssl') and not isinstance(sock, ssl.SSLSocket):
                        continue

                    sock.send(probe['send'])
                    response = sock.recv(2048)

                    if response and re.search(probe['expect'], response):
                        result['service'] = service
                        result['banner'] = response
                        version = self._extract_version(response)
                        if version:
                            result['version'] = version
                        break

                except Exception as e:
                    continue

            if result.get('service'):
                break

        # Try additional protocol detection
        if not result.get('service'):
            if self._test_ssh(sock):
                result['service'] = 'ssh'
            elif self._test_http(sock):
                result['service'] = 'http'
            elif self._test_smtp(sock):
                result['service'] = 'smtp'

        return result

    def _identify_service_from_banner(self, banner: bytes, port: int) -> Optional[Dict]:
        """Identify service from initial banner"""
        result = {}

        # Check against all signature patterns
        signatures = {
            'http': self.web_signatures['http']['patterns'],
            'mysql': self.db_signatures['mysql']['patterns'],
            'postgresql': self.db_signatures['postgresql']['patterns'],
            'smtp': self.mail_signatures['smtp']['patterns'],
            'pop3': self.mail_signatures['pop3']['patterns'],
            'ssh': self.ssh_signatures['patterns'],
            'ftp': self.ftp_signatures['patterns']
        }

        for service, patterns in signatures.items():
            for pattern in patterns:
                if re.search(pattern, banner, re.IGNORECASE):
                    result['service'] = service
                    version = self._extract_version(banner)
                    if version:
                        result['version'] = version
                    return result

        # Common port check as fallback
        common_ports = {
            80: 'http',
            443: 'https',
            22: 'ssh',
            21: 'ftp',
            25: 'smtp',
            110: 'pop3',
            143: 'imap',
            3306: 'mysql',
            5432: 'postgresql'
        }

        if port in common_ports and not result.get('service'):
            result['service'] = common_ports[port]

        return result

    def _get_service_details(self, sock: socket.socket, service: str, port: int) -> Dict:
        """Get additional service-specific details"""
        details = {}

        if service == 'http':
            details = self._get_http_details(sock)
        elif service == 'ssh':
            details = self._get_ssh_details(sock)
        elif service == 'smtp':
            details = self._get_smtp_details(sock)
        elif service == 'mysql':
            details = self._get_mysql_details(sock)

        return details

    def _get_http_details(self, sock: socket.socket) -> Dict:
        """Get detailed HTTP server information"""
        details = {}
        try:
            # Send HTTP request with multiple headers
            request = (
                "GET / HTTP/1.1\r\n"
                f"Host: {self.target}\r\n"
                "User-Agent: Mozilla/5.0\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n\r\n"
            )
            sock.send(request.encode())
            
            response = sock.recv(4096)
            if response:
                # Parse headers
                headers = {}
                try:
                    header_lines = response.split(b'\r\n\r\n')[0].split(b'\r\n')
                    for line in header_lines[1:]:
                        if b':' in line:
                            key, value = line.split(b':', 1)
                            headers[key.strip().decode()] = value.strip().decode()
                except:
                    pass

                details['headers'] = headers
                
                # Extract server software
                if 'Server' in headers:
                    details['server'] = headers['Server']
                    
                # Extract technologies
                techs = []
                if 'X-Powered-By' in headers:
                    techs.append(headers['X-Powered-By'])
                if 'X-AspNet-Version' in headers:
                    techs.append(f"ASP.NET {headers['X-AspNet-Version']}")
                    
                details['technologies'] = techs

        except Exception as e:
            self.logger.debug(f"Error getting HTTP details: {e}")

        return details

    def _get_ssh_details(self, sock: socket.socket) -> Dict:
        """Get detailed SSH server information"""
        details = {}
        try:
            banner = sock.recv(1024)
            if banner:
                # Extract version
                match = re.search(rb'SSH-2\.0-([^\r\n]+)', banner)
                if match:
                    details['version'] = match.group(1).decode()
                    
                # Identify software
                if b'OpenSSH' in banner:
                    details['software'] = 'OpenSSH'
                elif b'dropbear' in banner:
                    details['software'] = 'Dropbear'
                    
                # Extract OS info if available
                if b'Ubuntu' in banner:
                    details['os'] = 'Ubuntu'
                elif b'Debian' in banner:
                    details['os'] = 'Debian'

        except Exception as e:
            self.logger.debug(f"Error getting SSH details: {e}")

        return details

    def _get_smtp_details(self, sock: socket.socket) -> Dict:
        """Get detailed SMTP server information"""
        details = {}
        try:
            # Send EHLO command
            sock.send(b'EHLO test\r\n')
            response = sock.recv(1024)
            
            if response:
                # Extract capabilities
                capabilities = []
                for line in response.split(b'\r\n'):
                    if line.startswith(b'250-'):
                        cap = line[4:].decode()
                        capabilities.append(cap)
                        
                details['capabilities'] = capabilities
                
                # Identify software
                if b'Postfix' in response:
                    details['software'] = 'Postfix'
                if b'Exchange' in response:
                    details['software'] = 'Microsoft Exchange'
                elif b'Exim' in response:
                    details['software'] = 'Exim'

        except Exception as e:
            self.logger.debug(f"Error getting SMTP details: {e}")

        return details

    def _get_mysql_details(self, sock: socket.socket) -> Dict:
        """Get detailed MySQL server information"""
        details = {}
        try:
            initial_packet = sock.recv(1024)
            if not initial_packet or len(initial_packet) < 5:
                return details

            # Parse protocol version
            protocol_ver = initial_packet[4]
            details['protocol_version'] = protocol_ver

            # Parse server version
            idx = 5
            version_end = initial_packet.find(b'\x00', idx)
            if version_end > idx:
                version = initial_packet[idx:version_end].decode('utf-8', errors='ignore')
                details['version'] = version

                # Identify distribution
                if 'MariaDB' in version:
                    details['distribution'] = 'MariaDB'
                else:
                    details['distribution'] = 'MySQL'

            # Extract thread ID
            if len(initial_packet) >= version_end + 5:
                thread_id = struct.unpack('<I', initial_packet[version_end+1:version_end+5])[0]
                details['thread_id'] = thread_id

        except Exception as e:
            self.logger.debug(f"Error getting MySQL details: {e}")

        return details

    def _extract_version(self, banner: bytes) -> Optional[str]:
        """Extract version information from banner with enhanced patterns"""
        version_patterns = [
            # General version patterns
            rb'(?i)version[:\s]+([0-9][0-9\.\-_]+)',
            rb'(?i)/([0-9][0-9\.\-_]+)',
            rb'(?i)([0-9]+\.[0-9]+[\.0-9]*)',
            
            # Web servers
            rb'(?i)Apache(?:/?([0-9][0-9\.\-_]+))?',
            rb'(?i)nginx/?([0-9][0-9\.\-_]+)',
            rb'(?i)Microsoft-IIS/?([0-9][0-9\.\-_]+)',
            
            # SSH
            rb'OpenSSH[_-]([0-9][0-9\.\-_]+)',
            rb'SSH-2\.0-OpenSSH_([0-9][0-9\.\-_]+)',
            
            # Databases
            rb'MySQL(?:/?([0-9][0-9\.\-_]+))?',
            rb'MariaDB-([0-9][0-9\.\-_]+)',
            rb'PostgreSQL\s+([0-9][0-9\.\-_]+)',
            
            # Mail servers
            rb'Postfix\s+([0-9][0-9\.\-_]+)',
            rb'Exim\s+([0-9][0-9\.\-_]+)',
            rb'Exchange\s+Server\s+([0-9][0-9\.\-_]+)'
        ]

        for pattern in version_patterns:
            match = re.search(pattern, banner)
            if match and match.group(1):
                try:
                    version = match.group(1).decode('utf-8', errors='ignore')
                    # Validate version format
                    if re.match(r'^[0-9][0-9\.\-_]+$', version):
                        return version
                except:
                    continue

        return None

    def _test_ssl(self, sock: socket.socket) -> bool:
        """Test if service supports SSL/TLS"""
        try:
            ssl_sock = self.ssl_context.wrap_socket(sock)
            ssl_sock.do_handshake()
            return True
        except:
            return False

    def _test_http(self, sock: socket.socket) -> bool:
        """Test if service is HTTP"""
        try:
            sock.send(b'GET / HTTP/1.0\r\n\r\n')
            response = sock.recv(1024)
            return response.startswith(b'HTTP/')
        except:
            return False

    def _test_ssh(self, sock: socket.socket) -> bool:
        """Test if service is SSH"""
        try:
            banner = sock.recv(1024)
            return banner.startswith(b'SSH-')
        except:
            return False

    def _test_smtp(self, sock: socket.socket) -> bool:
        """Test if service is SMTP"""
        try:
            banner = sock.recv(1024)
            return banner.startswith(b'220') and (b'SMTP' in banner or b'smtp' in banner)
        except:
            return False

    def _create_socket(self, port: int) -> Optional[socket.socket]:
        """Create socket with appropriate timeout"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeouts.get('default', 3))
            sock.connect((self.target, port))
            return sock
        except Exception as e:
            self.logger.debug(f"Error creating socket for port {port}: {e}")
            return None

    def _close_socket(self, sock: socket.socket) -> None:
        """Safely close socket"""
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except:
            pass
        finally:
            try:
                sock.close()
            except:
                pass

    def _get_cert_info(self, ssl_sock: ssl.SSLSocket) -> Dict:
        """Extract SSL certificate information"""
        cert_info = {}
        try:
            cert = ssl_sock.getpeercert()
            if cert:
                cert_info['subject'] = dict(x[0] for x in cert['subject'])
                cert_info['issuer'] = dict(x[0] for x in cert['issuer'])
                cert_info['version'] = cert['version']
                cert_info['serialNumber'] = cert['serialNumber']
                cert_info['notBefore'] = cert['notBefore']
                cert_info['notAfter'] = cert['notAfter']
                
                # Extract SANs
                if 'subjectAltName' in cert:
                    cert_info['subjectAltName'] = [x[1] for x in cert['subjectAltName']]

        except Exception as e:
            self.logger.debug(f"Error extracting certificate info: {e}")

        return cert_info

    def _generate_cpe(self, service: str, product: str, version: Optional[str]) -> str:
        """Generate CPE identifier"""
        cpe = f"cpe:/a:"
        
        if service == 'http':
            if 'apache' in product.lower():
                cpe += f"apache:http_server:{version}" if version else "apache:http_server"
            elif 'nginx' in product.lower():
                cpe += f"nginx:nginx:{version}" if version else "nginx:nginx"
            elif 'microsoft-iis' in product.lower():
                cpe += f"microsoft:iis:{version}" if version else "microsoft:iis"
        elif service == 'ssh':
            if 'openssh' in product.lower():
                cpe += f"openbsd:openssh:{version}" if version else "openbsd:openssh"
        elif service == 'mysql':
            if 'mariadb' in product.lower():
                cpe += f"mariadb:mariadb:{version}" if version else "mariadb:mariadb"
            else:
                cpe += f"mysql:mysql:{version}" if version else "mysql:mysql"
                
        return cpe

    def scan_target(self, start_port: int, end_port: int, threads: int = 10) -> List[Dict]:
        """Scan target for services in port range"""
        results = []
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_port = {
                executor.submit(self.detect_service, port): port 
                for port in range(start_port, end_port + 1)
            }
            
            for future in future_to_port:
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    port = future_to_port[future]
                    self.logger.error(f"Error scanning port {port}: {e}")
                    
        return sorted(results, key=lambda x: x.get('port', 0))

    def get_service_stats(self) -> Dict:
        """Get statistics about detected services"""
        with self.lock:
            return {
                'total_scanned': len(self.scanned_ports),
                'open_ports': len(self.open_ports),
                'services': dict(self.service_counts)
            }