# PortHandlers.py
import socket
import ssl
import time
import random
from typing import Dict, Optional, List, Tuple
from PacketManipulation import PacketManipulation
import re

class PortHandlers:
    """Advanced class for port management"""

    def __init__(self, target: str):
        self.target = target
        self.packet_manager = PacketManipulation()
        
        # Service detection patterns
        self.service_patterns = {
            'SSH': (b'SSH-', b'OpenSSH'),
            'FTP': (b'220', b'FTP'),
            'SMTP': (b'220', b'SMTP'),
            'HTTP': (b'HTTP/', b'Server:'),
            'POP3': (b'+OK', b'POP3'),
            'IMAP': (b'* OK', b'IMAP'),
            'MySQL': (b'\x4a\x00\x00\x00', b'mysql_native_password'),
            'PostgreSQL': (b'PostgreSQL', b'FATAL'),
            'Redis': (b'-NOAUTH', b'redis_version'),
            'MongoDB': (b'MongoDB', b'version'),
            'RDP': (b'\x03\x00\x00', b'Microsoft Terminal Services')
        }
        
        # Timeouts for each service
        self.service_timeouts = {
            'SSH': 2.0,
            'FTP': 1.5,
            'SMTP': 2.0,
            'HTTP': 1.5,
            'POP3': 1.5,
            'IMAP': 1.5,
            'MySQL': 2.0,
            'PostgreSQL': 2.0,
            'Redis': 1.5,
            'MongoDB': 2.0,
            'RDP': 2.0
        }

    def handle_port(self, port: int) -> Dict:
        """Main port management"""
        result = {
            'port': port,
            'state': 'closed',
            'service': None,
            'version': None,
            'banner': None,
            'protocol': 'tcp'
        }

        try:
            sock = socket.create_connection((self.target, port), timeout=2)
            result['state'] = 'open'

            # Receive initial banner
            try:
                banner = sock.recv(1024)
                if banner:
                    result['banner'] = banner
                    service_info = self._identify_service(banner)
                    if service_info:
                        result.update(service_info)
            except:
                pass

            # Specific tests for each service
            if result['service']:
                specific_handler = getattr(
                    self,
                    f'handle_{result["service"].lower()}',
                    None
                )
                if specific_handler:
                    specific_result = specific_handler(sock, port)
                    if specific_result:
                        result.update(specific_result)

            sock.close()
            return result

        except socket.timeout:
            result['state'] = 'filtered'
            return result
        except ConnectionRefusedError:
            result['state'] = 'closed'
            return result
        except Exception as e:
            result['state'] = 'error'
            result['error'] = str(e)
            return result

    def handle_http(self, sock: socket.socket, port: int) -> Dict:
        """Management of HTTP ports"""
        result = {}
        try:
            # Send HTTP request
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {self.target}\r\n"
                "User-Agent: Mozilla/5.0\r\n"
                "Connection: close\r\n\r\n"
            )
            sock.send(request.encode())
            
            # Receive response
            response = sock.recv(4096)
            if response:
                result['banner'] = response
                result['service'] = 'http'
                
                # Extract server info
                if b'Server:' in response:
                    server = re.search(rb'Server: ([^\r\n]+)', response)
                    if server:
                        result['server'] = server.group(1).decode()
                
        except Exception as e:
            result['error'] = str(e)
            
        return result

    def handle_https(self, sock: socket.socket, port: int) -> Dict:
        """Management of HTTPS ports"""
        result = {}
        try:
            # Convert to SSL socket
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            ssl_sock = context.wrap_socket(sock)
            
            # Send HTTPS request
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {self.target}\r\n"
                "User-Agent: Mozilla/5.0\r\n"
                "Connection: close\r\n\r\n"
            )
            ssl_sock.send(request.encode())
            
            # Receive response
            response = ssl_sock.recv(4096)
            if response:
                result['banner'] = response
                result['service'] = 'https'
                result['ssl'] = {
                    'version': ssl_sock.version(),
                    'cipher': ssl_sock.cipher()
                }
                
        except Exception as e:
            result['error'] = str(e)
            
        return result

    def handle_ssh(self, sock: socket.socket, port: int) -> Dict:
        """Management of SSH ports"""
        result = {}
        try:
            banner = sock.recv(1024)
            if banner:
                result['banner'] = banner
                result['service'] = 'ssh'
                
                # Extract version
                if b'SSH-' in banner:
                    version = re.search(rb'SSH-2.0-([^\r\n]+)', banner)
                    if version:
                        result['version'] = version.group(1).decode()
                        
        except Exception as e:
            result['error'] = str(e)
            
        return result

    def handle_ftp(self, sock: socket.socket, port: int) -> Dict:
        """Management of FTP ports"""
        result = {}
        try:
            banner = sock.recv(1024)
            if banner:
                result['banner'] = banner
                result['service'] = 'ftp'
                
                # Extract version
                if b'220' in banner:
                    version = re.search(rb'220[- ]([^\r\n]+)', banner)
                    if version:
                        result['version'] = version.group(1).decode()
                        
        except Exception as e:
            result['error'] = str(e)
            
        return result

    def handle_smtp(self, sock: socket.socket, port: int) -> Dict:
        """Management of SMTP ports"""
        result = {}
        try:
            banner = sock.recv(1024)
            if banner:
                result['banner'] = banner
                result['service'] = 'smtp'
                
                # Test EHLO
                sock.send(b'EHLO test\r\n')
                response = sock.recv(1024)
                if response:
                    result['extended_smtp'] = b'250' in response
                    
        except Exception as e:
            result['error'] = str(e)
            
        return result

    def handle_mysql(self, sock: socket.socket, port: int) -> Dict:
        """Management of MySQL ports"""
        result = {}
        try:
            banner = sock.recv(1024)
            if banner:
                result['banner'] = banner
                result['service'] = 'mysql'
                
                if b'mysql_native_password' in banner or b'MariaDB' in banner:
                    # Extract version
                    version = re.search(rb'([0-9]+\.[0-9]+\.[0-9]+)', banner)
                    if version:
                        result['version'] = version.group(1).decode()
                        
        except Exception as e:
            result['error'] = str(e)
            
        return result

    def handle_postgresql(self, sock: socket.socket, port: int) -> Dict:
        """Management of PostgreSQL ports"""
        result = {}
        try:
            # Send startup packet
            startup_packet = bytes([
                0x00, 0x00, 0x00, 0x08,
                0x04, 0xd2, 0x16, 0x2f
            ])
            sock.send(startup_packet)
            
            response = sock.recv(1024)
            if response:
                result['banner'] = response
                result['service'] = 'postgresql'
                
                # Extract version
                if b'PostgreSQL' in response:
                    version = re.search(rb'PostgreSQL ([0-9\.]+)', response)
                    if version:
                        result['version'] = version.group(1).decode()
                        
        except Exception as e:
            result['error'] = str(e)
            
        return result

    def _identify_service(self, response: bytes) -> Optional[Dict]:
        """Identify service based on response"""
        result = {}
        
        for service, signatures in self.service_patterns.items():
            for signature in signatures:
                if signature in response:
                    result['service'] = service.lower()
                    # Extract version
                    version = re.search(rb'([0-9]+\.[0-9]+[\.0-9]*)', response)
                    if version:
                        result['version'] = version.group(1).decode()
                    return result
                    
        return None
