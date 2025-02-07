import socket
import ssl
import re
import time
import threading
from typing import Dict, Optional, List, Tuple
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
import json

class WebProtocolTester:
    """Advanced implementation for testing web protocols"""

    def __init__(self):
        # Basic settings
        self.timeout = 3.0
        self.max_retries = 2
        self.thread_count = 10
        self.ports_to_scan = [80, 443, 8080, 8443, 3000, 4000, 4433, 5000, 8000, 8008, 8888]
        self.lock = threading.Lock()
        self.open_ports = set()
        
        # SSL context settings
        self.ssl_context = self._create_ssl_context()
        
        # Detection patterns
        self.service_patterns = {
            'apache': [
                rb'Server: Apache/?([0-9.]+)?',
                rb'X-Powered-By: PHP/?([0-9.]+)?'
            ],
            'nginx': [
                rb'Server: nginx/?([0-9.]+)?',
                rb'X-FastCGI-Cache:'
            ],
            'iis': [
                rb'Server: Microsoft-IIS/?([0-9.]+)?',
                rb'X-Powered-By: ASP.NET'
            ],
            'tomcat': [
                rb'Apache Tomcat/?([0-9.]+)?',
                rb'X-Powered-By: Servlet'
            ],
            'nodejs': [
                rb'X-Powered-By: Express',
                rb'X-Powered-By: Node'
            ]
        }

        # HTTP probes
        self.http_probes = [
            # Simple GET request
            b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n',
            
            # HEAD request
            b'HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n',
            
            # OPTIONS request
            b'OPTIONS / HTTP/1.1\r\nHost: localhost\r\n\r\n',
            
            # TRACE request
            b'TRACE / HTTP/1.1\r\nHost: localhost\r\n\r\n'
        ]

        # Common security checks
        self.security_checks = [
            {
                'name': 'directory_listing',
                'path': '/test_directory/',
                'pattern': rb'Index of /',
                'severity': 'MEDIUM'
            },
            {
                'name': 'phpinfo',
                'path': '/phpinfo.php',
                'pattern': rb'PHP Version',
                'severity': 'HIGH'  
            },
            {
                'name': 'admin_panel',
                'path': '/admin/',
                'pattern': rb'login|admin|backend',
                'severity': 'MEDIUM'
            }
        ]

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create an SSL context with secure settings"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Disable old SSL versions
        ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
        return ctx

    def scan_ports(self, target: str) -> List[Dict]:
        """Simultaneous scanning of common web ports"""
        results = []
        print(f"\n[*] Scanning web ports on {target}")
        
        with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
            future_to_port = {executor.submit(self.test_web_port, target, port): port
                              for port in self.ports_to_scan}
            
            for future in future_to_port:
                try:
                    result = future.result()
                    if result and result.get('state') == 'open':
                        results.append(result)
                        with self.lock:
                            self.open_ports.add(future_to_port[future])
                except Exception as e:
                    print(f"Error scanning port {future_to_port[future]}: {e}")

        return results

    def test_web_port(self, target: str, port: int) -> Optional[Dict]:
        """Comprehensive test of a web port"""
        result = {
            'port': port,
            'state': 'closed',
            'service': None,
            'is_ssl': False,
            'server': None,
            'vulnerabilities': [],
            'headers': {},
            'security_issues': []
        }

        # Initial connection test
        sock = self._create_socket(target, port)
        if not sock:
            return result

        try:
            # SSL test
            if port in [443, 8443, 4433] or self._test_ssl(sock):
                result['is_ssl'] = True
                sock = self.ssl_context.wrap_socket(sock)

            # Test web service
            for probe in self.http_probes:
                response = self._send_probe(sock, probe)
                if response:
                    result['state'] = 'open'
                    
                    # Identify service and version
                    service_info = self._detect_web_service(response)
                    result.update(service_info)
                    
                    # Extract headers
                    headers = self._parse_headers(response)
                    result['headers'] = headers
                    
                    # Security checks
                    security_issues = self._run_security_checks(sock, target, headers)
                    result['security_issues'] = security_issues
                    
                    # Test SSL/TLS if enabled
                    if result['is_ssl']:
                        ssl_info = self._analyze_ssl(sock)
                        result['ssl_info'] = ssl_info
                    
                    break

        except Exception as e:
            print(f"Error testing port {port}: {e}")
        finally:
            self._close_socket(sock)

        return result if result['state'] == 'open' else None

    def _create_socket(self, target: str, port: int) -> Optional[socket.socket]:
        """Create a socket with retries"""
        for _ in range(self.max_retries):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((target, port))
                return sock
            except:
                continue
        return None

    def _test_ssl(self, sock: socket.socket) -> bool:
        """Check for SSL/TLS support"""
        try:
            ssl_sock = self.ssl_context.wrap_socket(sock)
            ssl_sock.do_handshake()
            return True
        except:
            return False

    def _send_probe(self, sock: socket.socket, data: bytes) -> Optional[bytes]:
        """Send a probe and receive a response"""
        try:
            sock.send(data)
            response = b''
            timeout = time.time() + self.timeout
            
            while time.time() < timeout:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break
                    
            return response
        except:
            return None

    def _detect_web_service(self, response: bytes) -> Dict:
        """Identify the type and version of the web service"""
        result = {
            'service': 'unknown',
            'version': None,
            'server_software': None
        }

        for service, patterns in self.service_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, response)
                if match:
                    result['service'] = service
                    if len(match.groups()) > 0 and match.group(1):
                        result['version'] = match.group(1).decode()
                    break
                    
            if result['service'] != 'unknown':
                break

        # Extract server name
        server_match = re.search(rb'Server: ([^\r\n]+)', response)
        if server_match:
            result['server_software'] = server_match.group(1).decode()

        return result

    def _parse_headers(self, response: bytes) -> Dict:
        """Parse HTTP headers"""
        headers = {}
        try:
            header_section = response.split(b'\r\n\r\n')[0]
            for line in header_section.split(b'\r\n')[1:]:
                if b':' in line:
                    key, value = line.split(b':', 1)
                    headers[key.strip().decode()] = value.strip().decode()
        except:
            pass
        return headers

    def _run_security_checks(self, sock: socket.socket, target: str, headers: Dict) -> List[Dict]:
        """Execute security checks"""
        issues = []

        # Check for security headers
        security_headers = {
            'X-Frame-Options': 'Missing X-Frame-Options header',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'Strict-Transport-Security': 'Missing HSTS header',
            'Content-Security-Policy': 'Missing CSP header'
        }

        for header, message in security_headers.items():
            if header not in headers:
                issues.append({
                    'type': 'missing_security_header',
                    'description': message,
                    'severity': 'MEDIUM'
                })

        # Check for common vulnerabilities
        for check in self.security_checks:
            probe = f'GET {check["path"]} HTTP/1.1\r\nHost: {target}\r\n\r\n'
            response = self._send_probe(sock, probe.encode())
            
            if response and re.search(check['pattern'], response):
                issues.append({
                    'type': check['name'],
                    'path': check['path'],
                    'severity': check['severity']
                })

        # Check outdated servers
        server = headers.get('Server', '')
        version_match = re.search(r'([0-9.]+)', server)
        if version_match:
            version = version_match.group(1)
            if self._is_outdated_version(server, version):
                issues.append({
                    'type': 'outdated_server',
                    'description': f'Outdated server version: {server}',
                    'severity': 'HIGH'
                })

        return issues

    def _is_outdated_version(self, server: str, version: str) -> bool:
        """Check for outdated server versions"""
        outdated_versions = {
            'Apache': '2.4.49',
            'nginx': '1.18.0',
            'Microsoft-IIS': '8.0'
        }
        
        for server_name, min_version in outdated_versions.items():
            if server_name in server and self._compare_versions(version, min_version) < 0:
                return True
        return False

    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare versions"""
        v1_parts = [int(x) for x in v1.split('.') if x.isdigit()]
        v2_parts = [int(x) for x in v2.split('.') if x.isdigit()]
        
        for i in range(max(len(v1_parts), len(v2_parts))):
            v1_part = v1_parts[i] if i < len(v1_parts) else 0
            v2_part = v2_parts[i] if i < len(v2_parts) else 0
            
            if v1_part < v2_part:
                return -1
            elif v1_part > v2_part:
                return 1
                
        return 0

    def _analyze_ssl(self, sock: ssl.SSLSocket) -> Dict:
        """Analyze SSL/TLS configuration"""
        ssl_info = {
            'version': sock.version(),
            'cipher': sock.cipher(),
            'issues': []
        }

        # Check insecure protocols
        if ssl_info['version'] in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
            ssl_info['issues'].append({
                'type': 'insecure_protocol',
                'description': f'Insecure protocol {ssl_info["version"]} in use',
                'severity': 'HIGH'
            })

        # Check weak ciphers
        cipher = ssl_info['cipher'][0]
        if any(x in cipher.lower() for x in ['null', 'anon', 'export', 'des', 'rc4', 'md5']):
            ssl_info['issues'].append({
                'type': 'weak_cipher',
                'description': f'Weak cipher {cipher} in use',
                'severity': 'HIGH'
            })

        return ssl_info

    def _close_socket(self, sock: socket.socket) -> None:
        """Close the socket safely"""
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except:
            pass
        finally:
            try:
                sock.close()
            except:
                pass

    def scan_target(self, target: str) -> Dict:
        """Scan an entire target"""
        scan_start = time.time()
        results = self.scan_ports(target)
        scan_duration = time.time() - scan_start

        return {
            'target': target,
            'scan_time': scan_duration,
            'open_ports': len(self.open_ports),
            'results': results
        }

if __name__ == '__main__':
    import sys
    import argparse

    parser = argparse.ArgumentParser(description='Web Protocol Tester')
    parser.add_argument('target', help='Target IP or hostname')
    parser.add_argument('-p', '--ports', help='Port range (e.g. 1-100)', default='1-1000')
    args = parser.parse_args()

    try:
        # Parse port range
        start_port, end_port = map(int, args.ports.split('-'))
        
        # Create an instance of the class
        tester = WebProtocolTester()
        # Set the port range
        tester.ports_to_scan = range(start_port, end_port + 1)
        # Run scan with args.target
        results = tester.scan_target(args.target)
        print(json.dumps(results, indent=2))

    except ValueError:
        print("Error: Invalid port range. Use format: start-end (e.g. 1-100)")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

class WebVulnScanner:
    """Class for scanning web vulnerabilities"""
    
    def __init__(self):
        self.vuln_patterns = {
            'sql_injection': [
                r"(?i)you have an error in your sql syntax",
                r"(?i)warning.*?\Wmysqli?_",
                r"(?i)sqlite3.*?error",
                r"(?i)pg_.*?error"
            ],
            'xss': [
                r"(?i)<script.*?>.*?</script.*?>",
                r"(?i)javascript:",
                r"(?i)onerror=",
                r"(?i)onload="
            ],
            'lfi': [
                r"(?i)failed to open stream",
                r"(?i)include.*?\.\.\/",
                r"(?i)invalid files?\.?paths?"
            ]
        }
        
        self.vuln_payloads = {
            'sql_injection': [
                "'",
                "1' OR '1'='1",
                "1; DROP TABLE users--",
                "1/**/AND/**/1=1"
            ],
            'xss': [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)"
            ],
            'lfi': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\win.ini",
                "....//....//etc/passwd"
            ]
        }

    def scan_vulnerabilities(self, target: str, port: int) -> List[Dict]:
        """Scan for vulnerabilities with various payloads"""
        vulns = []
        
        # Test common vulnerabilities
        for vuln_type, payloads in self.vuln_payloads.items():
            for payload in payloads:
                path = f"/?test={payload}"
                try:
                    response = self._send_request(target, port, path)
                    if response:
                        findings = self._check_response(response, vuln_type)
                        vulns.extend(findings)
                except:
                    continue
                    
        return vulns

    def _send_request(self, target: str, port: int, path: str) -> Optional[bytes]:
        """Send an HTTP request"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        
        try:
            sock.connect((target, port))
            request = f"GET {path} HTTP/1.1\r\nHost: {target}\r\n\r\n"
            sock.send(request.encode())
            
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                
            return response
            
        except:
            return None
            
        finally:
            sock.close()

    def _check_response(self, response: bytes, vuln_type: str) -> List[Dict]:
        """Check the response for vulnerability signs"""
        findings = []
        response_str = response.decode('utf-8', errors='ignore')
        
        for pattern in self.vuln_patterns.get(vuln_type, []):
            if re.search(pattern, response_str):
                findings.append({
                    'type': vuln_type,
                    'pattern': pattern,
                    'severity': 'HIGH',
                    'description': f'Potential {vuln_type} vulnerability detected'
                })
                
        return findings

class WebFuzzer:
    """Class for fuzzing web parameters"""
    
    def __init__(self):
        self.fuzz_chars = "\"'<>\\%{}[]"
        self.max_length = 8192
        self.common_params = [
            'id', 'page', 'file', 'dir', 'search', 
            'query', 'user', 'pass', 'key', 'token'
        ]
        
    def fuzz_params(self, target: str, port: int) -> List[Dict]:
        """Fuzz GET parameters"""
        results = []
        
        for param in self.common_params:
            # Test long values
            long_value = "A" * self.max_length
            path = f"/?{param}={long_value}"
            
            try:
                response = self._send_request(target, port, path)
                if response and self._check_error_response(response):
                    results.append({
                        'param': param,
                        'type': 'buffer_overflow',
                        'value': f'Long string ({self.max_length} chars)'
                    })
            except:
                continue

            # Test special characters
            for char in self.fuzz_chars:
                path = f"/?{param}={char * 100}"
                try:
                    response = self._send_request(target, port, path)
                    if response and self._check_error_response(response):
                        results.append({
                            'param': param,
                            'type': 'special_chars',
                            'value': char
                        })
                except:
                    continue
                    
        return results

    def _send_request(self, target: str, port: int, path: str) -> Optional[bytes]:
        """Send an HTTP request"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        
        try:
            sock.connect((target, port))
            request = f"GET {path} HTTP/1.1\r\nHost: {target}\r\n\r\n"
            sock.send(request.encode())
            
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                
            return response
            
        except:
            return None
            
        finally:
            sock.close()

    def _check_error_response(self, response: bytes) -> bool:
        """Check the response for error indications"""
        response_str = response.decode('utf-8', errors='ignore').lower()
        
        error_signs = [
            'error',
            'exception',
            'stack trace',
            'overflow',
            'crash',
            'undefined',
            'not found'
        ]
        
        return any(sign in response_str for sign in error_signs)

class WebSecurityScanner:
    """Main class for web security scanning"""
    
    def __init__(self):
        self.protocol_tester = WebProtocolTester()
        self.vuln_scanner = WebVulnScanner()
        self.fuzzer = WebFuzzer()
        
    def scan(self, target: str) -> Dict:
        """Full security scan"""
        results = {
            'target': target,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'port_scan': {},
            'vulnerabilities': [],
            'fuzzing': []
        }
        
        # Scan ports and services
        port_results = self.protocol_tester.scan_target(target)
        results['port_scan'] = port_results
        
        # For each open port, perform vulnerability scanning and fuzzing
        for port_info in port_results.get('results', []):
            port = port_info['port']
            
            # Vulnerability scanning
            vulns = self.vuln_scanner.scan_vulnerabilities(target, port)
            results['vulnerabilities'].extend(vulns)
            
            # Fuzzing parameters
            fuzz_results = self.fuzzer.fuzz_params(target, port)
            results['fuzzing'].extend(fuzz_results)
            
        return results

if __name__ == '__main__':
    import sys
    import argparse

    parser = argparse.ArgumentParser(description='Web Protocol Tester')
    parser.add_argument('target', help='Target IP or hostname')
    parser.add_argument('-p', '--ports', help='Port range (e.g. 1-100)', default='1-1000')
    args = parser.parse_args()

    try:
        # Parse the port range
        start_port, end_port = map(int, args.ports.split('-'))
        
        # Create an instance of the class
        tester = WebProtocolTester()
        # Set the port range
        tester.ports_to_scan = range(start_port, end_port + 1)
        # Run the scan with target
        results = tester.scan_target(args.target)
        print(json.dumps(results, indent=2))

    except ValueError:
        print("Error: Invalid port range. Use format: start-end (e.g. 1-100)")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)
