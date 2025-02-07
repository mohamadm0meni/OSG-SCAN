# AdvancedSocketManager.py
import socket
import struct
import random
import time
from typing import Optional, Dict, List, Tuple
from Config import Config
import array
import logging
import threading
from concurrent.futures import ThreadPoolExecutor

class AdvancedSocketManager:
    def __init__(self):
        self.config = Config()
        self.active_sockets: Dict[int, socket.socket] = {}
        self.source_ports = self._initialize_source_ports()
        self._setup_socket_options()
        self.lock = threading.Lock()
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Connection stats
        self.connection_stats = {
            'attempts': 0,
            'successes': 0,
            'failures': 0,
            'timeouts': 0
        }

    def _initialize_source_ports(self) -> List[int]:
        """Initialize source ports with enhanced randomization"""
        ports = list(range(self.config.SOURCE_PORT_RANGE[0], 
                         self.config.SOURCE_PORT_RANGE[1]))
        random.shuffle(ports)
        return ports

    def _setup_socket_options(self):
        """Setup enhanced socket options"""
        self.tcp_options = [
            (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1),
            (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1),
            (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
            (socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
        ]
        
        # Additional options for Linux systems
        try:
            self.tcp_options.extend([
                (socket.SOL_TCP, socket.TCP_FASTOPEN, 1),
                (socket.SOL_TCP, socket.TCP_THIN_LINEAR_TIMEOUTS, 1),
                (socket.SOL_TCP, socket.TCP_DEFER_ACCEPT, 1)
            ])
        except AttributeError:
            pass

    def create_tcp_socket(self, timeout: float = None) -> Optional[socket.socket]:
        """Create enhanced TCP socket with better error handling"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Set timeout
            if timeout is None:
                timeout = self.config.TIMEOUT
            sock.settimeout(timeout)
            
            # Apply enhanced options
            for opt in self.tcp_options:
                try:
                    sock.setsockopt(*opt)
                except Exception as e:
                    self.logger.warning(f"Failed to set socket option {opt}: {e}")
                    continue
            
            # Set SO_LINGER
            l_onoff = 1
            l_linger = 0
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                          struct.pack('ii', l_onoff, l_linger))
            
            # Set source port with retries
            max_attempts = 5
            for attempt in range(max_attempts):
                try:
                    source_port = self.get_next_source_port()
                    sock.bind(('0.0.0.0', source_port))
                    break
                except OSError as e:
                    if attempt == max_attempts - 1:
                        raise
                    continue
            
            return sock
            
        except Exception as e:
            self.logger.error(f"Error creating socket: {e}")
            return None

    def get_next_source_port(self) -> int:
        """Get next source port thread-safely"""
        with self.lock:
            port = self.source_ports.pop(0)
            self.source_ports.append(port)
            return port

    def test_port(self, target: str, port: int, timeout: float = None) -> Dict:
        """Enhanced port testing with service detection"""
        result = {
            'port': port,
            'state': 'closed',
            'service': None,
            'banner': None,
            'latency': None,
            'error': None
        }

        try:
            start_time = time.time()
            sock = self.create_tcp_socket(timeout)
            if not sock:
                result['error'] = 'Failed to create socket'
                return result

            # Attempt connection
            try:
                sock.connect((target, port))
                result['state'] = 'open'
                result['latency'] = time.time() - start_time
                
                # Attempt banner grab
                try:
                    sock.send(b'')
                    banner = sock.recv(1024)
                    result['banner'] = banner
                    result['service'] = self._detect_service(port, banner)
                except:
                    pass

            except socket.timeout:
                result['state'] = 'filtered'
                result['error'] = 'Connection timeout'
            except ConnectionRefusedError:
                result['state'] = 'closed'
            except Exception as e:
                result['state'] = 'error'
                result['error'] = str(e)

            finally:
                self.close_socket(sock)

        except Exception as e:
            result['state'] = 'error'
            result['error'] = str(e)

        # Update stats
        with self.lock:
            self.connection_stats['attempts'] += 1
            if result['state'] == 'open':
                self.connection_stats['successes'] += 1
            elif result['state'] == 'filtered':
                self.connection_stats['timeouts'] += 1
            else:
                self.connection_stats['failures'] += 1

        return result

    def _detect_service(self, port: int, banner: Optional[bytes]) -> str:
        """Enhanced service detection"""
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'TELNET',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            27017: 'MongoDB'
        }

        # Check common ports first
        if port in common_ports:
            return common_ports[port]

        # Try to detect from banner
        if banner:
            banner_str = banner.decode('utf-8', errors='ignore').lower()
            
            # Common service signatures
            if b'ssh' in banner.lower():
                return 'SSH'
            elif b'ftp' in banner.lower():
                return 'FTP'
            elif b'http' in banner.lower():
                return 'HTTP'
            elif b'smtp' in banner.lower():
                return 'SMTP'
            elif b'mysql' in banner.lower():
                return 'MySQL'
            elif b'postgresql' in banner.lower():
                return 'PostgreSQL'
                
        return 'unknown'

    def scan_port_range(self, target: str, start_port: int, end_port: int, 
                       threads: int = 50) -> List[Dict]:
        """Scan port range with parallel execution"""
        results = []
        ports = range(start_port, end_port + 1)
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_port = {
                executor.submit(self.test_port, target, port): port 
                for port in ports
            }
            
            for future in future_to_port:
                try:
                    result = future.result()
                    if result['state'] == 'open':
                        results.append(result)
                except Exception as e:
                    port = future_to_port[future]
                    self.logger.error(f"Error scanning port {port}: {e}")

        return sorted(results, key=lambda x: x['port'])

    def close_socket(self, sock: socket.socket) -> None:
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

    def get_stats(self) -> Dict:
        """Get connection statistics"""
        with self.lock:
            stats = self.connection_stats.copy()
            if stats['attempts'] > 0:
                stats['success_rate'] = (stats['successes'] / stats['attempts']) * 100
            else:
                stats['success_rate'] = 0
            return stats

    def cleanup(self):
        """Cleanup all resources"""
        for sock in self.active_sockets.values():
            self.close_socket(sock)
        self.active_sockets.clear()
        self.logger.info("Cleaned up all sockets")