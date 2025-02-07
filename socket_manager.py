import socket
import ssl
import struct
import random
import time
import logging
from typing import Optional, Dict, List, Tuple, Any
import threading
from collections import defaultdict
import ipaddress
import fcntl
import array

class SocketManager:
    """Advanced socket management with stealth features"""
    
    def __init__(self):
        # Initialize socket pools and counters
        self.active_sockets: Dict[str, socket.socket] = {}
        self.socket_pool: List[socket.socket] = []
        self.pool_size = 50
        self.pool_lock = threading.Lock()
        
        # Connection tracking
        self.connection_attempts = defaultdict(int)
        self.last_connection_time = defaultdict(float)
        self.failed_attempts = defaultdict(int)
        self.host_locks = defaultdict(threading.Lock)
        
        # Timing controls
        self.min_delay = 0.1  # Minimum delay between connections
        self.max_delay = 0.3  # Maximum delay between connections 
        self.backoff_factor = 1.5  # Exponential backoff factor
        self.max_retries = 3
        
        # Socket options
        self.default_timeout = 2.0
        self.socket_options = [
            (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1),
            (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1),
            (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        ]
        
        # Source port management
        self.source_port_range = (32768, 61000)
        self.used_source_ports = set()
        self.port_lock = threading.Lock()

        # SSL context
        self.ssl_context = self._create_ssl_context()
        
        # Initialize socket pool
        self._initialize_socket_pool()
        
        # Start maintenance thread
        self._start_maintenance_thread()

    def create_socket(self, ssl_wrap: bool = False, timeout: float = None) -> Optional[socket.socket]:
        """Create a new socket with advanced options and stealth features"""
        try:
            # Get socket from pool if available
            sock = self._get_from_pool()
            if not sock:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Set timeout
            if timeout is None:
                timeout = self.default_timeout
            sock.settimeout(timeout)
            
            # Apply socket options
            self._apply_socket_options(sock)
            
            # Set source port
            source_port = self._get_next_source_port()
            try:
                sock.bind(('0.0.0.0', source_port))
            except OSError:
                # If binding fails, try another port
                source_port = self._get_next_source_port(exclude=source_port)
                sock.bind(('0.0.0.0', source_port))

            # Wrap with SSL if requested
            if ssl_wrap:
                try:
                    sock = self.ssl_context.wrap_socket(sock)
                except ssl.SSLError as e:
                    logging.error(f"SSL wrap failed: {e}")
                    self._cleanup_socket(sock)
                    return None

            return sock

        except Exception as e:
            logging.error(f"Error creating socket: {e}")
            if 'sock' in locals():
                self._cleanup_socket(sock)
            return None

    def connect(self, host: str, port: int, ssl_wrap: bool = False) -> Tuple[Optional[socket.socket], str]:
        """Establish connection with retry and backoff logic"""
        conn_id = f"{host}:{port}"
        
        # Check rate limiting
        with self.host_locks[host]:
            if not self._check_rate_limit(host):
                return None, "Rate limited"
            
            # Update connection tracking
            current_time = time.time()
            if current_time - self.last_connection_time[host] < self.min_delay:
                time.sleep(self.min_delay)
            
            self.connection_attempts[conn_id] += 1
            self.last_connection_time[host] = current_time

        for attempt in range(self.max_retries):
            try:
                sock = self.create_socket(ssl_wrap=ssl_wrap)
                if not sock:
                    continue

                # Add jitter to timeout for stealth
                timeout = self.default_timeout * (1 + random.uniform(-0.1, 0.1))
                sock.settimeout(timeout)
                
                # Connect with random delay
                if attempt > 0:
                    delay = min(self.max_delay, self.min_delay * (self.backoff_factor ** attempt))
                    delay += random.uniform(0, 0.1)  # Add jitter
                    time.sleep(delay)

                result = sock.connect_ex((host, port))
                
                if result == 0:
                    # Connection successful
                    self.active_sockets[conn_id] = sock
                    self.failed_attempts[host] = 0  # Reset failed attempts
                    return sock, "Success"

                error_msg = f"Connect failed with error {result}"
                self._cleanup_socket(sock)

            except socket.timeout:
                error_msg = "Connection timeout"
                if 'sock' in locals():
                    self._cleanup_socket(sock)
            except socket.error as e:
                error_msg = f"Socket error: {e}"
                if 'sock' in locals():
                    self._cleanup_socket(sock)
            except Exception as e:
                error_msg = f"Unexpected error: {e}"
                if 'sock' in locals():
                    self._cleanup_socket(sock)

            # Update failed attempts
            self.failed_attempts[host] += 1
            
        return None, error_msg

    def close_socket(self, sock: socket.socket) -> None:
        """Safely close socket and clean up resources"""
        try:
            # Remove from active sockets
            conn_id = None
            for cid, s in self.active_sockets.items():
                if s == sock:
                    conn_id = cid
                    break
            if conn_id:
                del self.active_sockets[conn_id]

            # Try graceful shutdown
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except:
                pass

            # Close socket
            try:
                sock.close()
            except:
                pass

            # Release source port
            if hasattr(sock, 'getsockname'):
                try:
                    _, port = sock.getsockname()
                    with self.port_lock:
                        self.used_source_ports.discard(port)
                except:
                    pass

        except Exception as e:
            logging.error(f"Error closing socket: {e}")

    def _initialize_socket_pool(self) -> None:
        """Initialize pool of reusable sockets"""
        for _ in range(self.pool_size):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._apply_socket_options(sock)
                self.socket_pool.append(sock)
            except Exception as e:
                logging.error(f"Error initializing socket pool: {e}")

    def _get_from_pool(self) -> Optional[socket.socket]:
        """Get socket from pool with thread safety"""
        with self.pool_lock:
            if self.socket_pool:
                return self.socket_pool.pop()
        return None

    def _return_to_pool(self, sock: socket.socket) -> None:
        """Return socket to pool if reusable"""
        try:
            sock.settimeout(None)
            sock.shutdown(socket.SHUT_RDWR)
            with self.pool_lock:
                if len(self.socket_pool) < self.pool_size:
                    self.socket_pool.append(sock)
                else:
                    sock.close()
        except:
            self._cleanup_socket(sock)

    def _cleanup_socket(self, sock: socket.socket) -> None:
        """Clean up socket resources"""
        try:
            sock.close()
        except:
            pass

    def _apply_socket_options(self, sock: socket.socket) -> None:
        """Apply socket options with error handling"""
        for opt in self.socket_options:
            try:
                sock.setsockopt(*opt)
            except Exception as e:
                logging.debug(f"Error setting socket option {opt}: {e}")

        # Set socket linger
        l_onoff = 1
        l_linger = 0
        try:
            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_LINGER,
                struct.pack('ii', l_onoff, l_linger)
            )
        except Exception as e:
            logging.debug(f"Error setting SO_LINGER: {e}")

    def _get_next_source_port(self, exclude: int = None) -> int:
        """Get next available source port with collision avoidance"""
        with self.port_lock:
            while True:
                port = random.randint(self.source_port_range[0], self.source_port_range[1])
                if port != exclude and port not in self.used_source_ports:
                    self.used_source_ports.add(port)
                    return port

    def _check_rate_limit(self, host: str) -> bool:
        """Check and enforce rate limits per host"""
        current_time = time.time()
        
        # Clean up old records
        cutoff = current_time - 3600  # 1 hour
        self.last_connection_time = defaultdict(
            float,
            {k: v for k, v in self.last_connection_time.items() if v > cutoff}
        )
        
        # Calculate current rate
        recent_conns = sum(
            1 for t in self.last_connection_time.values()
            if t > current_time - 60  # Last minute
        )
        
        # Apply rate limits
        max_rate = 30  # Max connections per minute
        if recent_conns >= max_rate:
            return False
            
        # Apply backoff for failed attempts
        if self.failed_attempts[host] > 5:
            backoff = min(300, 2 ** (self.failed_attempts[host] - 5))  # Max 5 minute backoff
            if current_time - self.last_connection_time[host] < backoff:
                return False
                
        return True

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context with secure defaults"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers('ALL:@SECLEVEL=1')
        # Disable compression for faster handshakes
        try:
            ctx.options |= ssl.OP_NO_COMPRESSION
        except AttributeError:
            pass
        return ctx

    def _start_maintenance_thread(self) -> None:
        """Start background thread for maintenance tasks"""
        def maintenance():
            while True:
                try:
                    # Clean up stale connection records
                    current_time = time.time()
                    cutoff = current_time - 3600
                    
                    with self.port_lock:
                        # Clear old connection attempts
                        self.connection_attempts = defaultdict(
                            int,
                            {k: v for k, v in self.connection_attempts.items() 
                             if self.last_connection_time[k.split(':')[0]] > cutoff}
                        )
                        
                        # Reset failed attempts counters
                        self.failed_attempts = defaultdict(
                            int,
                            {k: v for k, v in self.failed_attempts.items()
                             if self.last_connection_time[k] > cutoff}
                        )
                        
                    # Check socket pool health
                    with self.pool_lock:
                        for sock in self.socket_pool[:]:
                            try:
                                # Test socket
                                sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                            except:
                                # Remove bad socket
                                self.socket_pool.remove(sock)
                                self._cleanup_socket(sock)
                                
                        # Replenish pool
                        while len(self.socket_pool) < self.pool_size:
                            try:
                                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                self._apply_socket_options(sock)
                                self.socket_pool.append(sock)
                            except:
                                break
                                
                except Exception as e:
                    logging.error(f"Error in maintenance thread: {e}")
                    
                time.sleep(60)  # Run every minute
                
        thread = threading.Thread(target=maintenance, daemon=True)
        thread.start()