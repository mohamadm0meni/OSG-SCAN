#!/usr/bin/env python3
import os
import sys
import argparse
import logging
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Set, Any
import threading
import ipaddress
import signal
import socket

# Import configuration - تغییر از Config به config.py
try:
    import config
except ImportError:
    print("Error: config.py not found. Please ensure it's in the same directory.")
    sys.exit(1)

# Handle nmap import gracefully
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("Warning: python-nmap not available, using subprocess method")

# Core scanner components
from result_manager import ResultManager
# حذف خط زیر چون از config.py استفاده می‌کنیم
# from Config import Config
from delay_manager import DelayManager

# Service detection and testing
from ServiceDetector import ServiceDetector
from WebProtocolTester import WebProtocolTester

# Connection handling
from AdvancedSocketManager import AdvancedSocketManager
from socket_manager import SocketManager

# Protocol testers
from BannerAnalyzer import BannerAnalyzer
from DatabaseProtocolTester import DatabaseProtocolTester
from MailProtocolTester import MailProtocolTester

# Traffic management
from traffic_manager import TrafficManager

# Batch and port management
from port_batch_manager import PortBatchManager
from PortHandlers import PortHandlers


class EnhancedScanner:
    """Advanced port scanner with complete testing and identification capabilities"""

    def __init__(self, target: str, config_file: Optional[str] = None):
        self.target = target
        
        # Load configuration - استفاده از config.py به جای Config class
        if config_file and os.path.exists(config_file):
            try:
                import importlib.util
                spec = importlib.util.spec_from_file_location("custom_config", config_file)
                custom_config = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(custom_config)
                self.config = custom_config
                print(f"Loaded custom configuration from {config_file}")
            except Exception as e:
                print(f"Warning: Could not load custom config {config_file}: {e}")
                print("Using default configuration...")
                self.config = config
        else:
            self.config = config
            
        self.stop_scan = False
        self.scan_paused = threading.Event()
        
        # Initialize core components
        self.result_manager = ResultManager(target)
        self.delay_manager = DelayManager()
        
        #Initialize connection managers
        self.socket_manager = SocketManager()
        self.advanced_socket_manager = AdvancedSocketManager()
        
        # Initialize service detectors and testers
        self.service_detector = ServiceDetector(target)
        self.web_tester = WebProtocolTester()
        
        # Initialize protocol testers
        self.banner_analyzer = BannerAnalyzer()
        self.db_tester = DatabaseProtocolTester()
        self.mail_tester = MailProtocolTester()
        
        # Initialize traffic management
        self.traffic_manager = TrafficManager()
        
        # Initialize port management
        self.port_batch_manager = PortBatchManager()
        self.port_handlers = PortHandlers(target)
        
        # Thread safety
        self.lock = threading.Lock()
        
        # استفاده از config.py برای MAX_THREADS
        max_threads = getattr(self.config, 'ScannerConfig', config.ScannerConfig).MAX_THREADS
        self.thread_pool = ThreadPoolExecutor(max_workers=max_threads)

        # Stats tracking
        self.stats = {
            'start_time': None,
            'end_time': None,
            'duration': 0,
            'total_ports': 0,
            'scanned_ports': 0,
            'open_ports': set(),
            'filtered_ports': set(),
            'closed_ports': set(),
            'errors': 0,
            'timeouts': 0
        }

        # Setup logging and signal handlers
        self._setup_logging()
        self._setup_signal_handlers()

    def get_config_value(self, section: str, key: str, default: Any = None) -> Any:
        """Helper function to get configuration values safely from config.py"""
        try:
            if hasattr(self.config, section):
                section_obj = getattr(self.config, section)
                if hasattr(section_obj, key):
                    return getattr(section_obj, key)
            return default
        except Exception:
            return default

    def get_threads(self) -> int:
        """Get configured thread count."""
        return self.get_config_value('ScannerConfig', 'DEFAULT_THREADS', 50)

    def get_timeout(self) -> int:
        """Get configured timeout value."""
        return self.get_config_value('ScannerConfig', 'DEFAULT_TIMEOUT', 3)

    def get_timing_profile(self, profile_name: str) -> Dict[str, Any]:
        """Get timing profile by name."""
        if hasattr(self.config, 'TIMING_PROFILES'):
            # اگر profile_name یک عدد است، از آن استفاده کن
            if isinstance(profile_name, int) or profile_name.isdigit():
                profile_id = int(profile_name)
                return self.config.TIMING_PROFILES.get(profile_id, self.config.TIMING_PROFILES[3])
            
            # اگر profile_name یک string است، آن را پیدا کن
            for profile_id, profile_data in self.config.TIMING_PROFILES.items():
                if profile_data.get('name') == profile_name:
                    return profile_data
            
            # اگر پیدا نشد، default را برگردان
            return self.config.TIMING_PROFILES[3]
        
        # fallback به default values
        return {
            'name': 'normal',
            'delay': 0.5,
            'timeout': 4,
            'threads': 25,
            'randomize_delay': False
        }

    def _setup_logging(self):
        """Setup advanced logging system"""
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        date_format = '%Y-%m-%d %H:%M:%S'

        # استفاده از config.py برای log directory
        log_dir = self.get_config_value('OutputConfig', 'LOG_DIRECTORY', "scan_logs")
        if not os.path.exists(log_dir):  
            os.makedirs(log_dir)

        # Log file with unique name, including directory path
        log_file = f'{log_dir}/scanner_{self.target}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'

        # Create logger
        self.logger = logging.getLogger(__name__)

        # Check if handlers are already set up
        if not self.logger.hasHandlers():
            # Create file handler
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)  # Log level for file

            # Create stream handler (console output)
            stream_handler = logging.StreamHandler()
            stream_handler.setLevel(logging.CRITICAL)  # Log level for console

            # Create formatter
            formatter = logging.Formatter(log_format, datefmt=date_format)

            # Add formatter to handlers
            file_handler.setFormatter(formatter)
            stream_handler.setFormatter(formatter)

            # Add handlers to logger
            self.logger.addHandler(file_handler)
            self.logger.addHandler(stream_handler)

        self.logger.setLevel(logging.DEBUG)  # Set the logging level for the logger

        # Test log to check if logging is working
        self.logger.debug("Logging setup complete. This is a debug message.")  # Log a test message

    def _setup_signal_handlers(self):
        """Set up signal handlers for interrupt management"""
        signal.signal(signal.SIGINT, self._handle_interrupt)
        signal.signal(signal.SIGTERM, self._handle_interrupt)
        signal.signal(signal.SIGTSTP, self._handle_suspend)

    def _handle_interrupt(self, signum, frame):
        """Handle user interrupts"""
        self.logger.warning("\nReceived stop signal...")
        self.stop_scan = True
        self._cleanup()
    
    def _handle_suspend(self, signum, frame):
        """Handle suspend signal (Ctrl + Z)"""
        self.logger.warning("\nReceived suspend signal (Ctrl + Z)...")
        self.stop_scan = True
        self._cleanup()

    def scan(self, start_port: int, end_port: int, timing_profile: str = 'normal') -> dict:
        """Execute comprehensive scan with all capabilities"""
        self.stats['start_time'] = time.time()
        self.stats['total_ports'] = end_port - start_port + 1
        
        try:
            # Validate ports
            if not self._validate_ports(start_port, end_port):
                raise ValueError("Invalid port range")

            # Apply timing profile - استفاده از helper method جدید
            timing = self.get_timing_profile(timing_profile)
            self.delay_manager.set_scan_profile(timing_profile)

            self.logger.info(f"Starting scan of {self.target} with profile {timing_profile}")
            self.logger.info(f"Scanning ports {start_port} to {end_port}")

            # Create port batches
            batches = self.port_batch_manager.create_batches(start_port, end_port)
            total_batches = len(batches)

            self.logger.info(f"Created {total_batches} batches for scanning")

            scan_results = {
                'target': self.target,
                'start_time': datetime.now().isoformat(),
                'end_time': None,
                'duration': None,
                'scan_profile': timing_profile,
                'open_ports': [],
                'closed_ports': [],
                'filtered_ports': [],
                'services': {},
                'vulnerabilities': [],
                'traffic_analysis': {},
                'scan_stats': self.stats
            }

            # Process each batch
            for batch_idx, batch in enumerate(batches, 1):
                if self.stop_scan:
                    break

                self.logger.info(f"Processing batch {batch_idx}/{total_batches}")
                
                # Scan important ports first
                priority_ports = [p for p in batch if p in self.port_batch_manager.common_ports]
                if priority_ports:
                    self._scan_ports_batch(priority_ports, scan_results)
                
                # Scan remaining ports
                remaining_ports = [p for p in batch if p not in priority_ports]
                if remaining_ports:
                    self._scan_ports_batch(remaining_ports, scan_results)

                # Delay between batches
                if not self.stop_scan and batch_idx < total_batches:
                    self.delay_manager.wait_between_batches()

            # Finalize results
            scan_duration = time.time() - self.stats['start_time']
            scan_results.update({
                'end_time': datetime.now().isoformat(),
                'duration': scan_duration,
                'scan_stats': self.stats
            })

            # Traffic analysis
            traffic_analysis = self.traffic_manager.analyze_traffic_patterns()
            scan_results['traffic_analysis'] = traffic_analysis

            # Save results
            self.result_manager.save_results(scan_results)
            
            return scan_results

        except Exception as e:
            self.logger.error(f"Scan error: {str(e)}")
            raise
        finally:
            self._cleanup()

    def _scan_ports_batch(self, ports: List[int], scan_results: Dict):
        """Scan a batch of ports"""
        futures = []

        # استفاده از config.py برای MAX_THREADS
        max_threads = self.get_config_value('ScannerConfig', 'MAX_THREADS', 50)
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            for port in ports:
                if self.stop_scan:
                    break
                futures.append(executor.submit(self._scan_single_port, port))

            for future in futures:
                try:
                    result = future.result()
                    if result:
                        self._process_port_result(result, scan_results)
                except Exception as e:
                    self.logger.error(f"Port scan error: {e}")
                    self.stats['errors'] += 1

    def _scan_single_port(self, port: int) -> Optional[Dict]:
        """Single port scan with comprehensive tests"""
        if self.stop_scan:
            return None

        try:
            # Create advanced socket
            sock = self.advanced_socket_manager.create_tcp_socket()
            if not sock:
                return None

            # Initial port test
            result = self.port_handlers.handle_port(port)
            if result['state'] != 'open':
                return result

            # Service identification
            service_info = self.service_detector.detect_service(port)
            if service_info:
                result.update(service_info)

            # Protocol-specific tests
            if service_info and service_info['service']:
                self._perform_protocol_tests(sock, port, service_info['service'], result)

            # Banner analysis
            if result.get('banner'):
                banner_info = self.banner_analyzer.analyze_banner(result['banner'], port)
                result['banner_analysis'] = banner_info

                # Vulnerability check
                vulns = self.banner_analyzer.analyze_vulnerabilities(result['banner'])
                if vulns:
                    result['vulnerabilities'] = vulns

            return result

        except Exception as e:
            self.logger.error(f"Error scanning port {port}: {e}")
            return None
        finally:
            if 'sock' in locals():
                self.advanced_socket_manager.close_socket(sock)

    def _perform_protocol_tests(self, sock: socket.socket, port: int, service: str, result: Dict):
        """Perform protocol-specific tests"""
        if service == 'http':
            web_result = self.web_tester.test_web_port(self.target, port)
            if web_result:
                result.update(web_result)
        elif service in ['mysql', 'postgresql', 'mongodb']:
            db_result = self.db_tester.test_port(sock, port)
            if db_result:
                result.update(db_result)
        elif service in ['smtp', 'pop3', 'imap']:
            mail_result = self.mail_tester.verify_mail_service(sock, port)
            if mail_result:
                result.update(mail_result)

    def _process_port_result(self, result: Dict, scan_results: Dict):
        """Process and categorize port scan result"""
        if not result:
            return

        port = result['port']
        state = result['state']

        with self.lock:
            self.stats['scanned_ports'] += 1

            if state == 'open':
                scan_results['open_ports'].append(result)
                self.stats['open_ports'].add(port)
                
                # Update services
                service = result.get('service')
                if service:
                    if service not in scan_results['services']:
                        scan_results['services'][service] = []
                    scan_results['services'][service].append(port)

                # Check vulnerabilities
                if result.get('vulnerabilities'):
                    scan_results['vulnerabilities'].extend(
                        result['vulnerabilities']
                    )

            elif state == 'filtered':
                scan_results['filtered_ports'].append(port)
                self.stats['filtered_ports'].add(port)
            else:
                scan_results['closed_ports'].append(port)
                self.stats['closed_ports'].add(port)

    def _validate_ports(self, start_port: int, end_port: int) -> bool:
        """Validate port range"""
        return (1 <= start_port <= 65535 and 
                1 <= end_port <= 65535 and 
                start_port <= end_port)

    def _cleanup(self):
        """Clean up resources"""
        self.thread_pool.shutdown(wait=True)
        self.stop_scan = True
        self.logger.info("Cleaning up resources...")

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Port Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
        Usage examples:
        %(prog)s example.com
        %(prog)s example.com -p 1-1000
        %(prog)s example.com -p 1-1000 --timing 3 --threads 20
        %(prog)s example.com --profile stealth --output json
        '''
    )
    parser.prog = 'osgscan'
    
    parser.add_argument('target', help='Scan target')
    parser.add_argument(
        '-p', '--ports',
        help='Port range (e.g., 1-1000)',
        default='1-1000'
    )
    parser.add_argument(
        '-t', '--threads',
        type=int,
        help='Number of threads',
        default=10
    )
    parser.add_argument(
        '--timing',
        type=int,
        choices=range(0, 6),
        help='Timing profile (0=paranoid, 5=insane)',
        default=3
    )
    parser.add_argument(
        '--profile',
        choices=['stealth', 'normal', 'aggressive'],
        help='Scan profile',
        default='normal'
    )
    parser.add_argument(
        '-o', '--output',
        choices=['text', 'json', 'xml', 'html'],
        help='Output format',
        default='text'
    )
    parser.add_argument(
        '--config',
        help='Configuration file path (custom config.py file)'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode'
    )
    parser.add_argument(
        '--no-banner',
        action='store_true',
        help='Disable banner grabbing'
    )
    parser.add_argument(
        '--service-detection',
        action='store_true',
        help='Enable service detection'
    )
    parser.add_argument(
        '--vuln-check',
        action='store_true',
        help='Enable vulnerability checking'
    )
    parser.add_argument(
        '--interface',
        help='Network interface for scanning'
    )
    parser.add_argument(
        '--exclude-ports',
        help='Excluded ports (e.g., 80,443,3306)'
    )
    parser.add_argument(
        '--source-port',
        type=int,
        help='Source port'
    )

    args = parser.parse_args()

    # Set log level
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        # Convert and validate target
        target = args.target
        try:
            # Validate IP
            ipaddress.ip_address(target)
        except ValueError:
            try:
                # Convert hostname to IP
                target = socket.gethostbyname(target)
            except socket.gaierror:
                print(f"Error: Cannot resolve {args.target}")
                sys.exit(1)

        # Parse port range
        if '-' in args.ports:
            try:
                start_port, end_port = map(int, args.ports.split('-'))
                if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
                    raise ValueError
            except ValueError:
                print("Error: Invalid port range. Use start-end format (e.g., 1-1000)")
                sys.exit(1)
        else:
            try:
                # If only a single port is provided, treat it as a range
                start_port = end_port = int(args.ports)
                if not (1 <= start_port <= 65535):
                    raise ValueError
            except ValueError:
                print("Error: Invalid port. Port must be between 1 and 65535.")
                sys.exit(1)

        # Process excluded ports
        excluded_ports = set()
        if args.exclude_ports:
            try:
                excluded_ports = {int(p) for p in args.exclude_ports.split(',')}
            except ValueError:
                print("Error: Invalid excluded ports format")
                sys.exit(1)

        # Map timing to profile
        timing_profiles = {
            0: 'paranoid',
            1: 'sneaky',
            2: 'polite',
            3: 'normal',
            4: 'aggressive',
            5: 'insane'
        }
        timing_profile = timing_profiles[args.timing]

        # Create and configure scanner
        scanner = EnhancedScanner(target, args.config)
        
        # Apply additional settings - استفاده از attributes موجود
        if hasattr(scanner, 'config'):
            if args.source_port:
                # اگر config یک dynamic object است
                if hasattr(scanner.config, '__dict__'):
                    scanner.config.source_port = args.source_port
            if args.interface:
                if hasattr(scanner.config, '__dict__'):
                    scanner.config.interface = args.interface
            
            # Apply scanner-specific settings
            if hasattr(scanner.config, '__dict__'):
                scanner.config.service_detection = args.service_detection
                scanner.config.vuln_check = args.vuln_check
                scanner.config.no_banner = args.no_banner

        print(f"\nStarting scan of {args.target}")
        print(f"Port range: {start_port}-{end_port}")
        print(f"Profile: {timing_profile}")
        print("=" * 50)

        try:
            # Execute scan
            results = scanner.scan(
                start_port, 
                end_port,
                timing_profile
            )

            """Display formatted scan results"""
            print("\nScan Results:")
            print("-" * 50)
            print(f"Target: {results['target']}")
            print(f"Duration: {results['duration']:.2f} seconds")
            print(f"Total ports: {results['scan_stats']['total_ports']}")
            print(f"Open ports: {len(results['scan_stats']['open_ports'])}")
            print(f"Filtered ports: {len(results['scan_stats']['filtered_ports'])}")
            print(f"Closed ports: {len(results['scan_stats']['closed_ports'])}")

            if results.get('open_ports'):
                print("\nOpen Ports:")
                print("-" * 50)
                for port_info in sorted(results['open_ports'], key=lambda x: x['port']):
                    port = port_info['port']
                    state = port_info['state']
                    service = port_info.get('service', 'unknown')
                    version = port_info.get('version', '')
                    print(f"Port {port}/tcp - {state} - {service} {version}")
                    
                    # Display additional port details if available
                    if port_info.get('banner'):
                        print(f"  Banner: {port_info['banner'][:100]}...")
                    if port_info.get('ssl'):
                        print("  SSL: Enabled")

            if results.get('open_ports'):
                print("\nDetected Services:")
                print("-" * 50)
                services = {}
                for port_info in results['open_ports']:
                    if port_info.get('service'):
                        service = port_info['service']
                        port = port_info['port']
                        if service not in services:
                            services[service] = []
                        services[service].append(port)
                
                for service, ports in services.items():
                    ports_str = ', '.join(map(str, ports))
                    version = next((p.get('version', '') for p in results['open_ports'] 
                                if p['port'] == ports[0]), '')
                    version_str = f" (version {version})" if version else ""
                    print(f"{service}{version_str}: ports {ports_str}")

            if results.get('vulnerabilities'):
                print("\nDetected Vulnerabilities:")
                print("-" * 50)
                for vuln in results['vulnerabilities']:
                    print(f"- Port {vuln.get('port', 'N/A')}: {vuln['description']}")
                    print(f"  Severity: {vuln.get('severity', 'Unknown')}")

            print(f"\nComplete results have been saved to log file")
        except KeyboardInterrupt:
            print("\nScan stopped by user")
            scanner.stop_scan = True
            sys.exit(1)

    except Exception as e:
        print(f"\nError executing scan: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
