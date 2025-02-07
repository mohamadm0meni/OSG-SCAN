from typing import List, Set, Optional
import random
import time
import logging
from collections import defaultdict

class PortBatchManager:
    """Advanced port batch management with intelligent scan strategies"""

    def __init__(self):
        # Define service ports with priorities
        self.service_ports = {
            'CRITICAL': {
                'ports': {22, 3389},  # SSH, RDP
                'max_per_batch': 2,
                'scan_timeout': 3.0
            },
            'HIGH': {
                'ports': {80, 443, 8080, 8443},  # Web
                'max_per_batch': 4,
                'scan_timeout': 2.5
            },
            'MEDIUM': {
                'ports': {
                    21, 25, 110, 143,  # FTP, Mail
                    3306, 5432, 1433, 6379,  # Databases
                    389, 636,  # LDAP
                    445, 139  # SMB
                },
                'max_per_batch': 6,
                'scan_timeout': 2.0
            },
            'LOW': {
                'ports': set(range(1, 65536)) - {22, 3389, 80, 443, 8080, 8443,
                                            21, 25, 110, 143, 3306, 5432,
                                            1433, 6379, 389, 636, 445, 139},
                'max_per_batch': 10,
                'scan_timeout': 1.5
            }
        }

        # Initialize important ports set
        self.important_ports = set()
        for priority in ['CRITICAL', 'HIGH', 'MEDIUM']:
            self.important_ports.update(self.service_ports[priority]['ports'])
        
        # Add common ports for scanning (e.g., ports that are typically scanned)
        self.common_ports = {
            22, 3389, 80, 443, 8080, 8443, 21, 25, 110, 143, 3306, 5432
        }

        # Batch configuration
        self.default_batch_size = 50
        self.min_batch_delay = 0.5
        self.max_batch_delay = 2.0

        # Port state tracking
        self.scanned_ports = set()
        self.open_ports = set()
        self.filtered_ports = set()

        # Scan statistics
        self.scan_stats = {
            'start_time': None,
            'last_batch_time': 0,
            'batches_sent': 0,
            'ports_scanned': 0
        }

        # Setup logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

    def create_batches(self, start_port: int, end_port: int, batch_size: int = None) -> List[List[int]]:
        """Create optimized port scan batches"""
        if batch_size is None:
            batch_size = self.default_batch_size

        # Get all ports in range
        excluded_ports = {161, 162, 705}
        all_ports = [port for port in range(start_port, end_port + 1) 
                    if port not in excluded_ports]
        
        # Group ports by priority
        ports_by_priority = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': []
        }

        for port in all_ports:
            assigned = False
            for priority in ['CRITICAL', 'HIGH', 'MEDIUM']:
                if port in self.service_ports[priority]['ports']:
                    ports_by_priority[priority].append(port)
                    assigned = True
                    break
            if not assigned:
                ports_by_priority['LOW'].append(port)

        # Create batches with priority mixing
        batches = []
        current_batch = []

        # First add high priority ports
        for priority in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            for port in ports_by_priority[priority]:
                current_batch.append(port)
                if len(current_batch) >= batch_size:
                    batches.append(current_batch)
                    current_batch = []

        # Add any remaining ports
        if current_batch:
            batches.append(current_batch)

        return batches

    def get_port_priority(self, port: int) -> str:
        """Get priority level for a port"""
        for priority, config in self.service_ports.items():
            if port in config['ports']:
                return priority
        return 'LOW'

    def get_scan_timeout(self, port: int) -> float:
        """Get appropriate timeout for a port based on its priority"""
        priority = self.get_port_priority(port)
        return self.service_ports[priority]['scan_timeout']

    def update_stats(self, port: int, is_open: bool = False):
        """Update scan statistics"""
        self.scanned_ports.add(port)
        if is_open:
            self.open_ports.add(port)

    def log_stats(self):
        """Log the scan statistics"""
        self.logger.info(f"Scan statistics:")
        self.logger.info(f"  Total ports scanned: {len(self.scanned_ports)}")
        self.logger.info(f"  Open ports: {len(self.open_ports)}")
        self.logger.info(f"  Filtered ports: {len(self.filtered_ports)}")
        self.logger.info(f"  Last batch sent: {self.scan_stats['last_batch_time']}")
        self.logger.info(f"  Batches sent: {self.scan_stats['batches_sent']}")

    def adjust_batch_delay(self):
        """Adjust delay between batches"""
        batch_delay = random.uniform(self.min_batch_delay, self.max_batch_delay)
        self.scan_stats['last_batch_time'] = time.time()
        time.sleep(batch_delay)

    def reset_scan(self):
        """Reset scan stats"""
        self.scanned_ports = set()
        self.open_ports = set()
        self.filtered_ports = set()
        self.scan_stats = {
            'start_time': None,
            'last_batch_time': 0,
            'batches_sent': 0,
            'ports_scanned': 0
        }

    def get_open_ports(self) -> Set[int]:
        """Get all open ports"""
        return self.open_ports

    def get_filtered_ports(self) -> Set[int]:
        """Get all filtered ports"""
        return self.filtered_ports

    def get_total_scanned_ports(self) -> int:
        """Get total number of scanned ports"""
        return len(self.scanned_ports)

    def get_total_open_ports(self) -> int:
        """Get total number of open ports"""
        return len(self.open_ports)

    def get_total_filtered_ports(self) -> int:
        """Get total number of filtered ports"""
        return len(self.filtered_ports)

    def get_scan_duration(self) -> float:
        """Get total scan duration"""
        return self.scan_stats['last_batch_time'] - self.scan_stats['start_time'] if self.scan_stats['start_time'] else 0.0

    def start_scan(self, start_port: int, end_port: int, batch_size: Optional[int] = None):
        """Start scanning the ports in the given range"""
        self.reset_scan()
        self.scan_stats['start_time'] = time.time()

        batches = self.create_batches(start_port, end_port, batch_size)
        self.scan_stats['batches_sent'] = len(batches)

        # Scan batches
        for batch in batches:
            self.adjust_batch_delay()
            self.scan_ports(batch)

        self.log_stats()

    def scan_ports(self, batch: List[int]):
        """Scan the ports in a given batch"""
        for port in batch:
            # Here, you can call actual scanning functions for each port
            # For now, we simulate the port scanning logic:
            port_state = 'open' if random.random() < 0.5 else 'closed'
            if port_state == 'open':
                self.update_stats(port, is_open=True)
            elif port_state == 'filtered':
                self.filtered_ports.add(port)
                self.update_stats(port)

        # Increment scan stats after batch processing
        self.scan_stats['ports_scanned'] += len(batch)
