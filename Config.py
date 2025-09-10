# Config.py
import os
import yaml
import json
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
import threading

@dataclass
class ScanTiming:
    scan_delay: float = 0.1
    timeout: float = 2.0
    max_retries: int = 2
    max_rate: int = 1000
    parallel_hosts: int = 10
    batch_size: int = 50
    connection_timeout: float = 2.0
    banner_timeout: float = 1.0

class Config:
    def __init__(self, config_file: Optional[str] = None):
        self._lock = threading.Lock()
        self.EXCLUDED_PORTS = {161, 162, 705}  # SNMP ports
        
        # Basic scanner settings
        self.MAX_THREADS = 15
        self.TIMEOUT = 2.0
        self.RETRY_COUNT = 2
        
        # Setting SOURCE_PORT_RANGE
        self.SOURCE_PORT_RANGE = (32768, 61000)
        self.interface = None  # Default value is None
        self.service_detection = False  # Default setting for service detection
        self.vuln_check = False  # Default setting for vulnerability checks
        self.no_banner = False 

        # Setting timing templates
        self.timing = {
            'paranoid': ScanTiming(
                scan_delay=0.5, timeout=5.0, max_retries=3,
                max_rate=10, parallel_hosts=1
            ),
            'sneaky': ScanTiming(
                scan_delay=0.3, timeout=4.0, max_retries=2,
                max_rate=50, parallel_hosts=3
            ),
            'normal': ScanTiming(
                scan_delay=0.1, timeout=2.0, max_retries=2,
                max_rate=100, parallel_hosts=5
            ),
            'aggressive': ScanTiming(
                scan_delay=0.05, timeout=1.5, max_retries=1,
                max_rate=300, parallel_hosts=10
            )
        }

        # Network settings
        self.network = {
            'ip_fragmentation': True,
            'random_source_port': True,
            'custom_tcp_flags': True,
            'decoy_scan': False
        }

        # SSL/TLS settings
        self.ssl_config = {
            'verify_cert': False,
            'check_hostname': False,
            'min_version': 'TLSv1',
            'ciphers': 'ALL:@SECLEVEL=1'
        }

        # Reading settings from file
        if config_file:
            self.load_config(config_file)
            
    def load_config(self, config_file: str) -> None:
        try:
            with open(config_file, 'r') as f:
                if config_file.endswith('.yaml'):
                    config = yaml.safe_load(f)
                elif config_file.endswith('.json'):
                    config = json.load(f)
                else:
                    raise ValueError("Unsupported file format")

            self._update_config(config)
        except Exception as e:
            logging.error(f"Error reading configuration: {e}")
            raise

    def _update_config(self, config: Dict) -> None:
        """Update settings with new values"""
        with self._lock:
            if 'scanner' in config:
                self._update_scanner_config(config['scanner'])
            if 'timing_templates' in config:
                self._update_timing_templates(config['timing_templates'])
            if 'network' in config:
                self.network.update(config['network'])
            if 'ssl' in config:
                self.ssl_config.update(config['ssl'])
            if 'service_detection' in config:
                self.service_detection = config['service_detection']
            if 'vuln_check' in config:
                self.vuln_check = config['vuln_check']
            if 'no_banner' in config:
                self.no_banner = config['no_banner']

    def _update_scanner_config(self, config: Dict) -> None:
        if 'max_threads' in config:
            self.MAX_THREADS = config['max_threads']
        if 'timeout' in config:
            self.TIMEOUT = config['timeout']
        if 'retry_count' in config:
            self.RETRY_COUNT = config['retry_count']
        if 'source_port_range' in config:
            self.SOURCE_PORT_RANGE = tuple(config['source_port_range'])
        if 'excluded_ports' in config:
            self.SNMP_PORTS = config['excluded_ports']

    def _update_timing_templates(self, config: Dict) -> None:
        for template, settings in config.items():
            if template in self.timing:
                self.timing[template] = ScanTiming(**settings)

    def get_timing(self, profile: str = 'normal') -> ScanTiming:
        """Get timing settings for a specific profile"""
        return self.timing.get(profile, self.timing['normal'])

    def validate(self) -> bool:
        """Validate the settings"""
        try:
            assert self.SOURCE_PORT_RANGE[0] < self.SOURCE_PORT_RANGE[1]
            assert 1 <= self.SOURCE_PORT_RANGE[0] <= 65535
            assert 1 <= self.SOURCE_PORT_RANGE[1] <= 65535
            
            for timing in self.timing.values():
                assert timing.scan_delay > 0
                assert timing.timeout > 0
                assert timing.max_retries >= 0

            return True
            
        except AssertionError as e:
            logging.error(f"Error validating settings: {e}")
            return False
        
    def is_port_excluded(self, port: int) -> bool:
        return port in self.EXCLUDED_PORTS  
