#!/usr/bin/env python3
"""
OSG-SCAN Configuration Module

This module contains all configuration settings for OSG-SCAN.
Settings are organized by category and can be easily modified.

Version: 2.0
Last Updated: 2025-09-11
"""

import os
from typing import Dict, List, Any, Optional

# =============================================================================
# Core Configuration
# =============================================================================

VERSION = "2.0"
LAST_UPDATED = "2025-09-11"
AUTHOR = "mohamadm0meni"
GITHUB_URL = "https://github.com/mohamadm0meni/OSG-SCAN"

# =============================================================================
# Scanner Configuration
# =============================================================================

class ScannerConfig:
    """Main scanner configuration settings."""
    
    # Thread and timing settings
    DEFAULT_THREADS = 50
    MAX_THREADS = 200
    MIN_THREADS = 1
    
    # Timeout settings
    DEFAULT_TIMEOUT = 3
    MAX_TIMEOUT = 30
    MIN_TIMEOUT = 1
    
    # Retry and delay settings
    MAX_RETRIES = 3
    SCAN_DELAY = 0.1
    
    # Port settings
    DEFAULT_PORTS = "1-1000"
    COMMON_PORTS = "21,22,23,25,53,80,110,143,443,993,995,3306,5432,6379,27017"
    ALL_PORTS = "1-65535"
    
    # Scanner behavior
    STEALTH_MODE = True
    RANDOMIZE_SCAN_ORDER = True
    ENABLE_SERVICE_DETECTION = True
    ENABLE_BANNER_GRABBING = True


# =============================================================================
# Timing Profiles
# =============================================================================

TIMING_PROFILES = {
    0: {
        "name": "paranoid",
        "description": "Extremely slow and stealthy - maximum evasion",
        "delay": 5.0,
        "timeout": 10,
        "threads": 1,
        "randomize_delay": True,
        "max_delay_variance": 2.0,
        "packets_per_second": 0.2
    },
    1: {
        "name": "sneaky",
        "description": "Slow and stealthy - high evasion",
        "delay": 2.0,
        "timeout": 8,
        "threads": 5,
        "randomize_delay": True,
        "max_delay_variance": 1.0,
        "packets_per_second": 0.5
    },
    2: {
        "name": "polite",
        "description": "Respectful scanning - moderate evasion",
        "delay": 1.0,
        "timeout": 6,
        "threads": 10,
        "randomize_delay": True,
        "max_delay_variance": 0.5,
        "packets_per_second": 1.0
    },
    3: {
        "name": "normal",
        "description": "Balanced approach - default setting",
        "delay": 0.5,
        "timeout": 4,
        "threads": 25,
        "randomize_delay": False,
        "max_delay_variance": 0.2,
        "packets_per_second": 2.0
    },
    4: {
        "name": "aggressive",
        "description": "Fast scanning - minimal evasion",
        "delay": 0.1,
        "timeout": 2,
        "threads": 50,
        "randomize_delay": False,
        "max_delay_variance": 0.1,
        "packets_per_second": 10.0
    },
    5: {
        "name": "insane",
        "description": "Maximum speed - no evasion",
        "delay": 0.01,
        "timeout": 1,
        "threads": 100,
        "randomize_delay": False,
        "max_delay_variance": 0.01,
        "packets_per_second": 50.0
    }
}

# =============================================================================
# Scan Profiles
# =============================================================================

SCAN_PROFILES = {
    "stealth": {
        "description": "Maximum evasion and stealth capabilities",
        "randomize_agents": True,
        "fragment_packets": True,
        "randomize_delays": True,
        "randomize_source_ports": True,
        "avoid_common_ports": False,
        "timing_profile": 1,
        "use_decoys": False,
        "spoof_mac": False,
        "packet_trace": False,
        "tcp_window_size": 1024,
        "mss_value": 536
    },
    "normal": {
        "description": "Balanced scan with moderate stealth",
        "randomize_agents": True,
        "fragment_packets": False,
        "randomize_delays": True,
        "randomize_source_ports": True,
        "avoid_common_ports": False,
        "timing_profile": 3,
        "use_decoys": False,
        "spoof_mac": False,
        "packet_trace": False,
        "tcp_window_size": 8192,
        "mss_value": 1460
    },
    "aggressive": {
        "description": "Fast scan with minimal stealth",
        "randomize_agents": False,
        "fragment_packets": False,
        "randomize_delays": False,
        "randomize_source_ports": False,
        "avoid_common_ports": False,
        "timing_profile": 4,
        "use_decoys": False,
        "spoof_mac": False,
        "packet_trace": False,
        "tcp_window_size": 65535,
        "mss_value": 1460
    }
}

# =============================================================================
# Output Configuration
# =============================================================================

class OutputConfig:
    """Output and logging configuration."""
    
    # Output formats
    DEFAULT_FORMAT = "json"
    SUPPORTED_FORMATS = ["text", "json", "xml", "html", "csv"]
    
    # Directory paths
    RESULTS_DIRECTORY = "/usr/local/scanner/scan_results"
    LOG_DIRECTORY = "/usr/local/scanner/logs"
    TEMP_DIRECTORY = "/usr/local/scanner/temp"
    CONFIG_DIRECTORY = "/usr/local/scanner/config"
    
    # Logging settings
    LOG_LEVEL = "INFO"
    LOG_ROTATION = True
    MAX_LOG_SIZE = "10MB"
    MAX_LOG_FILES = 5
    TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
    
    # Output features
    INCLUDE_BANNER = True
    INCLUDE_STATISTICS = True
    COMPRESS_RESULTS = False
    AUTO_CLEANUP = True
    CLEANUP_DAYS = 30
    
    # File naming
    FILENAME_TEMPLATE = "osgscan_{target}_{timestamp}"
    TIMESTAMP_IN_FILENAME = True


# =============================================================================
# Database Configuration
# =============================================================================

class DatabaseConfig:
    """Database connection and settings."""
    
    # Connection settings
    ENABLED = False
    TYPE = "mysql"  # mysql, postgresql, sqlite
    HOST = "localhost"
    PORT = 3306
    DATABASE = "osgscan"
    USERNAME = ""
    PASSWORD = ""
    
    # Connection options
    CHARSET = "utf8mb4"
    AUTOCOMMIT = True
    CONNECTION_TIMEOUT = 10
    POOL_SIZE = 5
    MAX_RETRIES = 3
    
    # SSL settings
    SSL_ENABLED = False
    SSL_CA = ""
    SSL_CERT = ""
    SSL_KEY = ""
    
    # Table settings
    RESULTS_TABLE = "scan_results"
    HOSTS_TABLE = "scanned_hosts"
    SESSIONS_TABLE = "scan_sessions"


# =============================================================================
# Security Configuration
# =============================================================================

class SecurityConfig:
    """Security and stealth configuration."""
    
    # General security
    STEALTH_MODE = True
    RANDOMIZE_AGENTS = True
    AVOID_DETECTION = True
    
    # User agents for HTTP requests
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
    ]
    
    # Rate limiting
    MAX_REQUESTS_PER_SECOND = 10
    RESPECT_ROBOTS_TXT = False
    FOLLOW_REDIRECTS = True
    VERIFY_SSL = False
    
    # Custom headers
    CUSTOM_HEADERS = {}
    
    # Proxy settings
    PROXY_ENABLED = False
    PROXY_LIST = []
    PROXY_ROTATION = False
    PROXY_TIMEOUT = 10
    
    # Advanced evasion
    PACKET_FRAGMENTATION = True
    SOURCE_PORT_RANDOMIZATION = True
    TTL_MANIPULATION = False
    IP_ID_RANDOMIZATION = True


# =============================================================================
# Service Detection Configuration
# =============================================================================

class ServiceConfig:
    """Service detection and banner grabbing settings."""
    
    # Detection settings
    ENABLED = True
    BANNER_GRABBING = True
    DEEP_SCAN = False
    TIMEOUT = 5
    MAX_BANNER_SIZE = 1024
    BANNER_TIMEOUT = 3
    
    # Known service mappings
    KNOWN_SERVICES = {
        21: "ftp",
        22: "ssh", 
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        993: "imaps",
        995: "pop3s",
        3306: "mysql",
        5432: "postgresql",
        6379: "redis",
        27017: "mongodb",
        1433: "mssql",
        1521: "oracle",
        5984: "couchdb",
        9200: "elasticsearch",
        11211: "memcached",
        8080: "http-alt",
        8443: "https-alt",
        3389: "rdp",
        5900: "vnc",
        161: "snmp",
        389: "ldap",
        636: "ldaps"
    }
    
    # Service probes
    SERVICE_PROBES = {
        "http": ["GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: OSG-Scanner\r\n\r\n"],
        "https": ["GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: OSG-Scanner\r\n\r\n"],
        "ftp": ["\r\n", "USER anonymous\r\n"],
        "ssh": ["SSH-2.0-OSG_Scanner\r\n"],
        "smtp": ["EHLO osgscan.local\r\n"],
        "pop3": ["USER test\r\n"],
        "imap": ["A001 CAPABILITY\r\n"],
        "mysql": ["\x00\x00\x00\x0a"],
        "telnet": ["\xff\xfb\x01\xff\xfb\x03\xff\xfc\x01"],
        "dns": ["\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"]
    }
    
    # SSL/TLS settings
    SSL_PROBE_ENABLED = True
    SSL_CIPHER_SCAN = False
    SSL_CERT_INFO = True


# =============================================================================
# Vulnerability Assessment Configuration
# =============================================================================

class VulnerabilityConfig:
    """Vulnerability assessment settings."""
    
    # Assessment settings
    ENABLED = True
    UPDATE_DATABASES = True
    CHECK_CVE = True
    CHECK_MISCONFIGURATIONS = True
    CHECK_DEFAULT_CREDENTIALS = True
    SEVERITY_THRESHOLD = "medium"  # low, medium, high, critical
    MAX_CHECK_TIME = 30
    
    # External databases
    VULNERABILITY_DATABASES = [
        "https://cve.circl.lu/api/",
        "https://vulners.com/api/",
        "https://www.exploit-db.com/api/"
    ]
    
    # Local vulnerability database
    LOCAL_CVE_DB = "/usr/local/scanner/data/cve.db"
    UPDATE_INTERVAL = 24  # hours
    
    # Checks configuration
    CUSTOM_CHECKS = []
    EXCLUDE_CHECKS = []
    REPORT_FORMAT = "detailed"  # summary, detailed, full
    
    # Common vulnerabilities to check
    COMMON_VULNERABILITIES = {
        "ssl": ["weak_ciphers", "expired_certs", "self_signed"],
        "ssh": ["weak_algorithms", "default_keys"],
        "web": ["directory_listing", "default_pages", "admin_panels"],
        "database": ["default_credentials", "weak_auth", "version_disclosure"]
    }


# =============================================================================
# Network Configuration
# =============================================================================

class NetworkConfig:
    """Network and packet manipulation settings."""
    
    # Basic network settings
    SOURCE_PORT_RANDOMIZATION = True
    INTERFACE = "auto"  # auto-detect or specific interface
    MAX_BANDWIDTH = "1MB"
    PACKET_SIZE = 64
    FRAGMENT_SIZE = 8
    TTL = 64
    
    # Port settings
    SOURCE_PORT_RANGE = "32768-65535"
    BIND_ADDRESS = "0.0.0.0"
    
    # DNS settings
    RESOLVE_HOSTNAMES = True
    DNS_SERVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]
    DNS_TIMEOUT = 3
    
    # Protocol support
    IPV6_SUPPORT = False
    IPV4_PRIORITY = True
    
    # Advanced network options
    TCP_WINDOW_SIZE = 8192
    TCP_MSS = 1460
    TCP_NODELAY = True
    SOCKET_KEEPALIVE = False


# =============================================================================
# Performance Configuration
# =============================================================================

class PerformanceConfig:
    """Performance optimization settings."""
    
    # Memory management
    MEMORY_LIMIT = "512MB"
    CPU_LIMIT = 80  # percentage
    DISK_CACHE = True
    CACHE_SIZE = "100MB"
    
    # Concurrency settings
    PARALLEL_HOSTS = 1
    QUEUE_SIZE = 1000
    BATCH_SIZE = 100
    CONNECTION_POOLING = True
    POOL_MAX_SIZE = 100
    
    # Optimization flags
    USE_NATIVE_SOCKETS = True
    ENABLE_FAST_MODE = False
    MEMORY_MAPPED_FILES = False
    ASYNC_IO = True


# =============================================================================
# Reporting Configuration
# =============================================================================

class ReportingConfig:
    """Report generation and formatting settings."""
    
    # Report content
    INCLUDE_TIMESTAMP = True
    INCLUDE_SCAN_DETAILS = True
    INCLUDE_HOST_INFO = True
    INCLUDE_SERVICE_INFO = True
    INCLUDE_VULNERABILITY_INFO = True
    INCLUDE_BANNER_INFO = True
    GENERATE_STATISTICS = True
    
    # Report format
    COMPRESS_RESULTS = False
    PRETTY_PRINT_JSON = True
    XML_FORMATTING = True
    HTML_STYLING = True
    
    # Email reporting
    EMAIL_REPORTS = False
    EMAIL_SETTINGS = {
        "smtp_server": "",
        "smtp_port": 587,
        "username": "",
        "password": "",
        "from_address": "",
        "to_addresses": [],
        "use_tls": True,
        "subject_template": "OSG-SCAN Results: {target}"
    }
    
    # Report templates
    TEXT_TEMPLATE = "templates/report.txt"
    HTML_TEMPLATE = "templates/report.html"
    XML_TEMPLATE = "templates/report.xml"


# =============================================================================
# Advanced Configuration
# =============================================================================

class AdvancedConfig:
    """Advanced and experimental features."""
    
    # Raw socket capabilities
    ENABLE_RAW_SOCKETS = False
    ENABLE_PACKET_CAPTURE = False
    PCAP_INTERFACE = "any"
    
    # Custom techniques
    CUSTOM_TCP_OPTIONS = {}
    CUSTOM_SCAN_TECHNIQUES = []
    
    # Plugin system
    PLUGIN_DIRECTORY = "/usr/local/scanner/plugins"
    ENABLE_PLUGINS = False
    PLUGIN_TIMEOUT = 30
    
    # Debug and development
    DEBUG_MODE = False
    VERBOSE_LOGGING = False
    TRACE_PACKETS = False
    PROFILE_PERFORMANCE = False
    
    # Experimental features
    MACHINE_LEARNING = False
    AI_SERVICE_DETECTION = False
    BEHAVIORAL_ANALYSIS = False


# =============================================================================
# Web Interface Configuration (Future)
# =============================================================================

class WebConfig:
    """Web interface configuration (when implemented)."""
    
    # Server settings
    ENABLED = False
    HOST = "0.0.0.0"
    PORT = 8080
    SSL_PORT = 8443
    
    # SSL settings
    SSL_ENABLED = False
    SSL_CERT = ""
    SSL_KEY = ""
    
    # Authentication
    AUTHENTICATION = False
    USERNAME = "admin"
    PASSWORD = "admin"  # Should be changed!
    SESSION_TIMEOUT = 3600
    
    # Features
    MAX_CONCURRENT_SCANS = 5
    REAL_TIME_UPDATES = True
    SCAN_HISTORY = True


# =============================================================================
# API Configuration (Future)
# =============================================================================

class APIConfig:
    """REST API configuration (when implemented)."""
    
    # API server
    ENABLED = False
    HOST = "0.0.0.0"
    PORT = 8081
    
    # Security
    RATE_LIMITING = True
    MAX_REQUESTS_PER_MINUTE = 60
    AUTHENTICATION = False
    API_KEY = ""
    
    # CORS settings
    CORS_ENABLED = True
    ALLOWED_ORIGINS = ["*"]
    ALLOWED_METHODS = ["GET", "POST"]
    ALLOWED_HEADERS = ["Content-Type", "Authorization"]


# =============================================================================
# Environment-based Configuration Override
# =============================================================================

def load_environment_config():
    """Load configuration overrides from environment variables."""
    
    # Scanner settings
    if os.getenv("OSGSCAN_THREADS"):
        ScannerConfig.DEFAULT_THREADS = int(os.getenv("OSGSCAN_THREADS"))
    
    if os.getenv("OSGSCAN_TIMEOUT"):
        ScannerConfig.DEFAULT_TIMEOUT = int(os.getenv("OSGSCAN_TIMEOUT"))
    
    if os.getenv("OSGSCAN_PORTS"):
        ScannerConfig.DEFAULT_PORTS = os.getenv("OSGSCAN_PORTS")
    
    # Output settings
    if os.getenv("OSGSCAN_OUTPUT_DIR"):
        OutputConfig.RESULTS_DIRECTORY = os.getenv("OSGSCAN_OUTPUT_DIR")
    
    if os.getenv("OSGSCAN_LOG_LEVEL"):
        OutputConfig.LOG_LEVEL = os.getenv("OSGSCAN_LOG_LEVEL")
    
    # Database settings
    if os.getenv("OSGSCAN_DB_HOST"):
        DatabaseConfig.HOST = os.getenv("OSGSCAN_DB_HOST")
    
    if os.getenv("OSGSCAN_DB_USER"):
        DatabaseConfig.USERNAME = os.getenv("OSGSCAN_DB_USER")
    
    if os.getenv("OSGSCAN_DB_PASS"):
        DatabaseConfig.PASSWORD = os.getenv("OSGSCAN_DB_PASS")
    
    # Security settings
    if os.getenv("OSGSCAN_STEALTH"):
        SecurityConfig.STEALTH_MODE = os.getenv("OSGSCAN_STEALTH").lower() == "true"


# =============================================================================
# Configuration Validation
# =============================================================================

def validate_configuration():
    """Validate configuration settings and fix common issues."""
    
    # Validate thread count
    if ScannerConfig.DEFAULT_THREADS > ScannerConfig.MAX_THREADS:
        ScannerConfig.DEFAULT_THREADS = ScannerConfig.MAX_THREADS
    
    if ScannerConfig.DEFAULT_THREADS < ScannerConfig.MIN_THREADS:
        ScannerConfig.DEFAULT_THREADS = ScannerConfig.MIN_THREADS
    
    # Validate timeout
    if ScannerConfig.DEFAULT_TIMEOUT > ScannerConfig.MAX_TIMEOUT:
        ScannerConfig.DEFAULT_TIMEOUT = ScannerConfig.MAX_TIMEOUT
    
    if ScannerConfig.DEFAULT_TIMEOUT < ScannerConfig.MIN_TIMEOUT:
        ScannerConfig.DEFAULT_TIMEOUT = ScannerConfig.MIN_TIMEOUT
    
    # Create directories if they don't exist
    for directory in [OutputConfig.RESULTS_DIRECTORY, 
                     OutputConfig.LOG_DIRECTORY, 
                     OutputConfig.TEMP_DIRECTORY]:
        os.makedirs(directory, exist_ok=True)
    
    # Validate timing profiles
    for profile_id, profile in TIMING_PROFILES.items():
        if profile["threads"] > ScannerConfig.MAX_THREADS:
            profile["threads"] = ScannerConfig.MAX_THREADS


# =============================================================================
# Configuration Export/Import
# =============================================================================

def export_config_to_dict() -> Dict[str, Any]:
    """Export current configuration to dictionary."""
    return {
        "version": VERSION,
        "scanner": {
            "default_threads": ScannerConfig.DEFAULT_THREADS,
            "max_threads": ScannerConfig.MAX_THREADS,
            "default_timeout": ScannerConfig.DEFAULT_TIMEOUT,
            "max_timeout": ScannerConfig.MAX_TIMEOUT,
            "max_retries": ScannerConfig.MAX_RETRIES,
            "scan_delay": ScannerConfig.SCAN_DELAY,
            "default_ports": ScannerConfig.DEFAULT_PORTS,
            "stealth_mode": ScannerConfig.STEALTH_MODE
        },
        "timing_profiles": TIMING_PROFILES,
        "scan_profiles": SCAN_PROFILES,
        "output": {
            "default_format": OutputConfig.DEFAULT_FORMAT,
            "results_directory": OutputConfig.RESULTS_DIRECTORY,
            "log_level": OutputConfig.LOG_LEVEL
        },
        "security": {
            "stealth_mode": SecurityConfig.STEALTH_MODE,
            "randomize_agents": SecurityConfig.RANDOMIZE_AGENTS,
            "max_requests_per_second": SecurityConfig.MAX_REQUESTS_PER_SECOND
        }
    }


def get_timing_profile(profile_id: int) -> Dict[str, Any]:
    """Get timing profile by ID."""
    return TIMING_PROFILES.get(profile_id, TIMING_PROFILES[3])  # Default to normal


def get_scan_profile(profile_name: str) -> Dict[str, Any]:
    """Get scan profile by name."""
    return SCAN_PROFILES.get(profile_name, SCAN_PROFILES["normal"])  # Default to normal


# =============================================================================
# Initialization
# =============================================================================

def initialize_config():
    """Initialize configuration system."""
    load_environment_config()
    validate_configuration()
    
    # Log configuration status
    print(f"OSG-SCAN Configuration v{VERSION} loaded successfully")
    print(f"Default threads: {ScannerConfig.DEFAULT_THREADS}")
    print(f"Default timeout: {ScannerConfig.DEFAULT_TIMEOUT}")
    print(f"Stealth mode: {SecurityConfig.STEALTH_MODE}")


# Initialize configuration when module is imported
if __name__ != "__main__":
    initialize_config()


# =============================================================================
# Main Function (for testing)
# =============================================================================

if __name__ == "__main__":
    """Test configuration module."""
    print("Testing OSG-SCAN Configuration...")
    
    initialize_config()
    
    print("\nScanner Configuration:")
    print(f"  Threads: {ScannerConfig.DEFAULT_THREADS}")
    print(f"  Timeout: {ScannerConfig.DEFAULT_TIMEOUT}")
    print(f"  Ports: {ScannerConfig.DEFAULT_PORTS}")
    
    print("\nTiming Profiles:")
    for profile_id, profile in TIMING_PROFILES.items():
        print(f"  {profile_id}: {profile['name']} - {profile['description']}")
    
    print("\nScan Profiles:")
    for profile_name, profile in SCAN_PROFILES.items():
        print(f"  {profile_name}: {profile['description']}")
    
    print("\nConfiguration export test:")
    config_dict = export_config_to_dict()
    print(f"  Exported {len(config_dict)} configuration sections")
    
    print("\nConfiguration validation completed successfully!")
