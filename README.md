
<p align="center">
  <strong><span style="font-size: 1000px;">OSG-SCAN</span></strong>
</p>

<p align="center">
Don't think about Nmap when OSG Scan is here.
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/45c09394-525c-4ba3-83b8-1a7d10a10d04" alt="OSG SCAN"/>
</p>

## Install & Upgrade

```
bash <(curl -Ls https://raw.githubusercontent.com/mohamadm0meni/OSG-SCAN/main/install.sh)
```

### **Optional Arguments:**
| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message and exit |
| `-p PORTS, --ports PORTS` | Define port range (e.g., `1-1000`) |
| `-t THREADS, --threads THREADS` | Number of threads for scanning |
| `--timing {0,1,2,3,4,5}` | Timing profile (0=paranoid, 5=insane) |
| `--profile {stealth,normal,aggressive}` | Choose scan profile |
| `-o {text,json,xml,html}, --output {text,json,xml,html}` | Output format |
| `--config CONFIG` | Specify configuration file path |
| `--debug` | Enable debug mode |
| `--no-banner` | Disable banner grabbing |
| `--service-detection` | Enable service detection |
| `--vuln-check` | Enable vulnerability assessment |
| `--interface INTERFACE` | Define network interface for scanning |
| `--exclude-ports EXCLUDE_PORTS` | Exclude specific ports (e.g., `80,443,3306`) |
| `--source-port SOURCE_PORT` | Specify source port |


## 📌 Examples

```yaml
# Basic scan
osgscan example.com

# Scan ports 1-1000
osgscan example.com -p 1-1000

# Scan with timing profile 3 and 20 threads
osgscan example.com -p 1-1000 --timing 3 --threads 20

# Stealth scan with JSON output
osgscan example.com --profile stealth --output json
```

## 🚀 Features

> **Advanced and Stealthy Port Scanner**  

✅ **Fast and advanced port scanning**  
✅ **Service detection** for active services on the target  
✅ **Vulnerability assessment** based on up-to-date databases  
✅ **Bypasses IDS and IPS** for stealthy scans  
✅ **Compatible with various systems**, tested on **MikroTik** and **Snort**  
✅ **Output in JSON, text, and DB format** with full details including:  
&nbsp;&nbsp;&nbsp;&nbsp;📌 **Time and host details**  
&nbsp;&nbsp;&nbsp;&nbsp;📌 **Open, closed, and filtered ports**  
&nbsp;&nbsp;&nbsp;&nbsp;📌 **Service identification and banner detection**  


---


![carbon](https://github.com/user-attachments/assets/9ca715d0-47bb-425f-ad56-16b8495a8fcd)

---

# Class Diagram

```mermaid
classDiagram
    %% Core Scanner and Config
    class EnhancedScanner {
        -target: str
        -config: Config
        -socket_manager: SocketManager
        -advanced_socket_manager: AdvancedSocketManager
        -service_detector: ServiceDetector
        -banner_analyzer: BannerAnalyzer
        -delay_manager: DelayManager
        -port_batch_manager: PortBatchManager
        -result_manager: ResultManager
        -traffic_manager: TrafficManager
        -web_tester: WebProtocolTester
        -db_tester: DatabaseProtocolTester
        -mail_tester: MailProtocolTester
        -security_tester: WebSecurityTester
        +scan(start_port: int, end_port: int): dict
    }

    class Config {
        +EXCLUDED_PORTS: Set
        +MAX_THREADS: int
        +TIMEOUT: float
        +SOURCE_PORT_RANGE: Tuple
        +load_config(config_file: str)
        +validate(): bool
    }

    %% Socket Management Group
    class SocketManager {
        -active_sockets: Dict
        -socket_pool: List
        +create_socket(ssl_wrap: bool): socket
        +connect(host: str, port: int): Tuple
    }

    class AdvancedSocketManager {
        -config: Config
        -source_ports: List
        +create_tcp_socket(): socket
        +test_port(target: str, port: int): Dict
    }

    %% Service Detection Group
    class ServiceDetector {
        -target: str
        -ssl_context: SSLContext
        +detect_service(port: int): Dict
        -_probe_service(sock: socket): Dict
    }

    class BannerAnalyzer {
        -version_patterns: Dict
        -security_patterns: Dict
        +analyze_banner(banner: bytes): Dict
        +scan_vulnerabilities(banner: bytes): List
    }

    %% Protocol Testing Group
    class WebProtocolTester {
        -timeout: float
        -ssl_context: SSLContext
        +test_web_port(target: str, port: int): Dict
        +scan_ports(target: str): List
    }

    class DatabaseProtocolTester {
        -config: Config
        +test_mysql(sock: socket): Dict
        +test_postgresql(sock: socket): Dict
    }

    class MailProtocolTester {
        -service_patterns: Dict
        +test_smtp(sock: socket): Dict
        +test_pop3(sock: socket): Dict
    }

    %% Management Group
    class DelayManager {
        -min_delay: float
        -max_delay: float
        +get_scan_delay(port: int): float
        +wait_before_scan(port: int)
    }

    class PortBatchManager {
        -service_ports: Dict
        -common_ports: Set
        +create_batches(start_port: int): List
        +update_stats(port: int): void
    }

    class ResultManager {
        -target: str
        -results_dir: str
        +save_results(scan_results: Dict)
        -_generate_report(results: Dict)
    }

    class TrafficManager {
        -max_rate: int
        -stats: TrafficStats
        +analyze_traffic_patterns(): Dict
        -_identify_patterns(): Dict
    }

    %% Port and Packet Handling Group
    class PortHandlers {
        -target: str
        -packet_manager: PacketManipulation
        +handle_port(port: int): Dict
        +handle_http(sock: socket): Dict
    }

    class PacketManipulation {
        -tcp_flags: Dict
        -source_ports: List
        +create_packet(src_ip: str): bytes
        +fragment_packet(packet: bytes): List
    }

    %% Security Testing Group
    class WebSecurityTester {
        -protocol_tester: WebProtocolTester
        +scan(target: str): Dict
        -_test_vulnerabilities(): List
    }

    %% Core Relationships
    EnhancedScanner *-- Config
    EnhancedScanner *-- SocketManager
    EnhancedScanner *-- AdvancedSocketManager
    EnhancedScanner *-- ServiceDetector
    EnhancedScanner *-- BannerAnalyzer
    EnhancedScanner *-- DelayManager
    EnhancedScanner *-- PortBatchManager
    EnhancedScanner *-- ResultManager
    EnhancedScanner *-- TrafficManager
    EnhancedScanner *-- WebProtocolTester
    EnhancedScanner *-- DatabaseProtocolTester
    EnhancedScanner *-- MailProtocolTester
    EnhancedScanner *-- WebSecurityTester

    %% Dependency Relationships
    AdvancedSocketManager --> SocketManager
    AdvancedSocketManager --> Config
    ServiceDetector --> Config
    ServiceDetector --> SocketManager
    BannerAnalyzer --> Config
    WebProtocolTester --> SocketManager
    DatabaseProtocolTester --> SocketManager
    MailProtocolTester --> SocketManager
    DelayManager --> Config
    PortBatchManager --> Config
    PortHandlers --> PacketManipulation
    WebSecurityTester --> WebProtocolTester
    ```

