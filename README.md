
[English](/README.md) | [فارسی](/README.fa_IR.md)

<p align="center">
  <strong><span style="font-size: 1000px;">OSG-SCAN</span></strong>
</p>

<p align="center">
Don't think about Nmap when OSG Scan is here.
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/45c09394-525c-4ba3-83b8-1a7d10a10d04" alt="OSG SCAN"/>
</p>

## Install & Upgrade & Uninstall

```
bash <(curl -Ls https://raw.githubusercontent.com/mohamadm0meni/OSG-SCAN/main/install.sh)
```
## Launch Interactive Menu (after installation)

```
osgscan
```
## Direct Scan (without menu)

```
osgscan target.com -p 1-65535
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
    %% Core Layer
    direction TB

    class EnhancedScanner {
        -target: str
        -stop_scan: bool
        +scan()
        -_cleanup()
    }

    class Config {
        +MAX_THREADS: int
        +TIMEOUT: float
        +load_config()
        +validate()
    }

    %% Socket Layer
    class SocketManager {
        -active_sockets: Dict
        +create_socket()
        +connect()
    }

    class AdvancedSocketManager {
        -source_ports: List
        +create_tcp_socket()
        +test_port()
    }

    %% Service Layer
    class ServiceDetector {
        -target: str
        +detect_service()
        -_probe_service()
    }

    class BannerAnalyzer {
        -vuln_db: Dict
        +analyze_banner()
        +scan_vulnerabilities()
    }

    %% Protocol Layer
    class WebProtocolTester {
        -timeout: float
        +test_web_port()
        +scan_ports()
    }

    class DatabaseProtocolTester {
        -config: Config
        +test_mysql()
        +test_postgresql()
    }

    class MailProtocolTester {
        -service_patterns: Dict
        +test_smtp()
        +test_pop3()
    }

    %% Management Layer
    class DelayManager {
        -min_delay: float
        +get_scan_delay()
        +wait_before_scan()
    }

    class PortBatchManager {
        -service_ports: Dict
        +create_batches()
        +update_stats()
    }

    class ResultManager {
        -target: str
        +save_results()
        -_generate_report()
    }

    class TrafficManager {
        -max_rate: int
        +analyze_patterns()
        -_detect_anomalies()
    }

    %% Port and Security Layer
    class PortHandlers {
        -target: str
        +handle_port()
        +handle_http()
    }

    class PacketManipulation {
        -tcp_flags: Dict
        +create_packet()
        +fragment_packet()
    }

    class WebSecurityTester {
        -protocol_tester
        +scan()
        -_test_vulnerabilities()
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
    EnhancedScanner *-- PortHandlers

    %% Functional Dependencies
    SocketManager --> Config
    AdvancedSocketManager --> Config
    ServiceDetector --> SocketManager
    BannerAnalyzer --> Config

    PortHandlers --> PacketManipulation
    PortHandlers --> ServiceDetector
    PortHandlers --> BannerAnalyzer

    WebProtocolTester --> SocketManager
    DatabaseProtocolTester --> SocketManager
    MailProtocolTester --> SocketManager
    WebSecurityTester --> WebProtocolTester

    DelayManager --> Config
    PortBatchManager --> Config
    ResultManager --> Config
    TrafficManager --> DelayManager
    ```

