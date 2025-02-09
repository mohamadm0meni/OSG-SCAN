<p align="center">
  <strong><span style="font-size: 1000px;">OSG-SCAN</span></strong>
</p>

<p align="center">
وقتی OSG Scan هست، دیگه به Nmap فکر نکن.
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/45c09394-525c-4ba3-83b8-1a7d10a10d04" alt="OSG SCAN"/>
</p>

## نصب و بروزرسانی

```bash
bash <(curl -Ls https://raw.githubusercontent.com/mohamadm0meni/OSG-SCAN/main/install.sh)
```

### **پارامترهای اختیاری:**
| گزینه | توضیحات |
|--------|-------------|
| `-h, --help` | نمایش پیغام راهنما |
| `-p PORTS, --ports PORTS` | تعیین محدوده پورت (مثال: `1-1000`) |
| `-t THREADS, --threads THREADS` | تعداد thread های اسکن |
| `--timing {0,1,2,3,4,5}` | پروفایل زمان‌بندی (0=پارانوید، 5=فوق سریع) |
| `--profile {stealth,normal,aggressive}` | انتخاب پروفایل اسکن |
| `-o {text,json,xml,html}, --output {text,json,xml,html}` | فرمت خروجی |
| `--config CONFIG` | مسیر فایل پیکربندی |
| `--debug` | فعال‌سازی حالت اشکال‌زدایی |
| `--no-banner` | غیرفعال‌سازی دریافت banner |
| `--service-detection` | فعال‌سازی تشخیص سرویس |
| `--vuln-check` | فعال‌سازی ارزیابی آسیب‌پذیری |
| `--interface INTERFACE` | تعیین رابط شبکه برای اسکن |
| `--exclude-ports EXCLUDE_PORTS` | مستثنی کردن پورت‌های خاص (مثال: `80,443,3306`) |
| `--source-port SOURCE_PORT` | تعیین پورت مبدا |

## 📌 مثال‌ها

```yaml
# اسکن پایه
osgscan example.com

# اسکن پورت‌های 1 تا 1000
osgscan example.com -p 1-1000

# اسکن با پروفایل زمان‌بندی 3 و 20 thread
osgscan example.com -p 1-1000 --timing 3 --threads 20

# اسکن مخفیانه با خروجی JSON
osgscan example.com --profile stealth --output json
```

## 🚀 ویژگی‌ها

> **اسکنر پورت پیشرفته و مخفیانه**  

✅ **اسکن پورت سریع و پیشرفته**  
✅ **تشخیص سرویس** برای سرویس‌های فعال روی هدف  
✅ **ارزیابی آسیب‌پذیری** بر اساس پایگاه داده به‌روز  
✅ **دور زدن IDS و IPS** برای اسکن‌های مخفیانه  
✅ **سازگار با سیستم‌های مختلف**، تست شده روی **MikroTik** و **Snort**  
✅ **خروجی در فرمت‌های JSON، متن و پایگاه داده** با جزئیات کامل شامل:  
&nbsp;&nbsp;&nbsp;&nbsp;📌 **جزئیات زمان و میزبان**  
&nbsp;&nbsp;&nbsp;&nbsp;📌 **پورت‌های باز، بسته و فیلتر شده**  
&nbsp;&nbsp;&nbsp;&nbsp;📌 **شناسایی سرویس و تشخیص banner**  

---

# نمودار کلاس‌ها

```mermaid
classDiagram
    %% لایه هسته
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

    %% لایه سوکت
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

    %% لایه سرویس
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

    %% لایه پروتکل
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

    %% لایه مدیریت
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

    %% لایه پورت و امنیت
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

    %% ارتباطات هسته
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

    %% وابستگی‌های عملکردی
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
