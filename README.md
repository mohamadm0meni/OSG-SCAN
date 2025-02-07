
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



