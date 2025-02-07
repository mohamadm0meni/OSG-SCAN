import json
import sqlite3
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
import threading
import logging
import os

class ResultManager:
    """Manages scan results with storage capability"""

    def __init__(self, target: str):
        self.target = target
        self.start_time = datetime.now()
        self.results_dir = "scan_results"
        
        # Create a directory to store results
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)

        # Set up logger
        self.logger = logging.getLogger(__name__)
        
        # Initialize results
        self.scan_results = {
            'target': target,
            'start_time': self.start_time.isoformat(),
            'end_time': None,
            'duration': None,
            'open_ports': [],
            'filtered_ports': [],
            'closed_ports': [],
            'services': {},
            'vulnerabilities': []
        }
        
        # Lock for thread safety
        self.lock = threading.Lock()

    def _sanitize_for_json(self, data: Any) -> Any:
        """Convert data to a JSON-storable format"""
        if isinstance(data, bytes):
            try:
                return data.decode('utf-8', errors='ignore')
            except:
                return data.hex()
        elif isinstance(data, dict):
            return {key: self._sanitize_for_json(value) for key, value in data.items()}
        elif isinstance(data, list):
            return [self._sanitize_for_json(item) for item in data]
        elif isinstance(data, (int, float, str, bool, type(None))):
            return data
        else:
            return str(data)

    def save_results(self, scan_results: Dict) -> None:
        """Save scan results"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Create a directory for storing indexed results
        index_dir = len(os.listdir(self.results_dir)) + 1
        index_dir_path = os.path.join(self.results_dir, str(index_dir))
        
        # If the indexed directory does not exist, create it
        if not os.path.exists(index_dir_path):
            os.makedirs(index_dir_path)

        filename = f"{index_dir_path}/scan_{self.target}_{timestamp}"

        # Sanitize data for JSON
        sanitized_results = self._sanitize_for_json(scan_results)

        # Save JSON
        try:
            with open(f"{filename}.json", 'w', encoding='utf-8') as f:
                json.dump(sanitized_results, f, indent=4, ensure_ascii=False)
            self.logger.info(f"Results saved to {filename}.json")
        except Exception as e:
            self.logger.error(f"Error saving JSON: {e}")

        # Save to database
        try:
            self._save_to_database(scan_results)
            self.logger.info("Results saved to database")
        except Exception as e:
            self.logger.error(f"Error saving to database: {e}")

        # Generate text report
        try:
            self._generate_text_report(scan_results, f"{filename}.txt")
            self.logger.info(f"Text report saved to {filename}.txt")
        except Exception as e:
            self.logger.error(f"Error generating text report: {e}")

    def _save_to_database(self, results: Dict) -> None:
        """Save results in a SQLite database"""
        db_file = f"{self.results_dir}/scan_results.db"
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Create required tables
        cursor.executescript('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT,
                duration REAL
            );

            CREATE TABLE IF NOT EXISTS ports (
                scan_id INTEGER,
                port INTEGER,
                state TEXT,
                service TEXT,
                version TEXT,
                banner TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            );

            CREATE TABLE IF NOT EXISTS vulnerabilities (
                scan_id INTEGER,
                port INTEGER,
                type TEXT,
                severity TEXT,
                description TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            );
        ''')

        try:
            # Convert results for database storage
            clean_results = self._sanitize_for_json(results)

            # Store scan info
            cursor.execute('''
                INSERT INTO scans (target, start_time, end_time, duration)
                VALUES (?, ?, ?, ?)
            ''', (
                clean_results['target'],
                clean_results['start_time'],
                clean_results['end_time'],
                clean_results.get('duration', 0)
            ))
            scan_id = cursor.lastrowid

            # Store port info
            for port_info in clean_results.get('open_ports', []):
                cursor.execute('''
                    INSERT INTO ports (scan_id, port, state, service, version, banner)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    scan_id,
                    port_info['port'],
                    port_info['state'],
                    port_info.get('service'),
                    port_info.get('version'),
                    port_info.get('banner')
                ))

            # Store vulnerabilities
            for vuln in clean_results.get('vulnerabilities', []):
                cursor.execute('''
                    INSERT INTO vulnerabilities (scan_id, port, type, severity, description)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    scan_id,
                    vuln.get('port'),
                    vuln.get('type'),
                    vuln.get('severity'),
                    vuln.get('description')
                ))

            conn.commit()

        except Exception as e:
            conn.rollback()
            raise e

        finally:
            conn.close()

    def _generate_text_report(self, results: Dict, filename: str) -> None:
        """Generate a readable text report"""
        clean_results = self._sanitize_for_json(results)
        
        # Calculate actual port counts
        open_ports = len(clean_results.get('open_ports', []))
        filtered_ports = len(clean_results.get('filtered_ports', []))
        closed_ports = len(clean_results.get('closed_ports', []))
        total_ports = open_ports + filtered_ports + closed_ports
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 50 + "\n")
            f.write(f"Scan Report for {clean_results['target']}\n")
            f.write("=" * 50 + "\n\n")

            f.write("Scan Information:\n")
            f.write("-" * 30 + "\n")
            f.write(f"Start Time: {clean_results['start_time']}\n")
            f.write(f"End Time: {clean_results['end_time']}\n")
            f.write(f"Duration: {clean_results.get('duration', 0):.2f} seconds\n\n")

            f.write("Open Ports:\n")
            f.write("-" * 30 + "\n")
            for port_info in sorted(clean_results.get('open_ports', []), key=lambda x: x['port']):
                service = port_info.get('service', 'unknown')
                version = port_info.get('version', '')
                f.write(f"Port {port_info['port']}/tcp - {service} {version}\n")
            f.write("\n")

            if clean_results.get('vulnerabilities'):
                f.write("Vulnerabilities:\n")
                f.write("-" * 30 + "\n")
                for vuln in clean_results['vulnerabilities']:
                    f.write(f"- Port {vuln.get('port', 'N/A')}: {vuln.get('description')}\n")
                    f.write(f"  Severity: {vuln.get('severity', 'Unknown')}\n")
                f.write("\n")

            f.write("Scan Statistics:\n")
            f.write("-" * 30 + "\n")
            f.write(f"Total ports scanned: {total_ports}\n")
            f.write(f"Open ports: {open_ports}\n")
            f.write(f"Filtered ports: {filtered_ports}\n")
            f.write(f"Closed ports: {closed_ports}\n")
