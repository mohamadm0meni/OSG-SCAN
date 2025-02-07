# traffic_manager.py
import time
import random
import threading
from typing import Dict, List, Optional, Tuple, Any
from collections import deque
import logging
from dataclasses import dataclass

@dataclass
class TrafficStats:
    """Class for storing traffic statistics"""
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    start_time: float = 0.0
    last_packet_time: float = 0.0
    failed_attempts: int = 0
    retransmissions: int = 0
    dropped_packets: int = 0
    avg_response_time: float = 0.0
    current_rate: float = 0.0

class TrafficManager:
    """Advanced network traffic management"""

    def __init__(self):
        # Basic settings
        self.max_rate = 1000  # Maximum packets per second
        self.burst_size = 50  # Maximum burst size
        self.window_size = 5.0  # Time window in seconds
        
        # Delay settings
        self.min_delay = 0.001  # Minimum delay between packets
        self.max_delay = 0.1    # Maximum delay between packets
        self.adaptive_delay = 0.01  # Initial adaptive delay
        self.burst_threshold = 10
        
        # Statistics and history
        self.stats = TrafficStats()
        self.packet_history = deque(maxlen=1000)
        self.pattern_history = deque(maxlen=1000)
        self.timing_history = deque(maxlen=1000)
        
        # Locks for thread safety
        self.stats_lock = threading.Lock()
        self.history_lock = threading.Lock()
        self.rate_lock = threading.Lock()
        
        # Logger setup
        self.logger = logging.getLogger(__name__)
        
        # Initial value
        self.stats.start_time = time.time()

    def analyze_traffic_patterns(self) -> Dict:
        """Analyze traffic patterns"""
        with self.stats_lock:
            analysis = {
                'patterns': {},
                'stats': {},
                'anomalies': [],
                'recommendations': []
            }

            if not self.timing_history:
                return analysis

            # Calculate basic statistics
            timings = list(self.timing_history)
            mean_time = sum(timings) / len(timings)
            variance = sum((t - mean_time) ** 2 for t in timings) / len(timings)
            std_dev = variance ** 0.5

            analysis['stats'].update({
                'mean_time': mean_time,
                'std_dev': std_dev,
                'min_time': min(timings),
                'max_time': max(timings),
                'total_packets': self.stats.packets_sent + self.stats.packets_received,
                'packet_rate': self._calculate_packet_rate()
            })

            # Identify patterns
            patterns = self._identify_patterns(timings)
            analysis['patterns'].update(patterns)

            # Detect anomalies
            anomalies = self._detect_anomalies(timings, mean_time, std_dev)
            if anomalies:
                analysis['anomalies'].extend(anomalies)

            # Generate recommendations
            analysis['recommendations'] = self._generate_recommendations(analysis)

            return analysis

    def _calculate_packet_rate(self) -> float:
        """Calculate the current packet rate"""
        with self.stats_lock:
            if not self.stats.start_time:
                return 0.0
            duration = time.time() - self.stats.start_time
            if duration <= 0:
                return 0.0
            return (self.stats.packets_sent + self.stats.packets_received) / duration

    def _identify_patterns(self, timings: List[float]) -> Dict:
        """Identify traffic patterns"""
        patterns = {
            'periodic': False,
            'bursty': False,
            'random': False,
            'pattern_length': None,
            'confidence': 0.0
        }

        if len(timings) < 10:
            return patterns

        # Check for periodic pattern
        autocorr = self._calculate_autocorrelation(timings)
        max_correlation = max(autocorr[1:]) if len(autocorr) > 1 else 0
        
        if max_correlation > 0.7:
            patterns['periodic'] = True
            patterns['pattern_length'] = autocorr.index(max_correlation)
            patterns['confidence'] = max_correlation

        # Check for burst
        mean_time = sum(timings) / len(timings)
        burst_count = sum(1 for t in timings if t < mean_time * 0.5)
        if burst_count > len(timings) * 0.2:
            patterns['bursty'] = True

        # Check randomness
        if self._check_randomness(timings):
            patterns['random'] = True

        return patterns

    def _detect_anomalies(self, timings: List[float], mean: float, std_dev: float) -> List[Dict]:
        """Detect traffic anomalies"""
        anomalies = []
        
        for i, timing in enumerate(timings):
            if abs(timing - mean) > 3 * std_dev:
                anomalies.append({
                    'type': 'timing_anomaly',
                    'index': i,
                    'value': timing,
                    'deviation': abs(timing - mean) / std_dev,
                    'timestamp': time.time()
                })

        # Check for abnormal bursts
        current_burst = []
        for i, timing in enumerate(timings):
            if timing < mean - std_dev:
                current_burst.append(i)
            else:
                if len(current_burst) > self.burst_threshold:
                    anomalies.append({
                        'type': 'burst_anomaly',
                        'start_index': current_burst[0],
                        'end_index': current_burst[-1],
                        'size': len(current_burst),
                        'timestamp': time.time()
                    })
                current_burst = []

        return anomalies

    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate recommendations for improving traffic"""
        recommendations = []

        # Recommendations for identified patterns
        if analysis['patterns'].get('periodic'):
            recommendations.append(
                "Periodic pattern detected. It's recommended to introduce randomization in delays."
            )

        if analysis['patterns'].get('bursty'):
            recommendations.append(
                "High burst rate detected. Increasing delay between packets is recommended."
            )

        # Recommendations based on stats
        packet_rate = analysis['stats'].get('packet_rate', 0)
        if packet_rate > self.max_rate * 0.8:
            recommendations.append(
                f"Packet rate ({packet_rate:.2f}/s) is close to the maximum limit. "
                "Reducing the sending rate is recommended."
            )

        # Recommendations based on anomalies
        if len(analysis['anomalies']) > 5:
            recommendations.append(
                "Multiple anomalies detected in timing. "
                "Revisiting timing parameters is recommended."
            )

        return recommendations

    def _calculate_autocorrelation(self, data: List[float], max_lag: int = None) -> List[float]:
        """Calculate autocorrelation to detect patterns"""
        if max_lag is None:
            max_lag = len(data) // 2

        mean = sum(data) / len(data)
        var = sum((x - mean) ** 2 for x in data)
        
        autocorr = []
        for lag in range(max_lag):
            c = sum((data[i] - mean) * (data[i-lag] - mean) 
                   for i in range(lag, len(data)))
            autocorr.append(c / var)
            
        return autocorr

    def _check_randomness(self, data: List[float]) -> bool:
        """Check if data appears random"""
        median = sorted(data)[len(data)//2]
        runs = [1 if x > median else 0 for x in data]
        
        run_count = 1
        for i in range(1, len(runs)):
            if runs[i] != runs[i-1]:
                run_count += 1
                
        expected_runs = (2 * len(runs) - 1) / 3
        return abs(run_count - expected_runs) < expected_runs * 0.2

    def update_stats(self, packet_size: int, is_sent: bool, response_time: Optional[float] = None):
        """Update traffic statistics"""
        with self.stats_lock:
            current_time = time.time()
            
            if is_sent:
                self.stats.packets_sent += 1
                self.stats.bytes_sent += packet_size
            else:
                self.stats.packets_received += 1
                self.stats.bytes_received += packet_size

            # Update response time
            if response_time is not None:
                if self.stats.avg_response_time == 0:
                    self.stats.avg_response_time = response_time
                else:
                    self.stats.avg_response_time = (
                        0.9 * self.stats.avg_response_time + 0.1 * response_time
                    )

            # Calculate current rate
            duration = current_time - self.stats.start_time
            self.stats.current_rate = (
                self.stats.packets_sent + self.stats.packets_received
            ) / duration

            # Update timing history
            if self.stats.last_packet_time > 0:
                self.timing_history.append(current_time - self.stats.last_packet_time)

            self.stats.last_packet_time = current_time
