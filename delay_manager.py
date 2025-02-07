# delay_manager.py
import time
import random
import logging
from typing import Dict, Optional, List
from dataclasses import dataclass
import threading
from collections import deque
import statistics

@dataclass
class NetworkStats:
    """Network statistics tracking"""
    failed_attempts: int = 0
    timeouts: int = 0
    successful_attempts: int = 0
    total_latency: float = 0.0
    samples: List[float] = None
    last_update: float = 0.0

    def __post_init__(self):
        self.samples = []
        self.last_update = time.time()

class DelayManager:
    """Enhanced delay management for stealthy scanning"""

    def __init__(self):
        # Base timing settings
        self.min_delay = 0.1
        self.max_delay = 0.3
        self.batch_delay = 0.5
        self.port_scan_delay = 0.2
        
        # Adaptive settings
        self.adaptive_delay = 0.1
        self.burst_threshold = 10
        self.burst_count = 0
        self.max_burst_delay = 2.0
        
        # Network conditions
        self.network_stats = NetworkStats()
        self.latency_history = deque(maxlen=100)
        self.failed_attempt_threshold = 5
        
        self.scan_profiles = {
            'paranoid': {
                'min_delay': 0.5,    # setting porofile paranoid
                'max_delay': 1.0,
                'batch_delay': 1.5,
                'burst_threshold': 3
            },
            'sneaky': {
                'min_delay': 0.4,
                'max_delay': 0.7,
                'batch_delay': 1.0,
                'burst_threshold': 5
            },
            'polite': {
                'min_delay': 0.3,
                'max_delay': 0.6,
                'batch_delay': 0.8,
                'burst_threshold': 7
            },
            'normal': {
                'min_delay': 0.1,
                'max_delay': 0.3,
                'batch_delay': 0.5,
                'burst_threshold': 10
            },
            'aggressive': {
                'min_delay': 0.05,
                'max_delay': 0.15,
                'batch_delay': 0.2,
                'burst_threshold': 20
            },
            'insane': {
                'min_delay': 0.02,
                'max_delay': 0.1,
                'batch_delay': 0.1,
                'burst_threshold': 30
            }
        }

        
        # Initialize logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
        # Thread safety
        self.lock = threading.Lock()
        self.last_scan_time = 0
        
        # Port specific delays
        self.port_specific_delays = {
            22: 0.5,    # SSH
            25: 0.5,    # SMTP
            80: 0.3,    # HTTP
            443: 0.3,   # HTTPS
            3306: 0.4,  # MySQL
            5432: 0.4   # PostgreSQL
        }

    def get_scan_delay(self, port: Optional[int] = None) -> float:
        """Calculate appropriate delay for next scan"""
        with self.lock:
            current_time = time.time()
            time_diff = current_time - self.last_scan_time
            
            # Update burst tracking
            if time_diff < 0.1:
                self.burst_count += 1
            else:
                self.burst_count = max(0, self.burst_count - 1)
                
            # Calculate base delay
            base_delay = self._calculate_base_delay()
            
            # Add port-specific delay if applicable
            if port and port in self.port_specific_delays:
                base_delay += self.port_specific_delays[port]
                
            # Add adaptive component
            adaptive_component = self._calculate_adaptive_delay()
            
            # Add randomization
            jitter = random.uniform(-0.1 * base_delay, 0.1 * base_delay)
            
            final_delay = base_delay + adaptive_component + jitter
            
            # Update last scan time
            self.last_scan_time = current_time
            
            return max(self.min_delay, min(final_delay, self.max_delay))

    def wait_before_scan(self, port: Optional[int] = None) -> None:
        """Apply delay before scanning"""
        delay = self.get_scan_delay(port)
        time.sleep(delay)

    def wait_between_batches(self) -> None:
        """Apply delay between port batches"""
        # Calculate dynamic batch delay
        current_stats = self._get_network_stats()
        
        if current_stats['failure_rate'] > 0.2:  # High failure rate
            delay = self.batch_delay * 1.5
        elif current_stats['timeout_rate'] > 0.1:  # High timeout rate
            delay = self.batch_delay * 1.2
        else:
            delay = self.batch_delay
            
        # Add randomization
        delay *= random.uniform(0.8, 1.2)
        
        time.sleep(delay)

    def record_attempt(self, success: bool, latency: Optional[float] = None,
                      timeout: bool = False) -> None:
        """Record attempt results for adaptive delay calculation"""
        with self.lock:
            if success:
                self.network_stats.successful_attempts += 1
                if latency is not None:
                    self.network_stats.total_latency += latency
                    self.latency_history.append(latency)
                    self.network_stats.samples.append(latency)
            else:
                self.network_stats.failed_attempts += 1
                if timeout:
                    self.network_stats.timeouts += 1
                    
            self._update_adaptive_delay()

    def set_scan_profile(self, profile: str) -> None:
        """Set scan timing profile"""
        if profile in self.scan_profiles:
            with self.lock:
                settings = self.scan_profiles[profile]
                self.min_delay = settings['min_delay']
                self.max_delay = settings['max_delay']
                self.batch_delay = settings['batch_delay']
                self.burst_threshold = settings['burst_threshold']
                self.logger.info(f"Switched to {profile} scan profile")

    def _calculate_base_delay(self) -> float:
        """Calculate base delay based on current conditions"""
        base_delay = self.min_delay
        
        # Increase delay if in burst
        if self.burst_count > self.burst_threshold:
            burst_factor = min(self.burst_count / self.burst_threshold, 3)
            base_delay *= burst_factor
            
        return base_delay

    def _calculate_adaptive_delay(self) -> float:
        """Calculate adaptive delay component"""
        stats = self._get_network_stats()
        adaptive_delay = 0.0
        
        # Adjust for high failure rate
        if stats['failure_rate'] > 0.2:
            adaptive_delay += 0.1
            
        # Adjust for high timeout rate
        if stats['timeout_rate'] > 0.1:
            adaptive_delay += 0.2
            
        # Adjust for latency trend
        if stats['latency_trend'] > 1.2:  # Latency increasing
            adaptive_delay += 0.1
            
        return adaptive_delay

    def _get_network_stats(self) -> Dict:
        """Calculate current network statistics"""
        with self.lock:
            total_attempts = (self.network_stats.successful_attempts + 
                            self.network_stats.failed_attempts)
            
            if total_attempts == 0:
                return {
                    'failure_rate': 0,
                    'timeout_rate': 0,
                    'avg_latency': 0,
                    'latency_trend': 1.0
                }
                
            stats = {
                'failure_rate': self.network_stats.failed_attempts / total_attempts,
                'timeout_rate': self.network_stats.timeouts / total_attempts,
                'avg_latency': (self.network_stats.total_latency / 
                              self.network_stats.successful_attempts 
                              if self.network_stats.successful_attempts > 0 else 0)
            }
            
            # Calculate latency trend
            if len(self.latency_history) >= 10:
                recent = list(self.latency_history)[-5:]
                older = list(self.latency_history)[-10:-5]
                if older and statistics.mean(older) > 0:
                    stats['latency_trend'] = (statistics.mean(recent) / 
                                            statistics.mean(older))
                else:
                    stats['latency_trend'] = 1.0
            else:
                stats['latency_trend'] = 1.0
                
            return stats

    def _update_adaptive_delay(self) -> None:
        """Update adaptive delay based on network conditions"""
        stats = self._get_network_stats()
        
        # Increase delay if seeing problems
        if (stats['failure_rate'] > 0.2 or
            stats['timeout_rate'] > 0.1 or
            stats['latency_trend'] > 1.2):
            self.adaptive_delay = min(
                self.adaptive_delay * 1.2,
                self.max_burst_delay
            )
        # Decrease delay if conditions are good
        elif (stats['failure_rate'] < 0.1 and
              stats['timeout_rate'] < 0.05 and
              stats['latency_trend'] < 1.1):
            self.adaptive_delay = max(
                self.adaptive_delay * 0.9,
                self.min_delay
            )

    def reset_stats(self) -> None:
        """Reset all statistics and counters"""
        with self.lock:
            self.network_stats = NetworkStats()
            self.latency_history.clear()
            self.burst_count = 0
            self.adaptive_delay = 0.1
            self.last_scan_time = 0