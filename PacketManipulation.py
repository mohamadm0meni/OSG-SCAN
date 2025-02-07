import socket
import struct
import random
import time
from typing import Dict, List, Optional, Tuple
import array

class PacketManipulation:
    """Advanced packet manipulation with sophisticated evasion techniques"""

    def __init__(self):
        # Initialize TCP flags
        self.tcp_flags = {
            'FIN': 0x01,
            'SYN': 0x02,
            'RST': 0x04,
            'PSH': 0x08,
            'ACK': 0x10,
            'URG': 0x20,
            'ECE': 0x40,
            'CWR': 0x80
        }

        # Source ports management 
        self.source_ports = self._initialize_source_ports()
        self.port_index = 0

        # TCP options
        self.tcp_options = {
            'MSS': 2,
            'Window_Scale': 3,
            'SACK_Permitted': 4,
            'SACK': 5,
            'Timestamp': 8
        }
        
        # IP header fields
        self.ip_headers = {
            'Version': 4,
            'IHL': 5,
            'TOS': 0,
            'Total_Length': 20,
            'ID': 0,
            'Flags': 0,
            'Fragment_Offset': 0,
            'TTL': 64,
            'Protocol': socket.IPPROTO_TCP,
            'Checksum': 0
        }

    def _initialize_source_ports(self) -> List[int]:
        """Initialize source ports with advanced randomization"""
        base_ports = list(range(32768, 61000))
        
        # Exclude commonly filtered ports
        excluded_ports = set([53, 80, 443, 3389])
        ports = [p for p in base_ports if p not in excluded_ports]
        
        # Apply full randomization
        random.shuffle(ports)
        return ports

    def get_next_source_port(self) -> int:
        """Get next source port with intelligent selection"""
        port = self.source_ports[self.port_index]
        self.port_index = (self.port_index + 1) % len(self.source_ports)
        return port

    def create_ip_header(self, src_ip: str, dst_ip: str, 
                        ttl: Optional[int] = None) -> bytes:
        """Create IP header with customization options"""
        if ttl is None:
            # Use random but realistic TTL
            ttl = random.choice([64, 128, 255])

        # Generate random but believable IP ID
        ip_id = random.randint(1000, 65000)

        # Create header
        ip_header = struct.pack('!BBHHHBBH4s4s',
            (self.ip_headers['Version'] << 4) + self.ip_headers['IHL'],
            self.ip_headers['TOS'],
            self.ip_headers['Total_Length'],
            ip_id,
            self.ip_headers['Flags'] << 13 | self.ip_headers['Fragment_Offset'],
            ttl,
            self.ip_headers['Protocol'],
            0,  # Checksum (filled later)
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip)
        )

        # Calculate checksum
        checksum = self._calculate_checksum(ip_header)
        
        # Rebuild header with checksum
        ip_header = ip_header[:10] + struct.pack('H', checksum) + ip_header[12:]
        return ip_header

    def create_tcp_header(self, src_port: int, dst_port: int, 
                         flags: str = 'SYN', 
                         seq: Optional[int] = None,
                         ack: Optional[int] = None,
                         window: Optional[int] = None) -> bytes:
        """Create TCP header with advanced options"""
        if seq is None:
            seq = random.randint(1000000000, 4000000000)
        if ack is None:
            ack = 0
        if window is None:
            window = random.randint(8192, 65535)

        # Calculate flags
        flag_bits = self._calculate_tcp_flags(flags)

        # Generate random options
        options = self._generate_tcp_options()
        
        # Calculate data offset
        data_offset = 5 + len(options) // 4  # 5 words + options

        # Create basic header
        tcp_header = struct.pack('!HHLLBBHHH',
            src_port,
            dst_port,
            seq,
            ack,
            (data_offset << 4),
            flag_bits,
            window,
            0,  # Checksum (filled later)
            0   # Urgent pointer
        )

        # Add options
        tcp_header += options
        
        # Pad to 4-byte boundary
        while len(tcp_header) % 4:
            tcp_header += b'\x00'

        return tcp_header

    def _calculate_tcp_flags(self, flags: str) -> int:
        """Calculate TCP flags value from string representation"""
        flag_value = 0
        for flag in flags:
            if flag == 'F':
                flag_value |= self.tcp_flags['FIN']
            elif flag == 'S':
                flag_value |= self.tcp_flags['SYN']
            elif flag == 'R':
                flag_value |= self.tcp_flags['RST']
            elif flag == 'P':
                flag_value |= self.tcp_flags['PSH']
            elif flag == 'A':
                flag_value |= self.tcp_flags['ACK']
            elif flag == 'U':
                flag_value |= self.tcp_flags['URG']
        return flag_value

    def _generate_tcp_options(self) -> bytes:
        """Generate realistic TCP options"""
        options = bytearray()

        # MSS Option
        mss = random.choice([1360, 1400, 1440, 1460])
        options.extend([
            self.tcp_options['MSS'],  # Kind = MSS
            4,                        # Length
            mss >> 8,                # MSS value high byte
            mss & 0xFF               # MSS value low byte
        ])

        # Window Scale
        if random.random() < 0.8:  # 80% chance
            options.extend([
                self.tcp_options['Window_Scale'],  # Kind = Window Scale
                3,                                 # Length
                random.randint(0, 14)             # Shift count
            ])

        # SACK Permitted
        if random.random() < 0.7:  # 70% chance
            options.extend([
                self.tcp_options['SACK_Permitted'],  # Kind = SACK Permitted
                2                                    # Length
            ])

        # Timestamps
        if random.random() < 0.9:  # 90% chance
            ts_val = random.randint(20000, 100000)
            ts_ecr = random.randint(0, 10000)
            options.extend([
                self.tcp_options['Timestamp'],  # Kind = Timestamp
                10,                            # Length
            ] + list(struct.pack('!II', ts_val, ts_ecr)))

        return bytes(options)

    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate checksum for headers"""
        if len(data) % 2 == 1:
            data += b'\0'
        
        words = array.array('H', data)
        csum = sum(words)
        
        csum = (csum >> 16) + (csum & 0xffff)
        csum += (csum >> 16)
        
        return (~csum) & 0xffff

    def create_packet(self, src_ip: str, dst_ip: str, 
                     src_port: int, dst_port: int,
                     flags: str = 'SYN') -> bytes:
        """Create complete TCP/IP packet"""
        # Create headers
        ip_header = self.create_ip_header(src_ip, dst_ip)
        tcp_header = self.create_tcp_header(src_port, dst_port, flags)
        
        # Combine packet
        packet = ip_header + tcp_header
        
        return packet

    def fragment_packet(self, packet: bytes, 
                       fragment_size: int = 8) -> List[bytes]:
        """Fragment packet for evasion"""
        fragments = []
        offset = 0
        
        while offset < len(packet):
            # Calculate fragment size
            current_size = min(fragment_size, len(packet) - offset)
            
            # Create fragment
            fragment = packet[offset:offset + current_size]
            
            # Add fragment header
            frag_header = self._create_fragment_header(offset // 8)
            fragments.append(frag_header + fragment)
            
            offset += current_size
            
        return fragments

    def _create_fragment_header(self, offset: int) -> bytes:
        """Create header for IP fragment"""
        # Set appropriate flags for fragmentation
        flags = 1 if offset > 0 else 0  # More fragments flag
        
        header = struct.pack('!H', (flags << 13) | offset)
        return header

    def create_decoy_packet(self) -> bytes:
        """Create decoy packet for IDS evasion"""
        # Generate random source/dest
        src_ip = self._generate_random_ip()
        dst_ip = self._generate_random_ip()
        
        # Random ports
        src_port = random.randint(1024, 65535)
        dst_port = random.randint(1, 65535)
        
        # Random TCP flags
        flags = random.choice(['SYN', 'ACK', 'RST'])
        
        return self.create_packet(src_ip, dst_ip, src_port, dst_port, flags)

    def _generate_random_ip(self) -> str:
        """Generate random but valid IP address"""
        # Avoid reserved ranges
        while True:
            ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
            # Check if IP is in private ranges
            if not (ip.startswith('10.') or 
                   ip.startswith('172.16.') or
                   ip.startswith('192.168.')):
                return ip