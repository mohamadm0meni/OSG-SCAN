# DatabaseProtocolTester.py
import socket
import struct
import random
import logging
from typing import Dict, Optional, List, Any
from Config import Config
from dataclasses import dataclass
import threading
import hashlib

@dataclass
class DatabaseResponse:
    """Structure for database response information"""
    success: bool
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[bytes] = None
    details: Dict[str, Any] = None
    error: Optional[str] = None

class DatabaseProtocolTester:
    """Enhanced database protocol testing"""

    def __init__(self):
        self.config = Config()
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        self.lock = threading.Lock()

        # Database signatures and probes
        self.db_signatures = {
            'MySQL': {
                'ports': [3306],
                'patterns': [
                    b'\x4a\x00\x00\x00',  # Protocol v10
                    b'mysql_native_password',
                    b'MariaDB'
                ]
            },
            'PostgreSQL': {
                'ports': [5432],
                'patterns': [
                    b'PostgreSQL',
                    b'PGSQL',
                ],
                'error_patterns': [
                    b'FATAL',
                    b'password authentication failed'
                ]
            },
            'MongoDB': {
                'ports': [27017],
                'patterns': [
                    b'MongoDB',
                    b'ismaster',
                    b'maxBsonObjectSize'
                ]
            },
            'Redis': {
                'ports': [6379],
                'patterns': [
                    b'-NOAUTH',
                    b'+PONG',
                    b'redis_version'
                ]
            },
            'CouchDB': {
                'ports': [5984],
                'patterns': [
                    b'couchdb',
                    b'Welcome',
                    b'Apache'
                ]
            },
            'Cassandra': {
                'ports': [9042],
                'patterns': [
                    b'CQL_VERSION',
                    b'COMPRESSION'
                ]
            }
        }

    def test_mysql(self, sock: socket.socket) -> DatabaseResponse:
        """Test MySQL service with enhanced detection"""
        try:
            # Receive initial handshake
            initial_packet = sock.recv(1024)
            if not initial_packet or len(initial_packet) < 5:
                return DatabaseResponse(success=False, error="Invalid response")

            # Parse packet
            pkt_len = struct.unpack('<I', initial_packet[:3] + b'\x00')[0]
            protocol_ver = initial_packet[4]

            if protocol_ver == 10:  # MySQL Protocol 10
                handshake = self._parse_mysql_handshake(initial_packet[4:])
                
                return DatabaseResponse(
                    success=True,
                    service='MySQL',
                    version=handshake.get('version'),
                    banner=initial_packet,
                    details={
                        'protocol_version': protocol_ver,
                        'thread_id': handshake.get('thread_id'),
                        'capabilities': handshake.get('capabilities'),
                        'server_status': handshake.get('server_status'),
                        'auth_plugin': handshake.get('auth_plugin')
                    }
                )

        except Exception as e:
            self.logger.error(f"MySQL test error: {e}")
            return DatabaseResponse(success=False, error=str(e))

        return DatabaseResponse(success=False, error="Not MySQL")

    def test_postgresql(self, sock: socket.socket) -> DatabaseResponse:
        """Test PostgreSQL service with enhanced detection"""
        try:
            # Send startup message
            startup = self._create_postgresql_startup()
            sock.send(startup)
            
            response = sock.recv(1024)
            if not response:
                return DatabaseResponse(success=False, error="No response")

            if response[0:1] in [b'R', b'E', b'S']:
                auth_type = struct.unpack('!I', response[5:9])[0] if len(response) >= 9 else None
                
                details = self._parse_postgresql_response(response)
                return DatabaseResponse(
                    success=True,
                    service='PostgreSQL',
                    version=details.get('version'),
                    banner=response,
                    details={
                        'auth_type': auth_type,
                        'auth_method': details.get('auth_method'),
                        'error_fields': details.get('error_fields')
                    }
                )

        except Exception as e:
            self.logger.error(f"PostgreSQL test error: {e}")
            return DatabaseResponse(success=False, error=str(e))

        return DatabaseResponse(success=False, error="Not PostgreSQL")

    def test_mongodb(self, sock: socket.socket) -> DatabaseResponse:
        """Test MongoDB service with enhanced detection"""
        try:
            # Create ismaster command
            ismaster_msg = self._create_mongodb_ismaster()
            sock.send(ismaster_msg)
            
            response = sock.recv(1024)
            if response and len(response) > 16:
                metadata = self._parse_mongodb_response(response)
                
                return DatabaseResponse(
                    success=True,
                    service='MongoDB',
                    version=metadata.get('version'),
                    banner=response,
                    details=metadata
                )

        except Exception as e:
            self.logger.error(f"MongoDB test error: {e}")
            return DatabaseResponse(success=False, error=str(e))

        return DatabaseResponse(success=False, error="Not MongoDB")

    def test_redis(self, sock: socket.socket) -> DatabaseResponse:
        """Test Redis service with enhanced detection"""
        try:
            # Send INFO command
            sock.send(b'INFO\r\n')
            response = sock.recv(1024)
            
            if response.startswith(b'$') or response.startswith(b'-'):
                info = self._parse_redis_info(response)
                
                return DatabaseResponse(
                    success=True,
                    service='Redis',
                    version=info.get('redis_version'),
                    banner=response,
                    details=info
                )

        except Exception as e:
            self.logger.error(f"Redis test error: {e}")
            return DatabaseResponse(success=False, error=str(e))

        return DatabaseResponse(success=False, error="Not Redis")

    def _parse_mysql_handshake(self, data: bytes) -> Dict:
        """Parse MySQL handshake packet"""
        try:
            offset = 0
            
            # Skip protocol version
            offset += 1
            
            # Extract version string
            version_end = data.find(b'\x00', offset)
            version = data[offset:version_end].decode('utf-8', errors='ignore')
            offset = version_end + 1
            
            # Thread ID
            thread_id = struct.unpack('<I', data[offset:offset+4])[0]
            offset += 4
            
            # Auth plugin data
            auth_data = data[offset:offset+8]
            offset += 8
            
            # Skip filler
            offset += 1
            
            # Capability flags
            capabilities = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            
            # Server status
            server_status = struct.unpack('<H', data[offset:offset+2])[0] if len(data) > offset + 2 else None
            
            return {
                'version': version,
                'thread_id': thread_id,
                'auth_data': auth_data.hex(),
                'capabilities': capabilities,
                'server_status': server_status
            }

        except Exception as e:
            self.logger.error(f"Error parsing MySQL handshake: {e}")
            return {}

    def _create_postgresql_startup(self) -> bytes:
        """Create PostgreSQL startup message"""
        version = 196608  # PostgreSQL 3.0
        user = b'postgres\x00'
        database = b'postgres\x00'
        
        # Build packet
        length = 8 + len(user) + len(database)
        packet = struct.pack('!I', length)  # Packet length
        packet += struct.pack('!I', version)  # Protocol version
        packet += user
        packet += database
        packet += b'\x00'  # Terminator
        
        return packet

    def _parse_postgresql_response(self, response: bytes) -> Dict:
        """Parse PostgreSQL response"""
        try:
            msg_type = response[0:1].decode('ascii')
            info = {'message_type': msg_type}
            
            if msg_type == 'E':  # Error
                error_fields = {}
                pos = 5
                
                while pos < len(response):
                    field_type = response[pos:pos+1]
                    if field_type == b'\x00':
                        break
                        
                    pos += 1
                    field_value = b''
                    
                    while response[pos:pos+1] != b'\x00':
                        field_value += response[pos:pos+1]
                        pos += 1
                    
                    pos += 1
                    error_fields[field_type.decode('ascii')] = field_value.decode('utf-8')
                    
                info['error_fields'] = error_fields
                
            return info
            
        except Exception as e:
            self.logger.error(f"Error parsing PostgreSQL response: {e}")
            return {}

    def _create_mongodb_ismaster(self) -> bytes:
        """Create MongoDB ismaster command"""
        request_id = random.randint(0, 999999)
        
        # Build message
        message = bytearray([
            # messageLength (placeholder)
            0, 0, 0, 0,
            # requestID
            *(request_id.to_bytes(4, 'little')),
            # responseTo
            0, 0, 0, 0,
            # opCode (OP_QUERY)
            *(2004).to_bytes(4, 'little'),
            # flags
            0, 0, 0, 0,
            # fullCollectionName
            b'admin.$cmd\x00',
            # numberToSkip
            0, 0, 0, 0,
            # numberToReturn
            1, 0, 0, 0,
            # ismaster command
            b'\x0F\x00\x00\x00\x01ismaster\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00'
        ])
        
        # Update message length
        message[0:4] = len(message).to_bytes(4, 'little')
        
        return bytes(message)

    def _parse_mongodb_response(self, response: bytes) -> Dict:
        """Parse MongoDB response"""
        try:
            if len(response) < 16:
                return {}
                
            # Parse header
            header = {
                'messageLength': struct.unpack('<I', response[0:4])[0],
                'requestID': struct.unpack('<I', response[4:8])[0],
                'responseTo': struct.unpack('<I', response[8:12])[0],
                'opCode': struct.unpack('<I', response[12:16])[0]
            }
            
            # Try to extract version info
            try:
                body = response[20:]
                if b'version' in body:
                    version_start = body.find(b'version\x00') + 8
                    version_end = body.find(b'\x00', version_start)
                    if version_end > version_start:
                        header['version'] = body[version_start:version_end].decode()
            except:
                pass
                
            return header
            
        except Exception as e:
            self.logger.error(f"Error parsing MongoDB response: {e}")
            return {}

    def _parse_redis_info(self, response: bytes) -> Dict:
        """Parse Redis INFO response"""
        try:
            info = {}
            
            if response.startswith(b'$'):
                # Split off the RESP header
                content = response.split(b'\r\n', 2)[1]
                
                for line in content.split(b'\r\n'):
                    if b':' in line:
                        key, value = line.split(b':', 1)
                        info[key.decode('utf-8')] = value.decode('utf-8')
                        
            return info
            
        except Exception as e:
            self.logger.error(f"Error parsing Redis info: {e}")
            return {}