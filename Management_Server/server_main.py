from flask import Flask, request, jsonify
import json
import logging
import base64
from datetime import datetime, timedelta
from encryption_utils import ServerCrypto
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

class SecureManagementServer:
    def __init__(self, config_file="config.json"):
        with open(config_file, 'r') as f:
            self.config = json.load(f)
            
        self.crypto = ServerCrypto(
            self.config['certificate_file'],
            self.config['ca_public_key_file']
        )
        
        # Active sessions: reader_id -> {session_key, ecdh_private_key, timestamp}
        self.active_sessions = {}
        
        # Access control database (in production, use real database)
        self.access_database = self.load_access_database()
        
        # Security policies
        self.security_policies = {
            "max_session_duration": 3600,  # 1 hour
            "max_failed_attempts": 3,
            "lockout_duration": 1800,  # 30 minutes
            "require_biometric": False,
            "enable_time_restrictions": True
        }
        
        # Tracking failed attempts
        self.failed_attempts = {}
        self.locked_users = {}
        
    def load_access_database(self):
        """Load access control database"""
        try:
            with open('access_database.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Create default access database
            default_db = {
                "users": {
                    "user001": {
                        "name": "John Doe",
                        "employee_id": "EMP001",
                        "department": "IT Security",
                        "access_level": "L3",
                        "status": "active",
                        "card_keys": [],  # ECC public keys from cards
                        "access_zones": ["MAIN_ENTRANCE", "SERVER_ROOM", "OFFICE_FLOOR_1"],
                        "time_restrictions": {
                            "enabled": True,
                            "allowed_hours": "08:00-18:00",
                            "allowed_days": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
                        },
                        "biometric_required": False
                    },
                    "user002": {
                        "name": "Jane Smith", 
                        "employee_id": "EMP002",
                        "department": "Management",
                        "access_level": "L3",
                        "status": "active",
                        "card_keys": [],
                        "access_zones": ["MAIN_ENTRANCE", "OFFICE_FLOOR_1", "MANAGEMENT_FLOOR"],
                        "time_restrictions": {
                            "enabled": False
                        },
                        "biometric_required": True
                    },
                    "user003": {
                        "name": "Bob Wilson",
                        "employee_id": "EMP003",
                        "department": "Finance", 
                        "access_level": "L2",
                        "status": "active",
                        "card_keys": [],
                        "access_zones": ["MAIN_ENTRANCE", "OFFICE_FLOOR_1"],
                        "time_restrictions": {
                            "enabled": True,
                            "allowed_hours": "09:00-17:00",
                            "allowed_days": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
                        },
                        "biometric_required": False
                    },
                    "user004": {
                        "name": "Alice Brown",
                        "employee_id": "EMP004",
                        "department": "HR",
                        "access_level": "L1", 
                        "status": "suspended",
                        "card_keys": [],
                        "access_zones": ["MAIN_ENTRANCE"],
                        "time_restrictions": {
                            "enabled": True,
                            "allowed_hours": "08:00-17:00",
                            "allowed_days": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
                        },
                        "biometric_required": False
                    },
                    "attacker001": {
                        "name": "Evil Hacker",
                        "employee_id": "FAKE001",
                        "department": "Unknown",
                        "access_level": "L0",
                        "status": "revoked",
                        "card_keys": [],
                        "access_zones": [],
                        "time_restrictions": {
                            "enabled": True,
                            "allowed_hours": "00:00-00:00",
                            "allowed_days": []
                        },
                        "biometric_required": False
                    }
                },
                "zones": {
                    "MAIN_ENTRANCE": {
                        "name": "Main Entrance",
                        "required_level": "L1",
                        "description": "Building main entrance"
                    },
                    "OFFICE_FLOOR_1": {
                        "name": "Office Floor 1",
                        "required_level": "L2", 
                        "description": "General office area"
                    },
                    "SERVER_ROOM": {
                        "name": "Server Room",
                        "required_level": "L3",
                        "description": "Critical infrastructure"
                    },
                    "MANAGEMENT_FLOOR": {
                        "name": "Management Floor",
                        "required_level": "L3",
                        "description": "Executive offices"
                    }
                }
            }
            
            with open('access_database.json', 'w') as f:
                json.dump(default_db, f, indent=4)
            
            return default_db
            
    def authenticate_reader(self, reader_data):
        """Xác thực reader và thiết lập session"""
        reader_id = reader_data['reader_id']
        reader_certificate = reader_data['certificate']
        reader_ecdh_public_key_b64 = reader_data['ecdh_public_key_b64']
        signed_ecdh_key_b64 = reader_data['signed_ecdh_key_b64']
        
        logging.info(f"🔐 Reader authentication attempt: {reader_id}")
        
        # 1. Xác thực certificate của reader
        if not self.crypto.verify_certificate(reader_certificate):
            logging.error(f"❌ Reader certificate verification failed: {reader_id}")
            raise Exception("Reader certificate verification failed")
            
        # 2. Xác thực chữ ký trên ECDH public key
        reader_dilithium_pk_b64 = reader_certificate['certificate_data']['public_key']
        if not self.crypto.verify_signature(
            reader_dilithium_pk_b64,
            reader_ecdh_public_key_b64,
            signed_ecdh_key_b64
        ):
            logging.error(f"❌ Reader ECDH signature verification failed: {reader_id}")
            raise Exception("Reader ECDH key signature verification failed")
            
        # 3. Tạo session key bằng ECDH
        server_ecdh_private_key = self.crypto.create_session_keypair()
        session_key = self.crypto.perform_ecdh_with_reader(
            server_ecdh_private_key,
            reader_ecdh_public_key_b64
        )
        
        # 4. Lưu session với timestamp
        self.active_sessions[reader_id] = {
            'session_key': session_key,
            'ecdh_private_key': server_ecdh_private_key,
            'established_at': datetime.now(),
            'reader_certificate': reader_certificate
        }
        
        # 5. Trả về server certificate và ECDH public key (đã ký)
        server_ecdh_public_key_bytes = server_ecdh_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        server_ecdh_public_key_b64 = base64.b64encode(server_ecdh_public_key_bytes).decode()
        
        logging.info(f"✅ Reader authenticated successfully: {reader_id}")
        
        return {
            'status': 'success',
            'server_certificate': self.crypto.certificate,
            'server_ecdh_public_key_b64': server_ecdh_public_key_b64,
            'signed_server_ecdh_key_b64': self.crypto.sign_data(server_ecdh_public_key_b64),
            'message': 'Handshake successful'
        }
    
    def check_session_validity(self, reader_id):
        """Kiểm tra tính hợp lệ của session"""
        if reader_id not in self.active_sessions:
            return False, "No active session"
            
        session = self.active_sessions[reader_id]
        session_age = datetime.now() - session['established_at']
        
        if session_age.total_seconds() > self.security_policies['max_session_duration']:
            del self.active_sessions[reader_id]
            return False, "Session expired"
            
        return True, "Session valid"
    
    def decrypt_card_data(self, encrypted_card_data):
        """Giải mã dữ liệu thẻ từ JavaCard"""
        try:
            key = base64.b64decode(encrypted_card_data['key_b64'])
            nonce = base64.b64decode(encrypted_card_data['nonce_b64'])
            ciphertext = base64.b64decode(encrypted_card_data['ciphertext_b64'])
            
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            return json.loads(plaintext.decode())
        except Exception as e:
            logging.error(f"❌ Card data decryption failed: {e}")
            raise Exception("Card data decryption failed")
    
    def check_user_lockout(self, user_id):
        """Kiểm tra user có bị khóa không"""
        if user_id in self.locked_users:
            lockout_time = self.locked_users[user_id]
            if datetime.now() < lockout_time:
                remaining = (lockout_time - datetime.now()).total_seconds()
                return True, f"User locked for {int(remaining)} more seconds"
            else:
                # Unlock user
                del self.locked_users[user_id]
                if user_id in self.failed_attempts:
                    del self.failed_attempts[user_id]
                    
        return False, ""
    
    def record_failed_attempt(self, user_id):
        """Ghi nhận lần thử thất bại"""
        if user_id not in self.failed_attempts:
            self.failed_attempts[user_id] = 0
            
        self.failed_attempts[user_id] += 1
        
        if self.failed_attempts[user_id] >= self.security_policies['max_failed_attempts']:
            # Lock user
            lockout_until = datetime.now() + timedelta(seconds=self.security_policies['lockout_duration'])
            self.locked_users[user_id] = lockout_until
            logging.warning(f"🚫 User {user_id} locked due to too many failed attempts")
            
    def check_time_restrictions(self, user_data):
        """Kiểm tra giới hạn thời gian"""
        if not user_data.get('time_restrictions', {}).get('enabled', False):
            return True, "No time restrictions"
            
        current_time = datetime.now()
        current_day = current_time.strftime('%A')
        current_hour = current_time.strftime('%H:%M')
        
        allowed_days = user_data['time_restrictions'].get('allowed_days', [])
        allowed_hours = user_data['time_restrictions'].get('allowed_hours', '00:00-23:59')
        
        if current_day not in allowed_days:
            return False, f"Access not allowed on {current_day}"
            
        if allowed_hours:
            start_time, end_time = allowed_hours.split('-')
            if not (start_time <= current_hour <= end_time):
                return False, f"Access not allowed at {current_hour}"
                
        return True, "Time restrictions passed"
    
    def verify_biometric_data(self, user_id, biometric_data):
        """Verify biometric data (simulated)"""
        if not biometric_data:
            return False, "No biometric data provided"
            
        # Simulate biometric database lookup
        biometric_db = {
            "user001": ["fingerprint_template_001"],
            "user002": ["face_template_002"],
            "user003": ["fingerprint_template_003"],
            "user004": ["face_template_004"]
        }
        
        user_templates = biometric_db.get(user_id, [])
        provided_template = biometric_data.get('template')
        confidence = biometric_data.get('confidence', 0.0)
        
        if provided_template not in user_templates:
            return False, "Biometric template mismatch"
            
        if confidence < 0.8:  # Minimum confidence threshold
            return False, f"Biometric confidence too low: {confidence}"
            
        return True, f"Biometric verified: {biometric_data.get('type')} with {confidence:.1%} confidence"
    
    def evaluate_access_decision(self, request_data):
        """Đánh giá quyết định truy cập dựa trên nhiều yếu tố"""
        try:
            # Lấy user_id từ request (đã được Reader decrypt từ card)
            user_id = request_data.get('user_id')
            
            if not user_id:
                logging.error("❌ No user_id in request")
                return "DENY", "No user identification provided", None
                
            logging.info(f"🔍 Evaluating access for user: {user_id}")
            
            # Check if user exists in database
            if user_id not in self.access_database['users']:
                logging.warning(f"❌ User not found in database: {user_id}")
                return "DENY", "User not found in database", None
                
            user_data = self.access_database['users'][user_id]
            logging.info(f"   User: {user_data['name']} ({user_data['department']})")
            
            # 1. Check user lockout
            is_locked, lockout_reason = self.check_user_lockout(user_id)
            if is_locked:
                logging.warning(f"❌ User is locked: {lockout_reason}")
                return "DENY", f"User locked: {lockout_reason}", user_data
                
            # 2. Check user status
            if user_data['status'] != 'active':
                logging.warning(f"❌ User status is not active: {user_data['status']}")
                self.record_failed_attempt(user_id)
                return "DENY", f"User status: {user_data['status']}", user_data
                
            # 3. Check time restrictions
            time_allowed, time_reason = self.check_time_restrictions(user_data)
            if not time_allowed:
                logging.warning(f"❌ Time restriction failed: {time_reason}")
                self.record_failed_attempt(user_id)
                return "DENY", time_reason, user_data
                
            # 4. Check access zones
            requested_zone = request_data.get('access_zone', 'MAIN_ENTRANCE')
            user_zones = user_data.get('access_zones', [])
            if requested_zone not in user_zones:
                logging.warning(f"❌ Zone access denied: {requested_zone} not in {user_zones}")
                self.record_failed_attempt(user_id)
                return "DENY", f"Access denied to zone: {requested_zone}", user_data
                
            # 5. Check access level vs zone requirements
            zone_info = self.access_database['zones'].get(requested_zone, {})
            required_level = zone_info.get('required_level', 'L1')
            user_level = user_data.get('access_level', 'L0')
            
            level_hierarchy = {'L0': 0, 'L1': 1, 'L2': 2, 'L3': 3}
            user_level_num = level_hierarchy.get(user_level, 0)
            required_level_num = level_hierarchy.get(required_level, 0)
            
            if user_level_num < required_level_num:
                logging.warning(f"❌ Insufficient access level: {user_level} < {required_level}")
                self.record_failed_attempt(user_id)
                return "DENY", f"Insufficient access level. Required: {required_level}, User: {user_level}", user_data
                
            # 6. Check biometric requirement
            if user_data.get('biometric_required', False):
                biometric_data = request_data.get('biometric_data')
                if not biometric_data:
                    logging.warning(f"❌ Biometric verification required but not provided")
                    return "DENY", "Biometric verification required", user_data
                # Thêm logic verify biometric ở đây
                
            # 7. Verify challenge (optional - có thể skip nếu không decrypt được card data)
            challenge_used = request_data.get('challenge_used')
            if challenge_used:
                logging.info("✓ Challenge verification skipped (card data encrypted)")
            
            # Reset failed attempts on successful evaluation
            if user_id in self.failed_attempts:
                del self.failed_attempts[user_id]
                
            logging.info(f"✅ All security checks passed for user: {user_id}")
            return "ALLOW", "All security checks passed", user_data
            
        except Exception as e:
            logging.error(f"❌ Access evaluation error: {e}")
            return "DENY", f"Security evaluation failed: {str(e)}", None
    
    def process_access_request(self, reader_id, encrypted_request, monitor_callback=None):
        """Xử lý yêu cầu truy cập với logic bảo mật nâng cao"""
        
        # 1. Check session validity
        session_valid, session_reason = self.check_session_validity(reader_id)
        if not session_valid:
            logging.error(f"❌ Session invalid for reader {reader_id}: {session_reason}")
            raise Exception(f"Session invalid: {session_reason}")
            
        session = self.active_sessions[reader_id]
        
        # 2. Decrypt request
        try:
            decrypted_data = self.crypto.decrypt_data(encrypted_request, session['session_key'])
            request_data = json.loads(decrypted_data)
        except Exception as e:
            logging.error(f"❌ Request decryption failed for reader {reader_id}: {e}")
            raise Exception("Request decryption failed")
        
        # 3. Log request details
        logging.info(f"🔍 Access request from reader {reader_id}")
        logging.info(f"   Card public key: {request_data['card_public_key_b64'][:20]}...")
        logging.info(f"   Timestamp: {request_data.get('timestamp', 'N/A')}")
        
        # 4. Evaluate access decision
        decision, reason, user_data = self.evaluate_access_decision(request_data)
        
        # 5. Log decision
        if decision == "ALLOW":
            logging.info(f"✅ ACCESS GRANTED for reader {reader_id}")
            logging.info(f"   User: {user_data['name'] if user_data else 'Unknown'}")
            logging.info(f"   Reason: {reason}")
        else:
            logging.warning(f"🚫 ACCESS DENIED for reader {reader_id}")
            logging.warning(f"   Reason: {reason}")
            
        # 6. Notify monitoring system
        if monitor_callback:
            monitor_callback({
                'reader_id': reader_id,
                'user_id': user_data.get('user_id') if user_data else 'Unknown',
                'decision': decision,
                'reason': reason,
                'timestamp': datetime.now().isoformat(),
                'user_data': user_data
            })
        
        # 7. Prepare response
        response_data = {
            "status": "success",
            "decision": decision,
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
            "session_id": reader_id,
            "user_info": {
                "name": user_data.get('name', 'Unknown') if user_data else 'Unknown',
                "access_level": user_data.get('access_level', 'L0') if user_data else 'L0',
                "department": user_data.get('department', 'Unknown') if user_data else 'Unknown'
            } if decision == "ALLOW" else None
        }
        
        # 8. Encrypt response
        encrypted_response = self.crypto.encrypt_data(response_data, session['session_key'])
        return encrypted_response

# Global server instance
server = SecureManagementServer()

@app.route('/handshake', methods=['POST'])
def handshake():
    """Endpoint để thực hiện mutual authentication với reader"""
    try:
        reader_data = request.get_json()
        
        # Authenticate reader và thiết lập session
        handshake_response = server.authenticate_reader(reader_data)
        
        logging.info(f"✅ Handshake successful with reader {reader_data['reader_id']}")
        return jsonify(handshake_response)
        
    except Exception as e:
        logging.error(f"❌ Handshake failed: {str(e)}")
        return jsonify({"status": "error", "error": str(e)}), 403

@app.route('/verify_access', methods=['POST'])
def verify_access():
    """Endpoint để xử lý yêu cầu truy cập"""
    try:
        data = request.get_json()
        reader_id = data['reader_id']
        encrypted_request = data['encrypted_request']
        
        # Xử lý yêu cầu truy cập
        encrypted_response = server.process_access_request(reader_id, encrypted_request)
        
        return jsonify({
            "status": "success",
            "encrypted_response": encrypted_response
        })
        
    except Exception as e:
        logging.error(f"❌ Access verification failed: {str(e)}")
        return jsonify({"status": "error", "error": str(e)}), 400

@app.route('/admin/users', methods=['GET'])
def get_users():
    """Admin endpoint để xem danh sách users"""
    try:
        users = server.access_database['users']
        # Remove sensitive data
        safe_users = {}
        for user_id, user_data in users.items():
            safe_users[user_id] = {
                'name': user_data['name'],
                'employee_id': user_data['employee_id'],
                'department': user_data['department'],
                'access_level': user_data['access_level'],
                'status': user_data['status']
            }
        return jsonify(safe_users)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/admin/sessions', methods=['GET'])
def get_active_sessions():
    """Admin endpoint để xem active sessions"""
    try:
        sessions_info = {}
        for reader_id, session in server.active_sessions.items():
            sessions_info[reader_id] = {
                'established_at': session['established_at'].isoformat(),
                'age_seconds': (datetime.now() - session['established_at']).total_seconds()
            }
        return jsonify(sessions_info)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/admin/security/status', methods=['GET'])
def get_security_status():
    """Admin endpoint để xem tình trạng bảo mật"""
    try:
        return jsonify({
            'active_sessions': len(server.active_sessions),
            'failed_attempts': dict(server.failed_attempts),
            'locked_users': {user_id: lockout_time.isoformat() 
                           for user_id, lockout_time in server.locked_users.items()},
            'security_policies': server.security_policies
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy", 
        "service": "Secure Management Server",
        "active_sessions": len(server.active_sessions),
        "total_users": len(server.access_database['users']),
        "version": "2.0"
    })

if __name__ == '__main__':
    print("=" * 60)
    print("🔐 SECURE MANAGEMENT SERVER v2.0")
    print("=" * 60)
    print(f"🌐 Server: http://{server.config['host']}:{server.config['port']}")
    print(f"👥 Total users: {len(server.access_database['users'])}")
    print(f"🏢 Access zones: {len(server.access_database['zones'])}")
    print(f"⚙️  Security policies: {server.security_policies}")
    print("=" * 60)
    print("📊 Admin endpoints:")
    print("   GET  /admin/users - User management")
    print("   GET  /admin/sessions - Active sessions")
    print("   GET  /admin/security/status - Security status")
    print("=" * 60)
    
    app.run(
        host=server.config['host'],
        port=server.config['port'],
        debug=False
    )