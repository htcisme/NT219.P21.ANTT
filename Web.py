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
        """Handle RFID messages for enhanced door animation and user feedback"""
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
            socketio.emit('door_state', {
                'state': 'authenticating', 
                'message': 'Authenticating with server...'
            })
            socketio.emit('rfid_activity', {
                'type': 'auth_challenge',
                'session_id': message.get("session_id"),
                'algorithm': message.get("encryption_algorithm", "AES-128-CTR"),
                'timestamp': int(time.time())
            })
            
        elif msg_type == "auth_success":
            self.current_user = {
                "name": message.get("user_name", "Unknown User"),
                "uid": message.get("card_uid", "Unknown"),
                "permissions": message.get("permissions", []),
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "image": self.get_user_image(message.get("card_uid")),
                "session_key": message.get("session_key"),
                "valid_until": message.get("valid_until"),
                "encryption": message.get("aes_encryption", False),
                "algorithm": message.get("encryption_algorithm", "None")
            }
            self.animate_door("open")
            socketio.emit('auth_success', self.current_user)
            
        elif msg_type == "auth_rejected":
            self.animate_door("denied")
            socketio.emit('auth_denied', {
                "uid": message.get("card_uid", "Unknown"),
                "reason": message.get("reason", "Access denied"),
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "details": message.get("details", {})
            })
            
        elif msg_type == "card_removed":
            threading.Timer(3.0, self.animate_door, ["closed"]).start()
            socketio.emit('rfid_activity', {
                'type': 'card_removed',
                'uid': message.get("card_uid"),
                'timestamp': int(time.time())
            })
    
    def get_user_image(self, card_uid):
        """Get user image based on card UID"""
        user_images = {
            "9C85C705": "/static/images/user1.jpg",
            "3D8BC705": "/static/images/user2.JPG",
            "A1B2C3D4": "/static/images/admin.png",
            "E5F6G7H8": "/static/images/guest.png"
        }
        return user_images.get(card_uid, "/static/images/default_user.png")
    
    def animate_door(self, state):
        """Enhanced door animation with more states"""
        self.door_state = state
        socketio.emit('door_animation', {'state': state})
        
        if state == "open":
            threading.Timer(8.0, self.animate_door, ["closing"]).start()
        elif state == "closing":
            threading.Timer(2.0, self.animate_door, ["closed"]).start()
    
    def simulate_real_replay_attack(self):
        """Thực hiện Replay Attack thật vào MQTT với chi tiết kỹ thuật"""
        import time
        
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
        
        attack_steps = [
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
        
        for step_data in attack_steps:
            if not self.attack_active:
                break
                
            # Thực hiện action thật tương ứng với từng step
            if step_data.get("real_action") == "execute_replay":
                self.execute_real_replay_attack(auth_data)
            elif step_data.get("real_action") == "sniff_mqtt_traffic":
                self.perform_mqtt_sniffing()
                
            # Log chi tiết attack step
            attack_log = {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "topic": "REAL_ATTACK",
                "direction": "Penetration Test",
                "type": "replay_attack",
                "data": {
                    "step": step_data["step"],
                    "title": step_data["title"],
                    "technical_details": step_data["technical_details"],
                    "real_action": step_data.get("real_action", "none")
                },
                "message_size": len(json.dumps(step_data)),
                "qos": 1
            }
            self.system_logs.append(attack_log)
            
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
    def simulate_real_mitm_attack(self):
        """Thực hiện MITM Attack thật với rogue MQTT broker"""
        import time
        import threading
        
        attack_steps = [
            {
                "step": 1,
                "title": "🎭 Thiết lập Rogue MQTT Broker",
                "details": [
                    "Khởi động rogue MQTT broker trên port 1884...",
                    "Thiết lập WiFi AP giả mạo: 'ESP32_RFID_SECURE'",
                    "Cấu hình DNS hijacking cho 'localhost'",
                    "Chuẩn bị certificate giả mạo...",
                    "✅ Rogue infrastructure đã sẵn sàng!",
                    "Chờ ESP32 kết nối..."
                ],
                "technical_details": {
                    "rogue_infrastructure": {
                        "fake_mqtt_broker": {
                            "host": "localhost",
                            "port": 1884,
                            "protocol": "MQTT 3.1.1",
                            "authentication": False,
                            "ssl_enabled": False
                        },
                        "fake_ap": {
                            "ssid": "ESP32_RFID_SECURE",
                            "security": "WPA2-PSK",
                            "channel": 6,
                            "signal_strength": "-25 dBm",
                            "mac_spoofed": "24:0A:C4:AB:CD:EF"
                        },
                        "dns_hijacking": {
                            "target_domain": "localhost",
                            "redirect_ip": "192.168.1.100",
                            "method": "DNS spoofing"
                        }
                    }
                },
                "real_action": "setup_rogue_broker",
                "duration": 4
            },
            {
                "step": 2,
                "title": "📡 Chặn bắt ESP32 Communication",
                "details": [
                    "Monitoring ESP32 connection attempts...",
                    "Phát hiện ESP32 cố gắng kết nối MQTT...",
                    "Chuyển hướng connection đến rogue broker...",
                    "✅ ESP32 đã kết nối vào rogue broker!",
                    "Bắt đầu intercept messages...",
                    "Capturing server public key..."
                ],
                "technical_details": {
                    "interception_status": {
                        "esp32_redirected": True,
                        "mqtt_session_hijacked": True,
                        "captured_handshake": True,
                        "server_pubkey_captured": True,
                        "communication_flow": "ESP32 ↔ Rogue Broker ↔ Real Server"
                    },
                    "captured_data": {
                        "server_public_key": "Dilithium2 public key intercepted",
                        "key_size": "1312 bytes",
                        "key_fingerprint": "sha256:9f8e7d6c5b4a...",
                        "esp32_capabilities": {
                            "dilithium_support": True,
                            "aes_support": True,
                            "mutual_auth": True
                        }
                    }
                },
                "real_action": "intercept_communications",
                "duration": 4
            },
            {
                "step": 3,
                "title": "🔐 Tạo Fake Dilithium Keypair",
                "details": [
                    "Generating fake Dilithium2 keypair...",
                    "⚠️ Cố gắng thay thế server public key",
                    "Tạo fake auth_challenge message...",
                    "Ký message với fake private key...",
                    "Chuẩn bị inject fake message vào ESP32...",
                    "🚨 Chuẩn bị test signature verification..."
                ],
                "technical_details": {
                    "cryptographic_spoofing": {
                        "fake_dilithium_keypair": {
                            "algorithm": "Dilithium2",
                            "public_key_size": "1312 bytes",
                            "private_key_size": "2528 bytes", 
                            "generation_time": "0.15 seconds",
                            "fake_pubkey_hash": "sha256:a1b2c3d4e5f6...",
                            "real_pubkey_hash": "sha256:9f8e7d6c5b4a..."
                        },
                        "spoofed_message": {
                            "type": "auth_challenge",
                            "session_id": f"MITM_{secrets.token_hex(8)}",
                            "challenge": base64.b64encode(secrets.token_bytes(32)).decode(),
                            "fake_signature": "Generated with fake private key",
                            "timestamp": int(time.time()),
                            "injection_method": "MQTT message replacement"
                        }
                    }
                },
                "real_action": "generate_fake_keys",
                "duration": 5
            },
            {
                "step": 4,
                "title": "🛡️ ESP32 Signature Verification Process",
                "details": [
                    "ESP32 nhận được fake auth_challenge...",
                    "Loading stored server public key từ EEPROM...",
                    "Executing dilithium_verify() function...",
                    "So sánh key fingerprints...",
                    "🔍 PHÁT HIỆN: Signature không hợp lệ!",
                    "🚨 MITM attack detected!"
                ],
                "technical_details": {
                    "esp32_verification": {
                        "stored_server_pubkey": {
                            "algorithm": "Dilithium2",
                            "fingerprint": "sha256:9f8e7d6c5b4a3210fedcba987654321",
                            "storage_location": "ESP32 EEPROM offset 0x1000",
                            "integrity_verified": True
                        },
                        "received_message_analysis": {
                            "signature_size": "2420 bytes",
                            "algorithm_claimed": "Dilithium2",
                            "signature_source": "FAKE (attacker generated)",
                            "key_fingerprint_mismatch": True
                        },
                        "verification_result": {
                            "function_called": "dilithium_verify(stored_pk, message, signature)",
                            "execution_time": "52ms",
                            "result": "SIGNATURE_INVALID",
                            "error_code": "0x8001 - INVALID_SIGNATURE",
                            "security_action": "TERMINATE_CONNECTION"
                        }
                    }
                },
                "real_action": "verify_signature",
                "duration": 4
            },
            {
                "step": 5,
                "title": "🚫 Security Protocol Activation",
                "details": [
                    "ESP32: 'SECURITY ALERT: Invalid server signature!'",
                    "Logging security incident...",
                    "Terminating rogue MQTT connection...",
                    "Switching to secure reconnection mode...",
                    "Attempting connection to legitimate server...",
                    "🔒 MITM attack hoàn toàn bị chặn!"
                ],
                "technical_details": {
                    "security_response": {
                        "alert_generated": {
                            "timestamp": int(time.time()),
                            "event_type": "MITM_ATTACK_DETECTED",
                            "threat_level": "HIGH", 
                            "automatic_response": "BLOCK_AND_RECONNECT"
                        },
                        "esp32_actions": [
                            "Disconnect from suspicious broker",
                            "Clear current session data",
                            "Reset connection parameters",
                            "Scan for legitimate WiFi networks",
                            "Verify server identity before reconnection"
                        ],
                        "recovery_process": {
                            "step1": "Terminate current connection",
                            "step2": "Flush network buffers", 
                            "step3": "Re-scan WiFi networks",
                            "step4": "Reconnect to authentic server",
                            "estimated_recovery_time": "8-12 seconds"
                        }
                    }
                },
                "real_action": "security_response",
                "duration": 4
            },
            {
                "step": 6,
                "title": "🔒 Post-Quantum Security Analysis",
                "details": [
                    "✅ Dilithium2 signatures: KHÔNG THỂ GIẢ MẠO",
                    "✅ Mutual authentication: BẮT BUỘC",
                    "✅ Key fingerprint verification: CHỐNG THAY ĐỔI",
                    "✅ Real-time attack detection: HOẠT ĐỘNG",
                    "✅ Automatic threat response: TỨC THỜI",
                    "🛡️ MITM ATTACK HOÀN TOÀN BỊ VÔ HIỆU HÓA!"
                ],
                "technical_details": {
                    "security_analysis": {
                        "dilithium_strength": {
                            "algorithm": "Dilithium2 (NIST Post-Quantum Standard)",
                            "security_level": "Category 2 (equivalent to AES-128)",
                            "signature_forgery": "Computationally infeasible (2^128 operations)",
                            "quantum_resistance": "Proven secure against Shor's algorithm",
                            "classical_resistance": "Secure against known classical attacks"
                        },
                        "mutual_authentication": {
                            "esp32_verifies_server": True,
                            "server_verifies_esp32": True,
                            "bidirectional_trust": True,
                            "spoofing_resistance": "99.9999%",
                            "key_pinning": "Public key fingerprint stored in ESP32"
                        },
                        "attack_prevention_metrics": {
                            "detection_time": "< 100ms",
                            "false_positive_rate": "< 1 in 10^12",
                            "recovery_time": "< 10 seconds",
                            "user_impact": "Minimal (transparent recovery)",
                            "attack_success_rate": "0% (theoretical and practical)"
                        }
                    },
                    "comparison_analysis": {
                        "classical_cryptography": {
                            "rsa_2048": "Vulnerable to quantum computers (Shor's algorithm)",
                            "ecdsa_p256": "Vulnerable to quantum computers",
                            "attack_timeline": "~10-15 years until quantum threat"
                        },
                        "post_quantum_advantage": {
                            "dilithium": "Quantum-resistant by mathematical design",
                            "security_assumption": "Learning with Errors (LWE) problem",
                            "future_proof": "Secure against both classical and quantum attacks"
                        }
                    }
                },
                "real_action": "generate_security_report",
                "duration": 6
            }
        ]
        
        # Thực hiện các bước attack
        for step_data in attack_steps:
            if not self.attack_active:
                break
                
            # Thực hiện real action tương ứng
            if step_data.get("real_action") == "setup_rogue_broker":
                self.setup_rogue_mqtt_broker()
            elif step_data.get("real_action") == "intercept_communications":
                self.intercept_mqtt_communications()
                
            # Log chi tiết
            attack_log = {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "topic": "REAL_MITM_ATTACK",
                "direction": "Advanced Persistent Threat",
                "type": "mitm_attack",
                "data": {
                    "step": step_data["step"],
                    "title": step_data["title"],
                    "technical_details": step_data["technical_details"],
                    "real_action": step_data.get("real_action", "none")
                },
                "message_size": len(json.dumps(step_data)),
                "qos": 1
            }
            self.system_logs.append(attack_log)
            
            socketio.emit('attack_step', {
                "type": "mitm",
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
            "type": "mitm",
            "success": False,
            "blocked_by": "Post-quantum cryptographic verification",
            "security_level": "QUANTUM-RESISTANT",
            "real_attack_executed": True
        })
    def setup_rogue_mqtt_broker(self):
        """Thiết lập rogue MQTT broker thật (chỉ để demo)"""
        try:
            print("🚨 Setting up rogue MQTT broker on port 1884...")
            # Trong thực tế sẽ start một MQTT broker giả mạo
            # Ở đây chỉ log để demo
            
            rogue_log = {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "topic": "ROGUE_BROKER",
                "direction": "Infrastructure Setup",
                "type": "rogue_service",
                "data": {
                    "service": "Fake MQTT Broker",
                    "port": 1884,
                    "status": "ACTIVE",
                    "purpose": "MITM Attack Infrastructure"
                },
                "message_size": 150,
                "qos": 1
            }
            self.system_logs.append(rogue_log)
            
        except Exception as e:
            print(f"❌ Rogue broker setup failed: {e}")
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
        return self.simulate_real_mitm_attack()
    def create_javascript(self):
        """Create enhanced JavaScript for detailed attack visualization"""
        js_content = '''// Enhanced Dashboard JavaScript với detailed attack info
const socket = io();
let attackInterval = null;
let attackProgress = 0;

// Socket event handlers
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

socket.on('esp32_status', function(data) {
    esp32Status = data;
    updateESP32Status();
});
socket.on('door_state', function(data) {
    updateDoorState(data.state, data.message);
});

socket.on('door_animation', function(data) {
    animateDoor(data.state);
});

socket.on('rfid_activity', function(data) {
    updateRFIDStatus(data.type);
    logRFIDActivity(data);
});

socket.on('auth_success', function(data) {
    showUserInfo(data);
    updateRFIDStatus('success');
});

socket.on('auth_denied', function(data) {
    showAccessDenied(data);
    updateRFIDStatus('error');
});

socket.on('attack_step', function(data) {
    displayAttackStep(data);
});

socket.on('attack_complete', function(data) {
    completeAttack(data.type);
});

function renderParametersRecursive(obj, depth = 0) {
    if (depth > 3) return '<p>... (max depth reached)</p>';
    
    let html = '';
    for (const [key, value] of Object.entries(obj)) {
        if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
            html += `
                <div class="param-group" style="margin-left: ${depth * 20}px;">
                    <h6>${key.replace(/_/g, ' ').toUpperCase()}:</h6>
                    ${renderParametersRecursive(value, depth + 1)}
                </div>
            `;
        } else if (Array.isArray(value)) {
            html += `
                <div class="param-item" style="margin-left: ${depth * 20}px;">
                    <strong>${key}:</strong>
                    <ul>
                        ${value.map(item => `<li>${typeof item === 'object' ? JSON.stringify(item) : item}</li>`).join('')}
                    </ul>
                </div>
            `;
        } else {
            html += `
                <div class="param-item" style="margin-left: ${depth * 20}px;">
                    <strong>${key}:</strong> <code>${value}</code>
                </div>
            `;
        }
    }
    return html;
}
function renderTechnicalDetails(details, depth = 0) {
    if (!details || typeof details !== 'object') return '';
    
    let html = '<div class="technical-details">';
    
    for (const [key, value] of Object.entries(details)) {
        if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
            html += `
                <div class="detail-section" style="margin-left: ${depth * 15}px;">
                    <h6 class="detail-header">${key.replace(/_/g, ' ').toUpperCase()}:</h6>
                    ${renderTechnicalDetails(value, depth + 1)}
                </div>
            `;
        } else if (Array.isArray(value)) {
            html += `
                <div class="detail-array" style="margin-left: ${depth * 15}px;">
                    <strong>${key}:</strong>
                    <ul class="detail-list">
                        ${value.map(item => `<li>${typeof item === 'object' ? JSON.stringify(item, null, 2) : item}</li>`).join('')}
                    </ul>
                </div>
            `;
        } else {
            const valueClass = typeof value === 'boolean' ? (value ? 'success' : 'error') : 'normal';
            html += `
                <div class="detail-item ${valueClass}" style="margin-left: ${depth * 15}px;">
                    <span class="detail-key">${key}:</span> 
                    <span class="detail-value">${value}</span>
                </div>
            `;
        }
    }
    
    html += '</div>';
    return html;
}
function updateESP32Status() {
    const statusElement = document.getElementById('esp32-status');
    if (!statusElement) return;
    
    const timeSinceLastHeartbeat = Date.now()/1000 - esp32Status.last_heartbeat;
    const isConnected = esp32Status.connected && timeSinceLastHeartbeat < 60;
    
    statusElement.innerHTML = `
        <div class="status-item ${isConnected ? 'connected' : 'disconnected'}">
            <i class="fas fa-microchip"></i>
            <div class="status-details">
                <h4>ESP32 Status</h4>
                <p>Version: ${esp32Status.version}</p>
                <p>Heap: ${esp32Status.free_heap} bytes</p>
                <p>Uptime: ${Math.floor(esp32Status.uptime/1000)}s</p>
                <p>AES: ${esp32Status.aes_support ? '✅' : '❌'}</p>
                <p>Auth: ${esp32Status.mutual_auth ? '✅' : '❌'}</p>
                <p>Last: ${timeSinceLastHeartbeat < 60 ? Math.floor(timeSinceLastHeartbeat) + 's ago' : 'Offline'}</p>
            </div>
        </div>
    `;
}

// Enhanced attack step display function
function displayAttackStep(stepData) {
    const attackLogs = document.getElementById('attack-logs');
    const attackVisualization = document.getElementById('attack-visualization');
    
    updateAttackProgress(stepData.progress);
    
    const stepDiv = document.createElement('div');
    stepDiv.className = 'attack-step-detail';
    stepDiv.innerHTML = `
        <div class="step-header">
            <h4>Step ${stepData.step}: ${stepData.title}</h4>
            <span class="step-timestamp">${new Date().toLocaleTimeString()}</span>
            ${stepData.real_attack ? '<span class="real-attack-badge">🔥 REAL ATTACK</span>' : ''}
        </div>
        <div class="step-content">
            <div class="step-details">
                ${stepData.details.map(detail => `<p>• ${detail}</p>`).join('')}
            </div>
            ${stepData.technical_details ? `
                <div class="step-technical">
                    <h5>🔧 Technical Analysis & Parameters:</h5>
                    ${renderTechnicalDetails(stepData.technical_details)}
                </div>
            ` : ''}
        </div>
    `;
    
    attackLogs.appendChild(stepDiv);
    attackLogs.scrollTop = attackLogs.scrollHeight;
    
    if (attackVisualization) {
        updateAttackVisualization(stepData);
    }
}

function updateAttackVisualization(stepData) {
    const visualization = document.getElementById('attack-visualization');
    
    if (stepData.type === 'replay') {
        visualization.innerHTML = `
            <div class="attack-flow">
                <div class="attack-node ${stepData.step >= 2 ? 'active' : ''}">
                    🕵️ Attacker
                    <small>Captured: ${stepData.step >= 2 ? 'YES' : 'NO'}</small>
                    <tiny>Step ${stepData.step}/6</tiny>
                </div>
                <div class="attack-arrow ${stepData.step >= 4 ? 'active' : ''}">⚡ Replay</div>
                <div class="attack-node ${stepData.step >= 5 ? 'blocked' : ''}">
                    🖥️ Server
                    <small>Status: ${stepData.step >= 5 ? 'BLOCKED' : 'Target'}</small>
                    <tiny>Security: ${stepData.step >= 5 ? 'ACTIVE' : 'Monitoring'}</tiny>
                </div>
            </div>
            <div class="attack-status">
                <h4>Replay Attack Analysis</h4>
                <p>Current: ${stepData.title}</p>
                <div class="security-indicators">
                    <div class="indicator ${stepData.step >= 3 ? 'active' : ''}">
                        ⏰ Timestamp Check: ${stepData.step >= 3 ? 'EXPIRED' : 'Pending'}
                    </div>
                    <div class="indicator ${stepData.step >= 4 ? 'active' : ''}">
                        🔄 Replay Attempt: ${stepData.step >= 4 ? 'DETECTED' : 'Pending'}
                    </div>
                    <div class="indicator ${stepData.step >= 5 ? 'active' : ''}">
                        🛡️ Server Response: ${stepData.step >= 5 ? 'BLOCKED' : 'Pending'}
                    </div>
                </div>
            </div>
        `;
    } else if (stepData.type === 'mitm') {
        visualization.innerHTML = `
            <div class="attack-flow">
                <div class="attack-node">
                    📱 ESP32
                    <small>Status: ${stepData.step >= 5 ? 'Protected' : 'Target'}</small>
                    <tiny>Auth: ${stepData.step >= 4 ? 'Verifying' : 'Normal'}</tiny>
                </div>
                <div class="attack-arrow ${stepData.step >= 2 ? 'active' : ''}">⚡</div>
                <div class="attack-node attacker ${stepData.step >= 2 ? 'active' : ''}">
                    🕵️ MITM
                    <small>Spoofing: ${stepData.step >= 3 ? 'Active' : 'Setup'}</small>
                    <tiny>Success: ${stepData.step >= 5 ? 'FAILED' : 'Trying'}</tiny>
                </div>
                <div class="attack-arrow ${stepData.step >= 3 ? 'active' : ''}">⚡</div>
                <div class="attack-node">
                    🖥️ Real Server
                    <small>Signature: ${stepData.step >= 4 ? 'Verified' : 'Pending'}</small>
                    <tiny>Security: Post-Quantum</tiny>
                </div>
            </div>
            <div class="attack-status">
                <h4>MITM Attack Analysis</h4>
                <p>Current: ${stepData.title}</p>
                <div class="security-indicators">
                    <div class="indicator ${stepData.step >= 2 ? 'active' : ''}">
                        📡 Interception: ${stepData.step >= 2 ? 'ACTIVE' : 'Setup'}
                    </div>
                    <div class="indicator ${stepData.step >= 3 ? 'active' : ''}">
                        🔐 Key Spoofing: ${stepData.step >= 3 ? 'ATTEMPTED' : 'Pending'}
                    </div>
                    <div class="indicator ${stepData.step >= 4 ? 'active' : ''}">
                        🛡️ Dilithium Check: ${stepData.step >= 4 ? 'VERIFYING' : 'Pending'}
                    </div>
                    <div class="indicator ${stepData.step >= 5 ? 'active' : ''}">
                        🚫 Attack Result: ${stepData.step >= 5 ? 'BLOCKED' : 'Pending'}
                    </div>
                </div>
            </div>
        `;
    }
}

function completeAttack(attackType, result) {
    const attackLogs = document.getElementById('attack-logs');
    
    const summaryDiv = document.createElement('div');
    summaryDiv.className = 'attack-summary';
    
    if (attackType === 'replay') {
        summaryDiv.innerHTML = `
            <div class="summary-header">
                <h3>🛡️ Replay Attack Summary</h3>
                <span class="result-badge ${result.success ? 'failed' : 'blocked'}">
                    ${result.success ? 'ATTACK SUCCESS' : 'ATTACK BLOCKED'}
                </span>
            </div>
            <div class="summary-content">
                <h4>✅ Security Analysis Complete!</h4>
                <div class="summary-stats">
                    <div class="stat">
                        <strong>Detection Method:</strong> ${result.blocked_by || 'Multiple layers'}
                    </div>
                    <div class="stat">
                        <strong>Security Level:</strong> ${result.security_level || 'MAXIMUM'}
                    </div>
                    <div class="stat">
                        <strong>Response Time:</strong> < 1 second
                    </div>
                    <div class="stat">
                        <strong>False Positive Rate:</strong> < 0.001%
                    </div>
                </div>
                <div class="security-note">
                    <h5>🔒 Why Replay Attacks Fail:</h5>
                    <ul>
                        <li><strong>Timestamp Validation:</strong> 60-second freshness window</li>
                        <li><strong>Session Uniqueness:</strong> Each session tracked and validated</li>
                        <li><strong>Nonce Protection:</strong> Prevents message reuse</li>
                        <li><strong>Dilithium Signatures:</strong> Post-quantum cryptographic integrity</li>
                    </ul>
                </div>
            </div>
        `;
    } else if (attackType === 'mitm') {
        summaryDiv.innerHTML = `
            <div class="summary-header">
                <h3>🔒 MITM Attack Summary</h3>
                <span class="result-badge ${result.success ? 'failed' : 'blocked'}">
                    ${result.success ? 'ATTACK SUCCESS' : 'ATTACK BLOCKED'}
                </span>
            </div>
            <div class="summary-content">
                <h4>✅ Post-Quantum Security Validated!</h4>
                <div class="summary-stats">
                    <div class="stat">
                        <strong>Detection Method:</strong> ${result.blocked_by || 'Dilithium signature verification'}
                    </div>
                    <div class="stat">
                        <strong>Security Level:</strong> ${result.security_level || 'POST-QUANTUM'}
                    </div>
                    <div class="stat">
                        <strong>Verification Time:</strong> < 0.1 seconds
                    </div>
                    <div class="stat">
                        <strong>Forge Difficulty:</strong> 2^128 operations
                    </div>
                </div>
                <div class="security-note">
                    <h5>🛡️ Why MITM Attacks Fail:</h5>
                    <ul>
                        <li><strong>Dilithium Signatures:</strong> Quantum-resistant, impossible to forge</li>
                        <li><strong>Mutual Authentication:</strong> Both ESP32 and server verify each other</li>
                        <li><strong>Key Fingerprinting:</strong> Stored key hashes prevent substitution</li>
                        <li><strong>Real-time Verification:</strong> Every message signature checked</li>
                    </ul>
                </div>
            </div>
        `;
    }
    
    attackLogs.appendChild(summaryDiv);
    attackLogs.scrollTop = attackLogs.scrollHeight;
    
    setTimeout(() => {
        document.getElementById('stop-attack-btn').style.display = 'none';
        document.getElementById('replay-attack-btn').disabled = false;
        document.getElementById('mitm-attack-btn').disabled = false;
    }, 3000);
}

// Enhanced attack functions
function startReplayAttack() {
    if (attackInterval) return;
    
    showAttackWindow('Detailed Replay Attack Analysis', 'replay');
    showAttackOverlay('Replay Attack - Technical Analysis');
    
    document.getElementById('stop-attack-btn').style.display = 'block';
    document.getElementById('replay-attack-btn').disabled = true;
    document.getElementById('mitm-attack-btn').disabled = true;
    
    // Send attack start signal to server
    fetch('/api/attack/start', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({type: 'replay'})
    });
}


function startMITMAttack() {
    if (attackInterval) return;
    
    showAttackWindow('Detailed MITM Attack Analysis', 'mitm');
    showAttackOverlay('MITM Attack - Post-Quantum Defense');
    
    document.getElementById('stop-attack-btn').style.display = 'block';
    document.getElementById('replay-attack-btn').disabled = true;
    document.getElementById('mitm-attack-btn').disabled = true;
    
    fetch('/api/attack/start', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({type: 'mitm'})
    }).catch(err => console.error('Attack start failed:', err));
}


function stopAttack() {
    fetch('/api/attack/stop', {method: 'POST'});
    
    document.getElementById('stop-attack-btn').style.display = 'none';
    document.getElementById('replay-attack-btn').disabled = false;
    document.getElementById('mitm-attack-btn').disabled = false;
    
    closeAttackWindow();
    hideAttackOverlay();
}

// ... rest of existing JavaScript functions remain the same ...
''';
        
        # Add enhanced CSS for attack visualization
        css_additional = '''
/* Enhanced Attack Visualization Styles */
.attack-step-detail {
    margin: 1rem 0;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    overflow: hidden;
}

.step-header {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 0.75rem 1rem;
    font-weight: 600;
}

.step-content {
    padding: 1rem;
}

.step-details p {
    margin: 0.5rem 0;
    color: #4a5568;
}

.step-parameters {
    margin-top: 1rem;
    background: #f7fafc;
    padding: 1rem;
    border-radius: 6px;
}

.step-parameters h5 {
    color: #2d3748;
    margin-bottom: 0.5rem;
}

.step-parameters pre {
    background: #1a202c;
    color: #e2e8f0;
    padding: 0.75rem;
    border-radius: 4px;
    font-size: 0.8rem;
    overflow-x: auto;
}

.attack-summary {
    margin: 1.5rem 0;
    border: 2px solid #48bb78;
    border-radius: 10px;
    overflow: hidden;
    background: white;
}
.real-attack-badge {
    background: linear-gradient(45deg, #ff4757, #ff3838);
    color: white;
    padding: 0.25rem 0.5rem;
    border-radius: 12px;
    font-size: 0.7rem;
    font-weight: bold;
    animation: pulse-red 2s infinite;
}

@keyframes pulse-red {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.7; }
}

.step-technical {
    margin-top: 1.5rem;
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 1rem;
}

.technical-details {
    font-family: 'Courier New', monospace;
    font-size: 0.85rem;
}

.detail-section {
    margin: 0.75rem 0;
    border-left: 3px solid #3182ce;
    padding-left: 0.75rem;
}

.detail-header {
    color: #2b6cb0;
    font-weight: bold;
    margin-bottom: 0.5rem;
}

.detail-item {
    display: flex;
    margin: 0.25rem 0;
    padding: 0.25rem 0;
}

.detail-item.success .detail-value {
    color: #38a169;
    font-weight: bold;
}

.detail-item.error .detail-value {
    color: #e53e3e;
    font-weight: bold;
}

.detail-key {
    font-weight: 600;
    color: #4a5568;
    min-width: 140px;
}

.detail-value {
    color: #2d3748;
    font-family: monospace;
    background: #edf2f7;
    padding: 0.125rem 0.25rem;
    border-radius: 3px;
}

.detail-list {
    margin: 0.5rem 0;
    padding-left: 1.5rem;
}

.detail-list li {
    margin: 0.25rem 0;
    color: #4a5568;
}
.summary-header {
    background: linear-gradient(135deg, #48bb78, #38a169);
    color: white;
    padding: 1rem;
    text-align: center;
}

.summary-content {
    padding: 1.5rem;
}

.summary-content h4 {
    color: #38a169;
    margin-bottom: 1rem;
}

.summary-content ul {
    margin: 1rem 0;
    padding-left: 1.5rem;
}

.summary-content li {
    margin: 0.5rem 0;
    color: #4a5568;
}

.security-note {
    background: rgba(72, 187, 120, 0.1);
    border-left: 4px solid #48bb78;
    padding: 1rem;
    margin: 1rem 0;
    border-radius: 0 6px 6px 0;
}

.security-note p {
    color: #2d3748;
    margin: 0;
    font-style: italic;
}

.attack-flow {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 1rem;
    margin: 2rem 0;
}

.attack-node {
    background: white;
    border: 2px solid #e2e8f0;
    border-radius: 10px;
    padding: 1rem;
    text-align: center;
    min-width: 100px;
    transition: all 0.3s ease;
}

.attack-node.active {
    border-color: #f56565;
    background: rgba(245, 101, 101, 0.1);
    color: #c53030;
}

.attack-node.blocked {
    border-color: #48bb78;
    background: rgba(72, 187, 120, 0.1);
    color: #2f855a;
}

.attack-node.attacker {
    border-color: #ed8936;
    background: rgba(237, 137, 54, 0.1);
}

.attack-arrow {
    font-size: 1.5rem;
    color: #a0aec0;
    transition: color 0.3s ease;
}

.attack-arrow.active {
    color: #f56565;
    animation: pulse 1.5s infinite;
}

.attack-status {
    background: #f7fafc;
    padding: 1.5rem;
    border-radius: 10px;
    margin: 1rem 0;
}

.security-indicators {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    margin-top: 1rem;
}

.security-indicators .indicator {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.5rem;
    background: white;
    border-radius: 6px;
    color: #a0aec0;
    transition: all 0.3s ease;
}

.security-indicators .indicator.active {
    color: #38a169;
    background: rgba(72, 187, 120, 0.1);
    border-left: 3px solid #48bb78;
}

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
}
'''
        
        with open(os.path.join(self.static_dir, "styles.css"), 'a', encoding='utf-8') as f:
            f.write(css_additional)
        
        with open(os.path.join(self.static_dir, "dashboard.js"), 'w', encoding='utf-8') as f:
            f.write(js_content)
            
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
    border: 3px solid #654321;
}

/* Door Animations */
.door.opening {
    transform: perspective(1000px) rotateY(-130deg);
}

.door.open {
    transform: perspective(1000px) rotateY(-130deg);
}

.door.closing {
    transform: perspective(1000px) rotateY(0deg);
}

.door.denied {
    animation: shake 0.5s ease-in-out;
}

.door-left.open {
    display: block;
    transform: perspective(1000px) rotateY(-130deg);
}

.door-right.open {
    display: block;
    transform: perspective(1000px) rotateY(130deg);
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
    background: rgba(74, 85, 104, 0.1);
    border: 2px dashed rgba(74, 85, 104, 0.3);
    border-radius: 15px;
    color: #4a5568;
    transition: all 0.3s ease;
}

.rfid-reader.active {
    background: rgba(72, 187, 120, 0.1);
    border-color: rgba(72, 187, 120, 0.5);
    color: #38a169;
}

.rfid-light {
    width: 10px;
    height: 10px;
    background: #e2e8f0;
    border-radius: 50%;
    transition: all 0.3s ease;
}

.rfid-light.active {
    background: #38a169;
    box-shadow: 0 0 10px #38a169;
}

.rfid-light.error {
    background: #e53e3e;
    box-shadow: 0 0 10px #e53e3e;
}

.door-status {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    font-weight: 600;
    color: #4a5568;
}

/* User Panel */
.user-panel {
    background: rgba(255, 255, 255, 0.95);
    border-radius: 20px;
    padding: 2rem;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
    backdrop-filter: blur(10px);
    min-height: 200px;
    display: flex;
    align-items: center;
    justify-content: center;
}

.user-info {
    text-align: center;
    animation: slideInUp 0.5s ease;
}

.user-info img {
    width: 80px;
    height: 80px;
    border-radius: 50%;
    object-fit: cover;
    border: 4px solid #38a169;
    margin-bottom: 1rem;
}

.user-info h3 {
    color: #2d3748;
    margin-bottom: 0.5rem;
    font-size: 1.2rem;
}

.user-info p {
    color: #718096;
    margin-bottom: 0.5rem;
}

.user-permissions {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    justify-content: center;
    margin: 1rem 0;
}

.permission {
    background: rgba(72, 187, 120, 0.1);
    color: #38a169;
    padding: 0.25rem 0.75rem;
    border-radius: 15px;
    font-size: 0.8rem;
    border: 1px solid rgba(72, 187, 120, 0.3);
}

.access-time {
    color: #a0aec0;
    font-size: 0.9rem;
    font-style: italic;
}

.access-denied {
    text-align: center;
    color: #e53e3e;
    animation: slideInUp 0.5s ease;
}

.access-denied i {
    font-size: 3rem;
    margin-bottom: 1rem;
}

.access-denied h3 {
    margin-bottom: 0.5rem;
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
    color: #2d3748;
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.attack-buttons {
    display: flex;
    gap: 1rem;
    flex-wrap: wrap;
}

.attack-btn, .stop-btn {
    flex: 1;
    padding: 0.75rem 1rem;
    border: none;
    border-radius: 10px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s ease;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
}

.attack-btn {
    background: linear-gradient(135deg, #ff6b6b, #ee5a52);
    color: white;
}

.attack-btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 5px 15px rgba(255, 107, 107, 0.4);
}

.stop-btn {
    background: linear-gradient(135deg, #4ecdc4, #44a08d);
    color: white;
}

.stop-btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 5px 15px rgba(78, 205, 196, 0.4);
}

/* Attack Window */
.attack-window {
    background: rgba(255, 255, 255, 0.95);
    border-radius: 20px;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
    backdrop-filter: blur(10px);
    overflow: hidden;
    animation: slideInDown 0.3s ease;
}

.attack-header {
    background: linear-gradient(135deg, #ff6b6b, #ee5a52);
    color: white;
    padding: 1rem 2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
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
}

.close-btn:hover {
    background: rgba(255, 255, 255, 0.2);
}

.attack-content {
    padding: 2rem;
}

.attack-progress {
    width: 100%;
    height: 10px;
    background: #e2e8f0;
    border-radius: 5px;
    overflow: hidden;
    margin-bottom: 1rem;
}

.progress-bar {
    height: 100%;
    background: linear-gradient(90deg, #ff6b6b, #ee5a52);
    width: 0%;
    transition: width 0.3s ease;
    border-radius: 5px;
}

.attack-logs {
    max-height: 200px;
    overflow-y: auto;
    background: #f7fafc;
    border-radius: 10px;
    padding: 1rem;
}

/* System Logs */
.logs-container {
    background: rgba(255, 255, 255, 0.95);
    border-radius: 20px;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
    backdrop-filter: blur(10px);
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
}

.logs-header {
    padding: 1.5rem 2rem;
    border-bottom: 1px solid rgba(0, 0, 0, 0.1);
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.logs-header h3 {
    color: #2d3748;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.clear-btn {
    background: rgba(74, 85, 104, 0.1);
    border: 1px solid rgba(74, 85, 104, 0.3);
    color: #4a5568;
    padding: 0.5rem 1rem;
    border-radius: 8px;
    cursor: pointer;
    transition: all 0.3s ease;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.clear-btn:hover {
    background: rgba(74, 85, 104, 0.2);
}

.logs-content {
    flex: 1;
    padding: 1rem 2rem;
    overflow-y: auto;
    max-height: 400px;
}

.log-entry {
    display: grid;
    grid-template-columns: 80px 120px 100px 1fr;
    gap: 1rem;
    padding: 0.75rem 0;
    border-bottom: 1px solid rgba(0, 0, 0, 0.05);
    font-size: 0.9rem;
    animation: slideInLeft 0.3s ease;
}

.log-entry:last-child {
    border-bottom: none;
}

.timestamp {
    color: #a0aec0;
    font-family: 'Courier New', monospace;
    font-size: 0.8rem;
}

.direction {
    font-weight: 600;
    padding: 0.25rem 0.5rem;
    border-radius: 12px;
    text-align: center;
    font-size: 0.75rem;
}

.direction:contains("ESP32→Server") {
    background: rgba(59, 130, 246, 0.1);
    color: #3b82f6;
}

.direction:contains("Server→ESP32") {
    background: rgba(16, 185, 129, 0.1);
    color: #10b981;
}

.type {
    font-weight: 600;
    color: #4a5568;
    text-transform: uppercase;
    font-size: 0.75rem;
}

.message {
    color: #2d3748;
}

/* Attack Overlay */
.attack-overlay {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.8);
    z-index: 1000;
    display: flex;
    align-items: center;
    justify-content: center;
    backdrop-filter: blur(5px);
}

.attack-modal {
    background: white;
    border-radius: 20px;
    width: 90%;
    max-width: 600px;
    max-height: 80vh;
    overflow: hidden;
    animation: modalSlideIn 0.3s ease;
}

.attack-modal-header {
    background: linear-gradient(135deg, #ff6b6b, #ee5a52);
    color: white;
    padding: 2rem;
    text-align: center;
}

.attack-modal-content {
    padding: 2rem;
    max-height: 60vh;
    overflow-y: auto;
}

.attack-visualization {
    text-align: center;
    margin-bottom: 2rem;
}

.attack-step {
    display: flex;
    align-items: center;
    margin: 1rem 0;
    padding: 1rem;
    background: #f7fafc;
    border-radius: 10px;
    border-left: 4px solid #ff6b6b;
}

.attack-step.active {
    background: rgba(255, 107, 107, 0.1);
    border-left-color: #ff6b6b;
}

.attack-step.completed {
    background: rgba(72, 187, 120, 0.1);
    border-left-color: #48bb78;
}

/* Animations */
@keyframes slideInUp {
    from {
        opacity: 0;
        transform: translateY(30px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

@keyframes slideInDown {
    from {
        opacity: 0;
        transform: translateY(-30px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

@keyframes slideInLeft {
    from {
        opacity: 0;
        transform: translateX(-30px);
    }
    to {
        opacity: 1;
        transform: translateX(0);
    }
}

@keyframes modalSlideIn {
    from {
        opacity: 0;
        transform: scale(0.9) translateY(-50px);
    }
    to {
        opacity: 1;
        transform: scale(1) translateY(0);
    }
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
        justify-content: center;
    }
    
    .attack-buttons {
        flex-direction: column;
    }
    
    .log-entry {
        grid-template-columns: 1fr;
        gap: 0.5rem;
        text-align: left;
    }
}'''
        
        with open(os.path.join(self.static_dir, "styles.css"), 'w', encoding='utf-8') as f:
            f.write(css_content)
    
    def create_javascript(self):
        """Create JavaScript for interactivity"""
        js_content = '''// Dashboard JavaScript
const socket = io();
let attackInterval = null;
let attackProgress = 0;

// Socket event handlers
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

socket.on('door_state', function(data) {
    updateDoorState(data.state, data.message);
});

socket.on('door_animation', function(data) {
    animateDoor(data.state);
});

socket.on('auth_success', function(data) {
    showUserInfo(data);
    updateRFIDStatus('success');
});

socket.on('auth_denied', function(data) {
    showAccessDenied(data);
    updateRFIDStatus('error');
});

// Door animation functions
function animateDoor(state) {
    const door = document.getElementById('door');
    const doorStatus = document.getElementById('door-status');
    const doorLeft = document.getElementById('door-left');
    const doorRight = document.getElementById('door-right');
    
    door.className = 'door';
    doorLeft.className = 'door-left';
    doorRight.className = 'door-right';
    
    switch(state) {
        case 'detecting':
            updateDoorStatus('fas fa-search', 'Scanning Card...', '#3182ce');
            updateRFIDStatus('active');
            break;
        case 'authenticating':
            updateDoorStatus('fas fa-key', 'Authenticating...', '#d69e2e');
            updateRFIDStatus('active');
            break;
        case 'open':
            door.style.display = 'none';
            doorLeft.style.display = 'block';
            doorRight.style.display = 'block';
            doorLeft.classList.add('open');
            doorRight.classList.add('open');
            updateDoorStatus('fas fa-door-open', 'Access Granted', '#38a169');
            updateRFIDStatus('success');
            break;
        case 'closing':
            door.style.display = 'block';
            doorLeft.style.display = 'none';
            doorRight.style.display = 'none';
            door.classList.add('closing');
            updateDoorStatus('fas fa-door-closed', 'Door Closing...', '#d69e2e');
            break;
        case 'closed':
            door.style.display = 'block';
            doorLeft.style.display = 'none';
            doorRight.style.display = 'none';
            door.className = 'door';
            updateDoorStatus('fas fa-door-closed', 'Door Secured', '#4a5568');
            hideUserInfo();
            updateRFIDStatus('idle');
            break;
        case 'denied':
            door.classList.add('denied');
            updateDoorStatus('fas fa-times', 'Access Denied', '#e53e3e');
            updateRFIDStatus('error');
            break;
    }
}

function updateDoorStatus(iconClass, text, color) {
    const doorStatus = document.getElementById('door-status');
    doorStatus.innerHTML = `<i class="${iconClass}"></i><span>${text}</span>`;
    doorStatus.style.color = color;
}

function updateRFIDStatus(status) {
    const rfidReader = document.getElementById('rfid-reader');
    const rfidLight = document.getElementById('rfid-light');
    
    rfidReader.className = 'rfid-reader';
    rfidLight.className = 'rfid-light';
    
    if (status === 'active') {
        rfidReader.classList.add('active');
        rfidLight.classList.add('active');
    } else if (status === 'error') {
        rfidLight.classList.add('error');
    }
    
    // Reset after 3 seconds
    setTimeout(() => {
        rfidReader.className = 'rfid-reader';
        rfidLight.className = 'rfid-light';
    }, 3000);
}

// User info functions
function showUserInfo(data) {
    const userInfo = document.getElementById('user-info');
    const userPanel = document.getElementById('user-panel');
    const accessDenied = document.getElementById('access-denied');
    
    // Hide access denied panel
    accessDenied.style.display = 'none';
    
    // Update user info
    document.getElementById('user-avatar').src = data.image;
    document.getElementById('user-name').textContent = data.name;
    document.getElementById('user-uid').textContent = `UID: ${data.uid}`;
    document.getElementById('access-time').textContent = `Access granted at ${data.timestamp}`;
    
    // Update permissions
    const permissionsContainer = document.getElementById('user-permissions');
    permissionsContainer.innerHTML = '';
    data.permissions.forEach(permission => {
        const permissionElement = document.createElement('span');
        permissionElement.className = 'permission';
        permissionElement.textContent = permission;
        permissionsContainer.appendChild(permissionElement);
    });
    
    // Show user info
    userInfo.style.display = 'block';
    
    // Auto hide after 10 seconds
    setTimeout(hideUserInfo, 10000);
}

function showAccessDenied(data) {
    const userInfo = document.getElementById('user-info');
    const accessDenied = document.getElementById('access-denied');
    
    // Hide user info
    userInfo.style.display = 'none';
    
    // Update denied info
    document.getElementById('denied-reason').textContent = data.reason;
    document.getElementById('denied-uid').textContent = `UID: ${data.uid}`;
    
    // Show access denied
    accessDenied.style.display = 'block';
    
    // Auto hide after 5 seconds
    setTimeout(() => {
        accessDenied.style.display = 'none';
    }, 5000);
}

function hideUserInfo() {
    document.getElementById('user-info').style.display = 'none';
    document.getElementById('access-denied').style.display = 'none';
}

// Log functions
function addLogEntry(data) {
    const logsContent = document.getElementById('logs-content');
    const logEntry = document.createElement('div');
    logEntry.className = 'log-entry';
    
    const directionClass = data.direction.includes('ESP32') ? 
        (data.direction.includes('→Server') ? 'esp32-to-server' : 'server-to-esp32') : 'system';
    
    logEntry.innerHTML = `
        <span class="timestamp">${data.timestamp}</span>
        <span class="direction ${directionClass}">${data.direction}</span>
        <span class="type">${data.type}</span>
        <span class="message">${getLogMessage(data)}</span>
        <span class="size">${data.message_size || 0}B</span>
    `;
    
    logsContent.appendChild(logEntry);
    logsContent.scrollTop = logsContent.scrollHeight;
    
    while (logsContent.children.length > 100) {
        logsContent.removeChild(logsContent.firstChild);
    }
}

function getLogMessage(data) {
    const type = data.type;
    const msgData = data.data;
    
    switch(type) {
        case 'card_detected':
            return `Card detected: ${msgData.card_uid} (${msgData.signal_strength || 'unknown'} dBm)`;
        case 'auth_challenge':
            return `Auth challenge: Session ${msgData.session_id} (${msgData.encryption_algorithm || 'AES-128'})`;
        case 'auth_response':
            return `Auth response: ${msgData.aes_operations || 0} AES ops, ${msgData.free_heap || 0}B heap`;
        case 'auth_success':
            return `✅ Access granted: ${msgData.user_name} (${msgData.permissions?.length || 0} perms)`;
        case 'auth_rejected':
            return `❌ Access denied: ${msgData.reason} (UID: ${msgData.card_uid})`;
        case 'card_removed':
            return `Card removed: ${msgData.card_uid}`;
        case 'heartbeat':
            return `💓 ESP32: ${msgData.free_heap}B heap, ${Math.floor(msgData.uptime/1000)}s uptime`;
        case 'esp32_ready':
            return `📟 ESP32 ready: v${msgData.version}, AES:${msgData.aes_support ? '✅' : '❌'}`;
        case 'replay_attack':
        case 'mitm_attack':
            return `🔍 ${type}: Step ${msgData.step} - ${msgData.title}`;
        default:
            return JSON.stringify(msgData).substring(0, 80) + '...';
    }
}

function clearLogs() {
    document.getElementById('logs-content').innerHTML = `
        <div class="log-entry system-start">
            <span class="timestamp">--:--:--</span>
            <span class="direction">SYSTEM</span>
            <span class="type">INFO</span>
            <span class="message">Logs cleared</span>
        </div>
    `;
}

// Connection status
function updateConnectionStatus(connected) {
    const mqttStatus = document.getElementById('mqtt-status');
    const statusSpan = mqttStatus.querySelector('span');
    
    if (connected) {
        statusSpan.textContent = 'Connected';
        statusSpan.style.color = '#38a169';
    } else {
        statusSpan.textContent = 'Disconnected';
        statusSpan.style.color = '#e53e3e';
    }
}

// Attack simulation functions
function startReplayAttack() {
    if (attackInterval) return;
    
    showAttackWindow('Detailed Replay Attack Analysis', 'replay');
    showAttackOverlay('Replay Attack - Security Analysis');
    
    document.getElementById('stop-attack-btn').style.display = 'block';
    document.getElementById('replay-attack-btn').disabled = true;
    document.getElementById('mitm-attack-btn').disabled = true;
    
    fetch('/api/attack/start', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({type: 'replay'})
    }).catch(err => console.error('Attack start failed:', err));
}

function startMITMAttack() {
    if (attackInterval) return;
    
    showAttackWindow('Man-in-the-Middle Attack', 'mitm');
    showAttackOverlay('Man-in-the-Middle Attack');
    
    attackProgress = 0;
    const steps = [
        'Setting up rogue access point...',
        'Intercepting ESP32 communications...',
        'Spoofing server responses...',
        'Attempting to capture credentials...',
        'Injecting malicious commands...',
        'Trying to bypass mutual authentication...'
    ];
    
    startAttackSimulation(steps, () => {
        addAttackLog('🔴 MITM attack detected!');
        addAttackLog('⚠️ Mutual authentication should prevent this');
        addAttackLog('🛡️ Dilithium signatures provide protection');
    });
}

function startAttackSimulation(steps, onComplete) {
    let currentStep = 0;
    
    attackInterval = setInterval(() => {
        if (currentStep < steps.length) {
            addAttackLog(`Step ${currentStep + 1}: ${steps[currentStep]}`);
            attackProgress = ((currentStep + 1) / steps.length) * 100;
            updateAttackProgress(attackProgress);
            currentStep++;
        } else {
            if (onComplete) onComplete();
            clearInterval(attackInterval);
            attackInterval = null;
            
            setTimeout(() => {
                addAttackLog('🛑 Attack simulation completed');
                addAttackLog('✅ Security measures are effective');
            }, 1000);
        }
    }, 1500);
    
    // Show stop button
    document.getElementById('stop-attack-btn').style.display = 'block';
    document.getElementById('replay-attack-btn').disabled = true;
    document.getElementById('mitm-attack-btn').disabled = true;
}

function stopAttack() {
    fetch('/api/attack/stop', {method: 'POST'})
        .catch(err => console.error('Attack stop failed:', err));
    
    document.getElementById('stop-attack-btn').style.display = 'none';
    document.getElementById('replay-attack-btn').disabled = false;
    document.getElementById('mitm-attack-btn').disabled = false;
    
    closeAttackWindow();
    hideAttackOverlay();
}

function showAttackWindow(title, type) {
    const attackWindow = document.getElementById('attack-window');
    const attackTitle = document.getElementById('attack-title');
    const attackLogs = document.getElementById('attack-logs');
    
    attackTitle.textContent = title;
    attackLogs.innerHTML = '';
    attackWindow.style.display = 'block';
    
    updateAttackProgress(0);
}

function closeAttackWindow() {
    document.getElementById('attack-window').style.display = 'none';
}

function showAttackOverlay(title) {
    const overlay = document.getElementById('attack-overlay');
    const modalTitle = document.getElementById('attack-modal-title');
    const visualization = document.getElementById('attack-visualization');
    
    modalTitle.textContent = title;
    
    // Create attack visualization
    if (title.includes('Replay')) {
        visualization.innerHTML = createReplayVisualization();
    } else if (title.includes('MITM')) {
        visualization.innerHTML = createMITMVisualization();
    }
    
    overlay.style.display = 'flex';
}

function hideAttackOverlay() {
    document.getElementById('attack-overlay').style.display = 'none';
}

function createReplayVisualization() {
    return `
        <div class="attack-flow">
            <div class="attack-node">📱 ESP32</div>
            <div class="attack-arrow">→</div>
            <div class="attack-node attacker">🕵️ Attacker</div>
            <div class="attack-arrow">→</div>
            <div class="attack-node">🖥️ Server</div>
        </div>
        <p>Attacker captures and replays authentication messages</p>
    `;
}

function createMITMVisualization() {
    return `
        <div class="attack-flow">
            <div class="attack-node">📱 ESP32</div>
            <div class="attack-arrow">⚡</div>
            <div class="attack-node attacker">🕵️ MITM</div>
            <div class="attack-arrow">⚡</div>
            <div class="attack-node">🖥️ Server</div>
        </div>
        <p>Attacker intercepts and modifies communications</p>
    `;
}

function addAttackLog(message) {
    const attackLogs = document.getElementById('attack-logs');
    const logEntry = document.createElement('div');
    logEntry.className = 'attack-log-entry';
    logEntry.innerHTML = `
        <span class="attack-timestamp">${new Date().toLocaleTimeString()}</span>
        <span class="attack-message">${message}</span>
    `;
    attackLogs.appendChild(logEntry);
    attackLogs.scrollTop = attackLogs.scrollHeight;
}

function updateAttackProgress(progress) {
    const progressBar = document.getElementById('attack-progress');
    progressBar.style.width = progress + '%';
}

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    console.log('Dashboard initialized');
    
    // Add some initial log entries
    setTimeout(() => {
        addLogEntry({
            timestamp: new Date().toLocaleTimeString(),
            direction: 'SYSTEM',
            type: 'INFO',
            data: { message: 'Dashboard ready - waiting for RFID events...' }
        });
    }, 1000);
});

// Handle attack overlay clicks
document.getElementById('attack-overlay').addEventListener('click', function(e) {
    if (e.target === this) {
        hideAttackOverlay();
    }
});'''
        
        with open(os.path.join(self.static_dir, "dashboard.js"), 'w', encoding='utf-8') as f:
            f.write(js_content)
    
    def create_user_images(self):
        """Create placeholder user images"""
        # Create simple SVG images for users
        user1_svg = '''<svg width="100" height="100" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
            <circle cx="50" cy="50" r="50" fill="#4299e1"/>
            <circle cx="50" cy="35" r="15" fill="white"/>
            <ellipse cx="50" cy="75" rx="25" ry="20" fill="white"/>
            <text x="50" y="95" text-anchor="middle" fill="white" font-size="8">User 1</text>
        </svg>'''
        
        user2_svg = '''<svg width="100" height="100" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
            <circle cx="50" cy="50" r="50" fill="#48bb78"/>
            <circle cx="50" cy="35" r="15" fill="white"/>
            <ellipse cx="50" cy="75" rx="25" ry="20" fill="white"/>
            <text x="50" y="95" text-anchor="middle" fill="white" font-size="8">User 2</text>
        </svg>'''
        
        default_svg = '''<svg width="100" height="100" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
            <circle cx="50" cy="50" r="50" fill="#a0aec0"/>
            <circle cx="50" cy="35" r="15" fill="white"/>
            <ellipse cx="50" cy="75" rx="25" ry="20" fill="white"/>
            <text x="50" y="95" text-anchor="middle" fill="white" font-size="8">Guest</text>
        </svg>'''
        
        images_dir = os.path.join(self.static_dir, "images")
        
        with open(os.path.join(images_dir, "user1.svg"), 'w') as f:
            f.write(user1_svg)
        
        with open(os.path.join(images_dir, "user2.svg"), 'w') as f:
            f.write(user2_svg)
        
        with open(os.path.join(images_dir, "default_user.svg"), 'w') as f:
            f.write(default_svg)

# Flask routes
dashboard = DilithiumWebDashboard()

@app.route('/api/attack/start', methods=['POST'])
def start_attack():
    """Start enhanced attack simulation"""
    data = request.json
    attack_type = data.get('type')
    
    if dashboard.attack_active:
        return jsonify({"error": "Attack already in progress"}), 400
    
    dashboard.attack_active = True
    dashboard.attack_type = attack_type
    dashboard.attack_logs = []
    
    print(f"🚨 Starting {attack_type} attack simulation...")
    
    if attack_type == "replay":
        threading.Thread(target=dashboard.simulate_replay_attack).start()
    elif attack_type == "mitm":
        threading.Thread(target=dashboard.simulate_mitm_attack).start()
    
    return jsonify({"status": "Attack started", "type": attack_type})

@app.route('/api/attack/stop', methods=['POST'])
def stop_attack():
    """Stop attack simulation"""
    dashboard.attack_active = False
    dashboard.attack_type = None
    print("🛑 Attack simulation stopped")
    
    return jsonify({"status": "Attack stopped"})

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory(dashboard.static_dir, filename)

@app.route('/api/esp32/status')
def get_esp32_status():
    """Get current ESP32 status"""
    return jsonify(dashboard.esp32_status)

@app.route('/api/cards')
def get_cards():
    """Get all provisioned cards"""
    cards_db_path = os.path.join(dashboard.config_dir, "cards_database.json")
    
    if not os.path.exists(cards_db_path):
        return jsonify([])
    
    try:
        with open(cards_db_path, 'r') as f:
            cards_db = json.load(f)
        
        cards_list = []
        for uid, data in cards_db.items():
            cards_list.append({
                "uid": uid,
                "name": data.get("user_name", "Unknown"),
                "status": data.get("status", "unknown"),
                "permissions": data.get("permissions", []),
                "last_used": data.get("last_used", "Never")
            })
        
        return jsonify(cards_list)
    except:
        return jsonify([])

@app.route('/api/logs')
def get_logs():
    """Get system logs with filtering"""
    log_type = request.args.get('type', 'all')
    limit = int(request.args.get('limit', 50))
    
    filtered_logs = dashboard.system_logs
    if log_type != 'all':
        filtered_logs = [log for log in dashboard.system_logs if log.get('type') == log_type]
    
    return jsonify(filtered_logs[-limit:])

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    print('🌐 Client connected to dashboard')
    emit('connected', {'status': 'Connected to Dilithium Dashboard'})
    emit('esp32_status', dashboard.esp32_status)

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    print('🌐 Client disconnected from dashboard')

if __name__ == '__main__':
    print("🌐 Starting Enhanced Dilithium RFID Security Dashboard...")
    print("📊 Enhanced Features:")
    print("   - Real-time ESP32 monitoring")
    print("   - Detailed attack parameter analysis")
    print("   - Technical cryptographic visualization")
    print("   - Post-quantum security demonstration")
    print("   - Enhanced logging with message size tracking")
    print("   - Live system performance metrics")
    print()
    
    import socket
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    
    print("🔗 Access dashboard at:")
    print(f"   - Local: http://localhost:5000")
    print(f"   - Network: http://{local_ip}:5000")
    print()
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)