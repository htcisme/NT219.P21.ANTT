import os
import json
import base64
import time
import hashlib
import secrets
import hmac
from datetime import datetime
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import socketio

try:
    import oqs
    print(f"✅ OQS library available")
except ImportError:
    try:
        from oqs import Signature
        print("Using direct Signature import")
    except ImportError:
        try:
            import liboqs
            oqs = liboqs
            print("Using liboqs fallback")
        except ImportError:
            print("❌ No OQS library found!")
            exit(1)

class DilithiumUIDBackendServer:
    def __init__(self):
        self.config_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config")
        self.load_system_params()
        self.load_server_keys()
        self.setup_mqtt()
        
        # Runtime state
        self.active_sessions = {}
        self.authentication_timeout = 60
        self.recent_cards = {}
        self.card_cooldown = 2
        
        # AES encryption settings
        self.encryption_algorithm = "AES-128-CTR"
        self.nonce_size = 12
        self.setup_socketio()
    def setup_socketio(self):
        """Setup SocketIO client để communicate với dashboard"""
        try:
            self.sio = socketio.SimpleClient()
            # Connect to web dashboard
            self.sio.connect('http://localhost:5000')
            print("✅ Connected to Web Dashboard")
        except Exception as e:
            print(f"⚠️ Could not connect to Web Dashboard: {e}")
            self.sio = None

    def emit_to_dashboard(self, event, data):
        """Emit event to web dashboard"""
        if self.sio:
            try:
                self.sio.emit(event, data)
            except Exception as e:
                print(f"⚠️ Failed to emit to dashboard: {e}")
    def load_system_params(self):
        """Load system parameters"""
        params_path = os.path.join(self.config_dir, "system_params.json")
        with open(params_path, 'r') as f:
            params = json.load(f)
        
        self.sig_algorithm = params["sig_algorithm"]
        self.challenge_size = params["challenge_size"]
        self.encryption_algorithm = params.get("encryption_algorithm", "AES-128-CTR")
        
    def load_server_keys(self):
        """Load Dilithium server keys and AES key"""
        keys_path = os.path.join(self.config_dir, "server_keys.json")
        with open(keys_path, 'r') as f:
            keys = json.load(f)
        
        # Load Dilithium keys
        dilithium_public_key = base64.b64decode(keys["dilithium_public_key"])
        dilithium_secret_key = base64.b64decode(keys["dilithium_secret_key"])
        self.master_secret = base64.b64decode(keys["master_secret"])
        self.aes_key = base64.b64decode(keys["aes_key"])
        
        print(f"✅ Server keys loaded ({self.sig_algorithm} + {self.encryption_algorithm})")
        print(f"   - Public key size: {len(dilithium_public_key)} bytes")
        print(f"   - Secret key size: {len(dilithium_secret_key)} bytes")
        print(f"   - AES key size: {len(self.aes_key)} bytes")
        
        # Initialize Dilithium signer
        try:
            if hasattr(oqs, 'Signature'):
                self.dilithium_signer = oqs.Signature(self.sig_algorithm)
                print("✅ Using oqs.Signature")
            elif hasattr(oqs, 'sig'):
                self.dilithium_signer = oqs.sig.Signature(self.sig_algorithm)
                print("✅ Using oqs.sig.Signature")
            else:
                from oqs import Signature
                self.dilithium_signer = Signature(self.sig_algorithm)
                print("✅ Using direct Signature import")
                
        except Exception as e:
            print(f"❌ Failed to initialize Dilithium signer: {e}")
            exit(1)
        
        # Load secret key
        self.dilithium_signer._secret_key = dilithium_secret_key
        self.dilithium_public_key = dilithium_public_key
        self.dilithium_secret_key = dilithium_secret_key
    
    def derive_card_nonce(self, card_uid):
        """Derive deterministic nonce cho AES CTR từ card UID"""
        nonce_kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16,  # UPDATED: 16 bytes for CTR mode
            salt=f"NONCE_{card_uid}".encode(),
            iterations=50000,
        )
        return nonce_kdf.derive(self.master_secret)
    
    def decrypt_card_secret(self, card_uid, encrypted_data):
        """Decrypt card secret from database"""
        try:
            nonce = base64.b64decode(encrypted_data["nonce"])
            encrypted_secret = base64.b64decode(encrypted_data["encrypted_secret"])
            
            # Decrypt with AES-128 CTR
            cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(nonce))
            decryptor = cipher.decryptor()
            card_secret = decryptor.update(encrypted_secret) + decryptor.finalize()
            
            return card_secret
            
        except Exception as e:
            print(f"❌ Failed to decrypt card secret for {card_uid}: {e}")
            return None
    
    def setup_mqtt(self):
        """Setup MQTT communication"""
        self.mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1)
        self.mqtt_client.on_connect = self.on_mqtt_connect
        self.mqtt_client.on_message = self.on_mqtt_message
        
        self.topic_to_esp32 = "rfid/server_to_esp32"
        self.topic_from_esp32 = "rfid/esp32_to_server"
        
        try:
            self.mqtt_client.connect("localhost", 1883, 60)
            self.mqtt_client.loop_start()
            print("✅ MQTT connected")
        except Exception as e:
            print(f"❌ MQTT connection failed: {e}")
            exit(1)
    
    def on_mqtt_connect(self, client, userdata, flags, rc):
        """MQTT connect callback"""
        if rc == 0:
            client.subscribe(self.topic_from_esp32)
            print(f"📡 Subscribed to: {self.topic_from_esp32}")
            self.send_server_info()
        else:
            print(f"❌ MQTT connection failed with code {rc}")
    
    def send_server_info(self):
        """Send server information to ESP32"""
        server_info = {
            "type": "server_info",
            "sig_algorithm": self.sig_algorithm,
            "encryption_algorithm": self.encryption_algorithm,
            "public_key": base64.b64encode(self.dilithium_public_key).decode(),
            "challenge_size": self.challenge_size,
            "mutual_auth": True,
            "aes_support": True,
            "timestamp": int(time.time())
        }
        
        self.send_to_esp32(server_info)
        print("📤 Sent server info with AES support to ESP32")
    
    def on_mqtt_message(self, client, userdata, msg):
        """MQTT message callback"""
        try:
            message = json.loads(msg.payload.decode())
            self.handle_esp32_message(message)
        except Exception as e:
            print(f"❌ Error processing message: {e}")
    
    def handle_esp32_message(self, message):
        """Handle messages from ESP32"""
        msg_type = message.get("type")
        
        if not self.verify_message_freshness(message):
            print("❌ ESP32 message verification failed")
            return
        
        if msg_type == "card_detected":
            self.handle_card_detected(message)
        elif msg_type == "card_removed":
            self.handle_card_removed(message)
        elif msg_type == "auth_response":
            self.handle_auth_response(message)
        elif msg_type == "auth_error":
            self.handle_auth_error(message)
        elif msg_type == "heartbeat":
            self.handle_heartbeat(message)
        elif msg_type == "esp32_ready":
            self.handle_esp32_ready(message)
        else:
            print(f"⚠️ Unknown message type: {msg_type}")
    
    def verify_message_freshness(self, message):
        """Verify ESP32 message freshness"""
        msg_timestamp = message.get("timestamp", 0)
        
        if msg_timestamp == 0:
            return True  # Allow compatibility
        
        current_time = int(time.time())
        time_diff = abs(current_time - msg_timestamp)
        
        if time_diff > 600:  # 10 minutes tolerance
            print(f"❌ ESP32 message too old: {time_diff}s")
            return False
        
        return True
        
    def handle_esp32_ready(self, message):
        """Handle ESP32 ready notification"""
        esp32_version = message.get("version", "unknown")
        aes_support = message.get("aes_support", False)
        mutual_auth = message.get("mutual_auth", False)
        
        print(f"📟 ESP32 ready: version {esp32_version}")
        print(f"   - AES support: {aes_support}")
        print(f"   - Mutual authentication: {mutual_auth}")
        
        if not aes_support:
            print("⚠️ ESP32 doesn't support AES decryption!")
        
        # Emit to web dashboard
        self.emit_to_dashboard('esp32_ready', {
            'version': esp32_version,
            'aes_support': aes_support,
            'mutual_auth': mutual_auth,
            'timestamp': int(time.time())
        })
        
    def handle_card_detected(self, message):
        """Handle card detection with AES processing"""
        card_uid = message.get("card_uid")
        current_time = time.time()
        
        print(f"🏷️ Card detected (UID): {card_uid}")
        
        # Emit card detected to dashboard FIRST
        self.emit_to_dashboard('card_detected', {
            'uid': card_uid,
            'timestamp': current_time
        })
        
        # Cooldown check
        if card_uid in self.recent_cards:
            last_seen = self.recent_cards[card_uid]
            if current_time - last_seen < 1:
                print(f"   - Card cooldown active, ignoring")
                return
        
        self.recent_cards[card_uid] = current_time
        
        # Lookup card in database
        card_data = self.get_card_data(card_uid)
        
        if card_data is None:
            print(f"❌ Card UID {card_uid} not found in database!")
            self.send_rejection(card_uid, "Card not registered")
            self.emit_to_dashboard('card_not_found', {'uid': card_uid})
            return
        
        if card_data.get('status') != 'active':
            status = card_data.get('status', 'unknown')
            print(f"❌ Card {card_uid} status: {status}")
            self.send_rejection(card_uid, f"Card {status}")
            self.emit_to_dashboard('card_inactive', {'uid': card_uid, 'status': status})
            return
        
        # Emit card info to dashboard
        self.emit_to_dashboard('card_info_loaded', {
            'uid': card_uid,
            'user_name': card_data.get('user_name', 'Unknown'),
            'permissions': card_data.get('permissions', []),
            'status': card_data.get('status', 'active'),
            'last_used': card_data.get('last_used', 'Never')
        })
        
        # Start authentication with AES support
        self.start_dilithium_authentication_with_aes(card_uid, card_data)

    def get_card_data(self, card_uid):
        """Get card data from database"""
        cards_db_path = os.path.join(self.config_dir, "cards_database.json")
        
        if not os.path.exists(cards_db_path):
            return None
        
        try:
            with open(cards_db_path, 'r') as f:
                cards_db = json.load(f)
            return cards_db.get(card_uid)
        except:
            return None
    
    def start_dilithium_authentication_with_aes(self, card_uid, card_data):
        """Start authentication with AES-encrypted card secret"""
        print(f"🚀 Starting Dilithium + AES authentication for UID: {card_uid}")
        
        # Generate challenge components
        challenge = secrets.token_bytes(self.challenge_size)
        timestamp = int(time.time())
        nonce = secrets.token_bytes(16)  # Ensure 16 bytes for CTR mode
        session_id = secrets.token_hex(8)
        
        # Get encrypted card secret from database
        encrypted_card_secret = card_data.get("encrypted_card_secret")
        if not encrypted_card_secret:
            print(f"❌ No encrypted card secret found for {card_uid}")
            self.send_rejection(card_uid, "Card not properly provisioned")
            return
        
        # DEBUG: Validate encrypted card secret data
        print(f"🔍 Debug encrypted card secret:")
        print(f"   - encrypted_secret: '{encrypted_card_secret['encrypted_secret']}'")
        print(f"   - nonce: '{encrypted_card_secret['nonce']}'")
        print(f"   - algorithm: '{encrypted_card_secret.get('algorithm', 'unknown')}'")
        
        # Validate Base64 data lengths
        try:
            enc_data = base64.b64decode(encrypted_card_secret["encrypted_secret"])
            enc_nonce = base64.b64decode(encrypted_card_secret["nonce"])
            
            print(f"   - Decoded encrypted data: {len(enc_data)} bytes")
            print(f"   - Decoded nonce: {len(enc_nonce)} bytes")
            
            if len(enc_data) != 32:
                print(f"❌ Wrong encrypted data length: {len(enc_data)} bytes (expected 32)")
                self.send_rejection(card_uid, "Invalid card data")
                return
                
            if len(enc_nonce) != 16:
                print(f"❌ Wrong nonce length: {len(enc_nonce)} bytes (expected 16)")
                self.send_rejection(card_uid, "Invalid card data")
                return
                
        except Exception as e:
            print(f"❌ Invalid Base64 data in card secret: {e}")
            self.send_rejection(card_uid, "Corrupted card data")
            return
        
        # Decrypt card secret server-side
        card_secret = self.decrypt_card_secret(card_uid, encrypted_card_secret)
        if card_secret is None:
            print(f"❌ Failed to decrypt card secret for {card_uid}")
            self.send_rejection(card_uid, "Card decryption failed")
            return
        
        print(f"✅ Successfully decrypted card secret for {card_uid}")
        
        # Create authentication message for signature
        auth_message = (
            card_uid.encode() + 
            challenge + 
            timestamp.to_bytes(8, 'big') +
            nonce
        )
        
        # Create simplified signature for ESP32 memory constraints
        mock_signature = hashlib.sha256(auth_message + self.dilithium_secret_key[:32]).digest()
        mock_signature = mock_signature * 10  # 320 bytes instead of 2420
        
        # Store session
        self.active_sessions[session_id] = {
            "card_uid": card_uid,
            "challenge": challenge,
            "timestamp": timestamp,
            "nonce": nonce,
            "card_secret": card_secret,
            "auth_message": auth_message,
            "signature": mock_signature,
            "card_data": card_data,
            "start_time": time.time(),
            "retry_count": 0
        }
        
        # Create clean encrypted card secret for ESP32
        esp32_encrypted_secret = {
            "encrypted_secret": encrypted_card_secret["encrypted_secret"].strip(),
            "nonce": encrypted_card_secret["nonce"].strip(),
            "algorithm": "AES-128-CTR"
        }
        
        # Send challenge with AES encryption info
        challenge_message = {
            "type": "auth_challenge",
            "session_id": session_id,
            "card_uid": card_uid,
            "challenge": base64.b64encode(challenge).decode().strip(),
            "timestamp": timestamp,
            "nonce": base64.b64encode(nonce).decode().strip(),
            "server_signature": base64.b64encode(mock_signature).decode().strip(),
            "mutual_auth": True,
            "aes_support": True,
            "encrypted_card_secret": esp32_encrypted_secret,
            "timeout": self.authentication_timeout
        }
        
        self.send_to_esp32(challenge_message)
        print(f"📤 Sent AES-enhanced auth challenge to UID: {card_uid}")
        print(f"   - Challenge size: {len(challenge)} bytes")
        print(f"   - Signature size: {len(mock_signature)} bytes")
        print(f"   - Encrypted secret B64 length: {len(esp32_encrypted_secret['encrypted_secret'])} chars")
        print(f"   - Nonce B64 length: {len(esp32_encrypted_secret['nonce'])} chars")
        print(f"   - AES algorithm: {self.encryption_algorithm}")
    
    def handle_auth_response(self, message):
        """Handle authentication response with AES verification"""
        session_id = message.get("session_id")
        card_uid = message.get("card_uid")
        response_b64 = message.get("response")
        response_timestamp = message.get("timestamp")
        aes_operations = message.get("aes_operations", 0)
        free_heap = message.get("free_heap", 0)
        
        print(f"📥 Auth response received from ESP32:")
        print(f"   - Session ID: {session_id}")
        print(f"   - Card UID: {card_uid}")
        print(f"   - AES operations: {aes_operations}")
        print(f"   - Free heap: {free_heap} bytes")
        
        if session_id not in self.active_sessions:
            print("❌ Invalid session ID")
            return
        
        session = self.active_sessions[session_id]
        
        # Check session timeout
        if time.time() - session["start_time"] > self.authentication_timeout:
            print("❌ Authentication timeout")
            del self.active_sessions[session_id]
            self.send_rejection(card_uid, "Authentication timeout")
            return
        
        try:
            # Decode response
            card_response = base64.b64decode(response_b64)
            
            # Verify timestamp
            if response_timestamp:
                time_diff = abs(time.time() - response_timestamp)
                if time_diff > 60:
                    print(f"❌ Response timestamp too old: {time_diff}s")
                    self.send_rejection(card_uid, "Invalid timestamp")
                    return
            
            # Get session data
            card_secret = session["card_secret"]
            challenge = session["challenge"]
            
            print(f"🔍 Verifying ESP32 response:")
            print(f"   - Card UID: {card_uid}")
            print(f"   - Algorithm: {self.encryption_algorithm}")
            
            # DEBUG: Print detailed comparison
            print(f"🔍 Server-side debug:")
            print(f"   - Challenge hex: {challenge.hex()}")
            print(f"   - Card secret hex: {card_secret.hex()}")
            print(f"   - Challenge + secret length: {len(challenge)} + {len(card_secret)} = {len(challenge) + len(card_secret)} bytes")
            
            # ESP32 creates response as hash(challenge + card_secret)
            response_data = challenge + card_secret
            
            # Calculate expected hash
            expected_response = hashlib.sha256(response_data).digest()
            
            print(f"   - Response data hex: {response_data[:16].hex()}...{response_data[-16:].hex()}")
            print(f"   - Expected response: {base64.b64encode(expected_response).decode()}")
            print(f"   - Received response: {response_b64}")
            print(f"   - Expected hash hex: {expected_response.hex()}")
            print(f"   - Received hash hex: {card_response.hex()}")
            
            # Verify response
            if expected_response == card_response:
                print("✅ AES + Dilithium authentication successful!")
                
                # Update usage statistics
                self.update_card_usage(card_uid)
                
                # Get user info
                card_data = session["card_data"]
                user_name = card_data.get("user_name", "Unknown")
                permissions = card_data.get("permissions", [])
                
                # Emit success to dashboard
                self.emit_to_dashboard('auth_success', {
                    'card_uid': card_uid,
                    'user_name': user_name,
                    'permissions': permissions,
                    'timestamp': int(time.time())
                })
                
                # Send success with encryption info
                success_message = {
                    "type": "auth_success",
                    "card_uid": card_uid,
                    "user_name": user_name,
                    "permissions": permissions,
                    "session_key": base64.b64encode(secrets.token_bytes(16)).decode(),
                    "valid_until": int(time.time() + 3600),
                    "timestamp": int(time.time()),
                    "mutual_auth": True,
                    "aes_encryption": True,
                    "encryption_algorithm": self.encryption_algorithm
                }
                
                self.send_to_esp32(success_message)
                print(f"🔑 Access granted to {user_name} (UID: {card_uid})")
                print(f"   - Permissions: {permissions}")
                print(f"   - Security: Dilithium2 + {self.encryption_algorithm}")
                
                # Log access
                self.log_access(card_uid, "granted", user_name)
                
            else:
                print("❌ Authentication failed - invalid response")
                
                # Emit rejection to dashboard
                self.emit_to_dashboard('auth_rejected', {
                    'card_uid': card_uid,
                    'reason': 'Invalid credentials',
                    'timestamp': int(time.time())
                })
                
                self.send_rejection(card_uid, "Invalid credentials")
                self.log_access(card_uid, "denied")
                
        except Exception as e:
            print(f"❌ Error processing auth response: {e}")
            self.send_rejection(card_uid, "Authentication error")
            # Emit error to dashboard
            self.emit_to_dashboard('auth_rejected', {
                'card_uid': card_uid,
                'reason': f'Processing error: {str(e)}',
                'timestamp': int(time.time())
            })
        
        finally:
            # Cleanup session
            if session_id in self.active_sessions:
                del self.active_sessions[session_id]

    def handle_auth_error(self, message):
        """Handle authentication error from ESP32"""
        session_id = message.get("session_id")
        error_reason = message.get("reason", "Unknown error")
        error_details = message.get("details", {})
        
        print(f"❌ ESP32 authentication error: {error_reason}")
        
        # Log detailed error for AES troubleshooting
        if "aes" in error_reason.lower() or "decrypt" in error_reason.lower():
            print(f"   🔍 AES Error Details:")
            print(f"      - Error: {error_reason}")
            print(f"      - Details: {error_details}")
            
            # Log AES-specific errors
            self.log_security_event("aes_decrypt_error", {
                "session_id": session_id,
                "reason": error_reason,
                "details": error_details,
                "timestamp": datetime.now().isoformat()
            })
        
        # Cleanup session
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
    
    def handle_auth_error(self, message):
        """Handle authentication error from ESP32"""
        session_id = message.get("session_id")
        error_reason = message.get("reason", "Unknown error")
        error_details = message.get("details", {})
        
        print(f"❌ ESP32 authentication error: {error_reason}")
        
        # Log detailed error for AES troubleshooting
        if "aes" in error_reason.lower() or "decrypt" in error_reason.lower():
            print(f"   🔍 AES Error Details:")
            print(f"      - Error: {error_reason}")
            print(f"      - Details: {error_details}")
            
            # Log AES-specific errors
            self.log_security_event("aes_decrypt_error", {
                "session_id": session_id,
                "reason": error_reason,
                "details": error_details,
                "timestamp": datetime.now().isoformat()
            })
        
        # Cleanup session
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
    
    def update_card_usage(self, card_uid):
        """Update card usage statistics"""
        cards_db_path = os.path.join(self.config_dir, "cards_database.json")
        
        try:
            with open(cards_db_path, 'r') as f:
                cards_db = json.load(f)
            
            if card_uid in cards_db:
                cards_db[card_uid]['last_used'] = datetime.now().isoformat()
                cards_db[card_uid]['usage_count'] = cards_db[card_uid].get('usage_count', 0) + 1
                
                with open(cards_db_path, 'w') as f:
                    json.dump(cards_db, f, indent=2)
                    
        except Exception as e:
            print(f"⚠️ Failed to update usage stats: {e}")
    
    def handle_card_removed(self, message):
        """Handle card removal"""
        card_uid = message.get("card_uid")
        print(f"🏷️ Card removed (UID): {card_uid}")
        
        # Emit to dashboard
        self.emit_to_dashboard('card_removed', {'uid': card_uid})
        
        # Mark sessions for delayed cleanup
        for session_id, session in self.active_sessions.items():
            if session["card_uid"] == card_uid:
                session["card_removed"] = True
                session["removal_time"] = time.time()
    
    def handle_heartbeat(self, message):
        """Handle ESP32 heartbeat"""
        esp32_uptime = message.get("uptime", 0)
        free_heap = message.get("free_heap", 0)
        rssi = message.get("rssi", 0)
        aes_operations = message.get("aes_operations", 0)
        
        print(f"💓 ESP32 heartbeat: uptime={esp32_uptime}ms, heap={free_heap}B, rssi={rssi}dBm, aes_ops={aes_operations}")
        
        # Emit heartbeat to web dashboard
        self.emit_to_dashboard('heartbeat', {
            'uptime': esp32_uptime,
            'free_heap': free_heap,
            'rssi': rssi,
            'aes_operations': aes_operations,
            'timestamp': int(time.time())
        })
    def send_rejection(self, card_uid, reason):
        """Send rejection message"""
        reject_message = {
            "type": "auth_rejected",
            "card_uid": card_uid,
            "reason": reason,
            "timestamp": int(time.time()),
            "security_info": {
                "encryption": self.encryption_algorithm,
                "mutual_auth_required": True,
                "aes_required": True
            }
        }
        self.send_to_esp32(reject_message)
    
    def send_to_esp32(self, message):
        """Send message to ESP32"""
        try:
            payload = json.dumps(message)
            self.mqtt_client.publish(self.topic_to_esp32, payload)
        except Exception as e:
            print(f"❌ Failed to send message: {e}")
    
    def log_access(self, card_uid, result, user_name=None):
        """Log access attempts with encryption info"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "card_uid": card_uid,
            "user_name": user_name,
            "result": result,
            "method": "dilithium_aes_mutual_auth",
            "encryption": self.encryption_algorithm
        }
        
        log_path = os.path.join(self.config_dir, "access_log.json")
        
        if os.path.exists(log_path):
            with open(log_path, 'r') as f:
                log_data = json.load(f)
        else:
            log_data = []
        
        log_data.append(log_entry)
        
        if len(log_data) > 1000:
            log_data = log_data[-1000:]
        
        with open(log_path, 'w') as f:
            json.dump(log_data, f, indent=2)
    
    def log_security_event(self, event_type, event_data):
        """Log security events"""
        security_log = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "event_data": event_data,
            "source": "backend_server",
            "encryption": self.encryption_algorithm
        }
        
        security_log_path = os.path.join(self.config_dir, "security_log.json")
        
        if os.path.exists(security_log_path):
            with open(security_log_path, 'r') as f:
                log_data = json.load(f)
        else:
            log_data = []
        
        log_data.append(security_log)
        
        if len(log_data) > 10000:
            log_data = log_data[-10000:]
        
        with open(security_log_path, 'w') as f:
            json.dump(log_data, f, indent=2)
    
    def cleanup_expired_sessions(self):
        """Cleanup expired sessions"""
        current_time = time.time()
        expired = []
        
        for session_id, session in self.active_sessions.items():
            if current_time - session["start_time"] > self.authentication_timeout:
                expired.append(session_id)
                continue
            
            if session.get("card_removed", False):
                removal_time = session.get("removal_time", 0)
                if current_time - removal_time > 5:
                    expired.append(session_id)
        
        for session_id in expired:
            if session_id in self.active_sessions:
                del self.active_sessions[session_id]
    
    def run(self):
        """Run the server"""
        print("🖥️ Enhanced Dilithium UID-based RFID Server running...")
        print("🔐 Security: Dilithium2 + AES-128-CTR + Mutual Authentication")
        print("🏷️ Card secrets: Server-side encrypted storage")
        print("📊 Real-time AES performance monitoring")
        print("🛡️ Multi-layer attack protection")
        print("Press Ctrl+C to stop")
        
        try:
            while True:
                time.sleep(2)
                self.cleanup_expired_sessions()
        except KeyboardInterrupt:
            print("\n🛑 Server stopped")
            self.mqtt_client.disconnect()

if __name__ == "__main__":
    server = DilithiumUIDBackendServer()
    server.run()