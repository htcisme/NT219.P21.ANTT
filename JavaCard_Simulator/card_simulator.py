from flask import Flask, request, jsonify, render_template
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import json
import os
import uuid
from datetime import datetime

app = Flask(__name__)

class JavaCardSimulator:
    def __init__(self):
        self.cards_data_file = "cards_storage.json"
        self.current_card_id = None
        self.attack_mode = None  # None, 'mitm', 'fake_card', 'replay'
        self.load_or_create_cards()
        
    def load_or_create_cards(self):
        """Tải hoặc tạo mới dữ liệu các thẻ"""
        if os.path.exists(self.cards_data_file):
            try:
                with open(self.cards_data_file, 'r') as f:
                    content = f.read().strip()
                    if not content:
                        print("Cards storage file is empty, creating new cards...")
                        self.create_default_cards()
                        return
                        
                    self.cards_data = json.loads(content)
                    # Set default card
                    if not self.current_card_id and self.cards_data:
                        self.current_card_id = list(self.cards_data.keys())[0]
                    print(f"✓ Loaded {len(self.cards_data)} cards")
                    
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                print(f"Cards storage file corrupted ({e}), creating new cards...")
                self.create_default_cards()
        else:
            print("No existing cards found, creating default cards...")
            self.create_default_cards()

    def create_default_cards(self):
        """Tạo các thẻ mặc định"""
        self.cards_data = {}
        
        # Danh sách thẻ mẫu
        sample_cards = [
            {
                "user_id": "user001",
                "name": "John Doe",
                "employee_id": "EMP001",
                "department": "IT Security",
                "access_level": "L3",
                "status": "active"
            },
            {
                "user_id": "user002", 
                "name": "Jane Smith",
                "employee_id": "EMP002",
                "department": "Management",
                "access_level": "L3",
                "status": "active"
            },
            {
                "user_id": "user003",
                "name": "Bob Wilson",
                "employee_id": "EMP003", 
                "department": "Finance",
                "access_level": "L2",
                "status": "active"
            },
            {
                "user_id": "user004",
                "name": "Alice Brown",
                "employee_id": "EMP004",
                "department": "HR",
                "access_level": "L1",
                "status": "suspended"
            },
            {
                "user_id": "attacker001",
                "name": "Evil Hacker",
                "employee_id": "FAKE001",
                "department": "Unknown",
                "access_level": "L3",
                "status": "revoked"
            }
        ]
        
        for card_info in sample_cards:
            card_id = str(uuid.uuid4())[:8]
            private_key = ec.generate_private_key(ec.SECP256R1())
            
            # Mã hóa dữ liệu cá nhân
            key = os.urandom(32)
            nonce = os.urandom(12)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, json.dumps(card_info).encode(), None)
            
            # Lưu private key
            private_key_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            self.cards_data[card_id] = {
                "card_id": card_id,
                "user_id": card_info["user_id"],
                "name": card_info["name"],
                "status": card_info["status"],
                "private_key_b64": base64.b64encode(private_key_bytes).decode(),
                "encrypted_data": {
                    "key_b64": base64.b64encode(key).decode(),
                    "nonce_b64": base64.b64encode(nonce).decode(),
                    "ciphertext_b64": base64.b64encode(ciphertext).decode()
                },
                "created_at": datetime.now().isoformat()
            }
            
        # Set default card
        self.current_card_id = list(self.cards_data.keys())[0]
        self.save_cards()
        print(f"✓ Created {len(self.cards_data)} default cards")

    def save_cards(self):
        """Lưu dữ liệu các thẻ"""
        with open(self.cards_data_file, 'w') as f:
            json.dump(self.cards_data, f, indent=4)

    def get_current_card(self):
        """Lấy thẻ hiện tại"""
        if not self.current_card_id or self.current_card_id not in self.cards_data:
            return None
        return self.cards_data[self.current_card_id]

    def get_private_key(self):
        """Lấy private key của thẻ hiện tại"""
        card = self.get_current_card()
        if not card:
            return None
        private_key_bytes = base64.b64decode(card['private_key_b64'])
        return serialization.load_der_private_key(private_key_bytes, password=None)

    def get_public_key(self):
        """Lấy khóa công khai của thẻ hiện tại"""
        private_key = self.get_private_key()
        if not private_key:
            return None
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(public_key_bytes).decode()

    def perform_ecdh_and_encrypt(self, reader_public_key_b64, challenge_b64):
        """Thực hiện ECDH và mã hóa dữ liệu trả về"""
        try:
            card = self.get_current_card()
            private_key = self.get_private_key()
            
            if not card or not private_key:
                raise Exception("No card selected")

            # Attack scenarios
            if self.attack_mode == 'replay':
                # Replay attack: trả về dữ liệu cũ
                if hasattr(self, 'last_response'):
                    print("⚠️ REPLAY ATTACK: Sending old response")
                    return self.last_response

            if self.attack_mode == 'fake_card':
                # Fake card: modify user data
                print("⚠️ FAKE CARD ATTACK: Sending forged data")
                fake_data = {
                    "user_id": card["user_id"],
                    "challenge_echo": challenge_b64,
                    "encrypted_personal_data": {
                        "key_b64": "fake_key",
                        "nonce_b64": "fake_nonce", 
                        "ciphertext_b64": "fake_data"
                    },
                    "timestamp": datetime.now().isoformat()
                }
                # Still perform proper ECDH but with fake data
                reader_public_key_bytes = base64.b64decode(reader_public_key_b64)
                reader_public_key = serialization.load_der_public_key(reader_public_key_bytes)
                shared_key = private_key.exchange(ec.ECDH(), reader_public_key)
                derived_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'card-reader-session',
                ).derive(shared_key)
                
                nonce = os.urandom(12)
                aesgcm = AESGCM(derived_key)
                ciphertext = aesgcm.encrypt(nonce, json.dumps(fake_data).encode(), None)
                
                response = {
                    "nonce_b64": base64.b64encode(nonce).decode(),
                    "ciphertext_b64": base64.b64encode(ciphertext).decode()
                }
                self.last_response = response
                return response

            # Normal operation
            reader_public_key_bytes = base64.b64decode(reader_public_key_b64)
            reader_public_key = serialization.load_der_public_key(reader_public_key_bytes)
            
            shared_key = private_key.exchange(ec.ECDH(), reader_public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'card-reader-session',
            ).derive(shared_key)
            
            challenge = base64.b64decode(challenge_b64)
            response_data = {
                "user_id": card["user_id"],
                "challenge_echo": base64.b64encode(challenge).decode(),
                "encrypted_personal_data": card["encrypted_data"],
                "timestamp": datetime.now().isoformat()
            }
            
            nonce = os.urandom(12)
            aesgcm = AESGCM(derived_key)
            ciphertext = aesgcm.encrypt(nonce, json.dumps(response_data).encode(), None)
            
            response = {
                "nonce_b64": base64.b64encode(nonce).decode(),
                "ciphertext_b64": base64.b64encode(ciphertext).decode()
            }
            
            # Store for potential replay attack
            self.last_response = response
            return response
            
        except Exception as e:
            raise Exception(f"ECDH encryption failed: {str(e)}")

# Global card instance
card_simulator = JavaCardSimulator()

@app.route('/')
def dashboard():
    """Card management dashboard"""
    return render_template('./card_dashboard.html', 
                         cards=card_simulator.cards_data,
                         current_card_id=card_simulator.current_card_id,
                         attack_mode=card_simulator.attack_mode)

@app.route('/select_card/<card_id>')
def select_card(card_id):
    """Chọn thẻ để sử dụng"""
    if card_id in card_simulator.cards_data:
        card_simulator.current_card_id = card_id
        print(f"✓ Selected card: {card_simulator.cards_data[card_id]['name']}")
        return jsonify({"status": "success", "card_id": card_id})
    return jsonify({"status": "error", "message": "Card not found"}), 404

@app.route('/set_attack_mode/<mode>')
def set_attack_mode(mode):
    """Thiết lập chế độ tấn công"""
    valid_modes = [None, 'mitm', 'fake_card', 'replay']
    if mode == 'none':
        mode = None
    if mode in valid_modes:
        card_simulator.attack_mode = mode
        print(f"⚠️ Attack mode set to: {mode}")
        return jsonify({"status": "success", "attack_mode": mode})
    return jsonify({"status": "error", "message": "Invalid attack mode"}), 400

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    card = card_simulator.get_current_card()
    return jsonify({
        "status": "healthy",
        "service": "JavaCard Simulator",
        "current_card": card["user_id"] if card else None,
        "total_cards": len(card_simulator.cards_data),
        "attack_mode": card_simulator.attack_mode
    })

@app.route('/get_public_key', methods=['GET'])
def get_public_key():
    """API để lấy khóa công khai của thẻ hiện tại"""
    card = card_simulator.get_current_card()
    if not card:
        return jsonify({"error": "No card selected"}), 400
        
    public_key_b64 = card_simulator.get_public_key()
    print(f"Card public key requested for user: {card['user_id']}")
    
    # MITM Attack: Return attacker's public key
    if card_simulator.attack_mode == 'mitm':
        print("⚠️ MITM ATTACK: Returning attacker's public key")
        # Generate attacker's key
        if not hasattr(card_simulator, 'attacker_key'):
            card_simulator.attacker_key = ec.generate_private_key(ec.SECP256R1())
        
        attacker_public_key = card_simulator.attacker_key.public_key()
        attacker_public_key_bytes = attacker_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_b64 = base64.b64encode(attacker_public_key_bytes).decode()
    
    return jsonify({
        "public_key_b64": public_key_b64
    })

@app.route('/authenticate', methods=['POST'])
def authenticate():
    """API xác thực với reader"""
    try:
        data = request.get_json()
        reader_public_key_b64 = data['reader_public_key_b64']
        challenge_b64 = data['challenge_b64']
        
        card = card_simulator.get_current_card()
        if not card:
            return jsonify({"status": "error", "message": "No card selected"}), 400
        
        print(f"Card authentication requested for user: {card['user_id']}")
        if card_simulator.attack_mode:
            print(f"⚠️ Attack mode active: {card_simulator.attack_mode}")
            
        encrypted_response = card_simulator.perform_ecdh_and_encrypt(reader_public_key_b64, challenge_b64)
        
        print("✓ Card authentication successful")
        return jsonify({
            "status": "success",
            "encrypted_response": encrypted_response
        })
        
    except Exception as e:
        print(f"✗ Card authentication failed: {e}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 400

if __name__ == '__main__':
    print("=" * 50)
    print("JAVACARD SIMULATOR WITH ATTACK SCENARIOS")
    print("=" * 50)
    print(f"Total cards: {len(card_simulator.cards_data)}")
    current_card = card_simulator.get_current_card()
    if current_card:
        print(f"Current card: {current_card['name']} ({current_card['user_id']})")
    print("Running on: http://localhost:5001")
    print("Dashboard: http://localhost:5001")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5001, debug=False)