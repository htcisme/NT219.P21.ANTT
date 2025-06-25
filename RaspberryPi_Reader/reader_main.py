import json
import requests
import base64
import os
from crypto_utils import ReaderCrypto
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
class SecureReader:
    def __init__(self, config_file="config.json"):
        with open(config_file, 'r') as f:
            self.config = json.load(f)
            
        print("Initializing Secure Reader with liboqs...")
        self.crypto = ReaderCrypto(
            self.config['certificate_file'],
            self.config['ca_public_key_file']
        )
        
        self.session_key = None
        
    def authenticate_with_server(self):
        """Xác thực lẫn nhau với server sử dụng Dilithium"""
        print("=== Starting Mutual Authentication with Server (Dilithium) ===")
        
        # 1. Gửi certificate và khóa ECDH đã ký đến server
        ecdh_public_key_b64 = self.crypto.get_ecdh_public_key_b64()
        signed_ecdh_key = self.crypto.sign_data(ecdh_public_key_b64)
        
        handshake_data = {
            "reader_id": self.config['reader_id'],
            "certificate": self.crypto.certificate,
            "ecdh_public_key_b64": ecdh_public_key_b64,
            "signed_ecdh_key_b64": signed_ecdh_key
        }
        
        try:
            print("Sending handshake request...")
            response = requests.post(
                f"{self.config['server_url']}/handshake",
                json=handshake_data,
                timeout=10
            )
            response.raise_for_status()
            
            handshake_response = response.json()
            
            # 2. Xác thực certificate của server
            print("Verifying server certificate...")
            server_certificate = handshake_response['server_certificate']
            if not self.crypto.verify_certificate(server_certificate):
                raise Exception("Server certificate verification failed")
                
            # 3. Xác thực chữ ký server trên ECDH key
            print("Verifying server ECDH key signature...")
            server_dilithium_pk_b64 = server_certificate['certificate_data']['public_key']
            server_ecdh_public_key_b64 = handshake_response['server_ecdh_public_key_b64']
            signed_server_ecdh_key_b64 = handshake_response['signed_server_ecdh_key_b64']
            
            if not self.crypto.verify_signature(
                server_dilithium_pk_b64,
                server_ecdh_public_key_b64,
                signed_server_ecdh_key_b64
            ):
                raise Exception("Server ECDH key signature verification failed")
            
            # 4. Thực hiện ECDH để tạo session key
            print("Performing ECDH key exchange...")
            self.session_key = self.crypto.perform_ecdh_with_server(server_ecdh_public_key_b64)
            
            print("✓ Mutual authentication with server successful")
            print(f"✓ Session key established ({len(self.session_key)} bytes)")
            return True
            
        except Exception as e:
            print(f"✗ Server authentication failed: {e}")
            return False
    
    def communicate_with_card(self):
        """Giao tiếp với thẻ JavaCard (giữ nguyên như trước)"""
        print("=== Communicating with JavaCard (ECC) ===")
        
        try:
            # 1. Lấy khóa công khai của thẻ
            response = requests.get(f"{self.config['card_simulator_url']}/get_public_key")
            response.raise_for_status()
            card_public_key_b64 = response.json()['public_key_b64']
            
            # 2. Tạo challenge và gửi đến thẻ
            challenge = os.urandom(32)
            reader_ecdh_public_key_b64 = self.crypto.get_ecdh_public_key_b64()
            
            auth_data = {
                "reader_public_key_b64": reader_ecdh_public_key_b64,
                "challenge_b64": base64.b64encode(challenge).decode()
            }
            
            response = requests.post(
                f"{self.config['card_simulator_url']}/authenticate",
                json=auth_data
            )
            response.raise_for_status()
            
            card_response = response.json()
            if card_response['status'] != 'success':
                raise Exception(f"Card authentication failed: {card_response.get('message', 'Unknown error')}")
                
            print("✓ Card authentication successful")
            return {
                "card_public_key_b64": card_public_key_b64,
                "encrypted_card_data": card_response['encrypted_response'],
                "challenge_used": base64.b64encode(challenge).decode()
            }
            
        except Exception as e:
            print(f"✗ Card communication failed: {e}")
            return None
    def simulate_biometric_capture(self, user_id):
        """Simulate biometric capture (fingerprint, face, etc.)"""
        print("=== Biometric Verification ===")
        
        # Simulate biometric capture delay
        import time
        print("📷 Capturing biometric data...")
        time.sleep(2)
        
        # Simulate biometric templates for known users
        biometric_templates = {
            "user001": "fingerprint_template_001",
            "user002": "face_template_002", 
            "user003": "fingerprint_template_003",
            "user004": "face_template_004"
        }
        
        template = biometric_templates.get(user_id)
        if template:
            print(f"✓ Biometric captured: {template}")
            return {
                "type": "fingerprint" if "fingerprint" in template else "face",
                "template": template,
                "confidence": 0.95,
                "timestamp": "2025-01-01T12:00:00Z"
            }
        else:
            print("✗ Biometric capture failed")
            return None
        
    def run_access_control_flow(self):
        """Chạy toàn bộ quy trình kiểm soát truy cập"""
        print("=" * 70)
        print("SECURE ACCESS CONTROL SYSTEM - RASPBERRY PI READER (liboqs)")
        print("=" * 70)
        
        # 1. Xác thực với server
        if not self.authenticate_with_server():
            return False
            
        # 2. Select user for testing
        print("\nSelect user to simulate:")
        print("1. user001 - John Doe (IT Security, L3, no biometric)")
        print("2. user002 - Jane Smith (Management, L3, biometric required)")
        print("3. user003 - Bob Wilson (Finance, L2, time restricted)")
        print("4. user004 - Alice Brown (HR, L1, suspended)")
        
        try:
            choice = input("Enter choice (1-4): ").strip()
            user_map = {
                "1": "user001",
                "2": "user002", 
                "3": "user003",
                "4": "user004"
            }
            selected_user = user_map.get(choice, "user001")
            print(f"Selected user: {selected_user}")
            
            # Override fallback user_id
            self.test_user_id = selected_user
            
        except KeyboardInterrupt:
            return False
            
        # 3. Giao tiếp với thẻ
        card_data = self.communicate_with_card()
        if not card_data:
            return False
            
        # 4. Gửi yêu cầu truy cập
        return self.send_access_request(card_data)

    def send_access_request(self, card_data):
        """Gửi yêu cầu truy cập đến server"""
        print("=== Sending Access Request to Server (AES-GCM) ===")
        
        if not self.session_key:
            print("✗ No session key available")
            return False
            
        try:
            # Decrypt card data để lấy user_id
            user_id = None
            try:
                # Thực hiện ECDH với card để decrypt
                card_public_key_bytes = base64.b64decode(card_data['card_public_key_b64'])
                card_public_key = serialization.load_der_public_key(card_public_key_bytes)
                
                # Tạo shared key với card
                shared_key = self.crypto.ecdh_private_key.exchange(ec.ECDH(), card_public_key)
                derived_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'card-reader-session',
                ).derive(shared_key)
                
                # Decrypt card response
                nonce = base64.b64decode(card_data['encrypted_card_data']['nonce_b64'])
                ciphertext = base64.b64decode(card_data['encrypted_card_data']['ciphertext_b64'])
                
                aesgcm = AESGCM(derived_key)
                plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                card_response = json.loads(plaintext.decode())
                
                user_id = card_response.get('user_id')
                print(f"✓ Extracted user_id from card: {user_id}")
                
            except Exception as e:
                print(f"✗ Failed to decrypt card data: {e}")
                # Fallback to default user for testing
                user_id = "user002"  # Change to user002 to test biometric
                print(f"Using fallback user_id: {user_id}")
            
            # Check if biometric is needed (simulate checking user requirements)
            biometric_data = None
            if user_id in ["user002"]:  # Users that require biometric
                print("🔍 Biometric verification required for this user")
                biometric_data = self.simulate_biometric_capture(user_id)
                if not biometric_data:
                    print("✗ Biometric verification failed - access denied")
                    return False
            
            # Chuẩn bị request với user_id và biometric data
            request_data = {
                "reader_id": self.config['reader_id'],
                "user_id": user_id,
                "card_public_key_b64": card_data['card_public_key_b64'],
                "encrypted_card_data": card_data['encrypted_card_data'],
                "challenge_used": card_data['challenge_used'],
                "timestamp": "2025-01-01T12:00:00Z",
                "access_zone": "MAIN_ENTRANCE",
                "biometric_data": biometric_data  # Add biometric data
            }
            
            # Mã hóa request
            encrypted_request = self.crypto.encrypt_data(request_data, self.session_key)
            
            # Gửi đến server
            response = requests.post(
                f"{self.config['server_url']}/verify_access",
                json={
                    "reader_id": self.config['reader_id'],
                    "encrypted_request": encrypted_request
                }
            )
            response.raise_for_status()
            
            # Decrypt response
            server_response = response.json()
            decrypted_response = self.crypto.decrypt_data(
                server_response['encrypted_response'],
                self.session_key
            )
            
            response_data = json.loads(decrypted_response)
            decision = response_data['decision']
            
            print(f"=== ACCESS DECISION: {decision} ===")
            if decision == "ALLOW":
                print("✓ Access granted!")
                user_info = response_data.get('user_info', {})
                print(f"  User: {user_info.get('name', 'Unknown')}")
                print(f"  Department: {user_info.get('department', 'Unknown')}")
                print(f"  Access Level: {user_info.get('access_level', 'Unknown')}")
                if biometric_data:
                    print(f"  Biometric: {biometric_data['type']} verified")
            else:
                print(f"✗ Access denied: {response_data.get('reason', 'Unknown')}")
                
            return decision == "ALLOW"
            
        except Exception as e:
            print(f"✗ Access request failed: {e}")
            return False
        
    def run_access_control_flow(self):
        """Chạy toàn bộ quy trình kiểm soát truy cập"""
        print("=" * 70)
        print("SECURE ACCESS CONTROL SYSTEM - RASPBERRY PI READER (liboqs)")
        print("=" * 70)
        
        # 1. Xác thực với server
        if not self.authenticate_with_server():
            return False
            
        # 2. Giao tiếp với thẻ
        card_data = self.communicate_with_card()
        if not card_data:
            return False
            
        # 3. Gửi yêu cầu truy cập
        return self.send_access_request(card_data)

def main():
    try:
        reader = SecureReader()
        
        while True:
            input("\nPress Enter to simulate card tap (or Ctrl+C to exit)...")
            try:
                success = reader.run_access_control_flow()
                if success:
                    print("\n🎉 ACCESS GRANTED - Door opened!")
                else:
                    print("\n🚫 ACCESS DENIED - Please contact administrator")
            except KeyboardInterrupt:
                print("\nShutting down reader...")
                break
            except Exception as e:
                print(f"\nUnexpected error: {e}")
                
    except Exception as e:
        print(f"Failed to initialize reader: {e}")
        print("Make sure CA setup has been completed first!")

if __name__ == "__main__":
    main()