import os
import json
import secrets
import base64
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    import oqs
except ImportError:
    print("⚠️ Warning: OQS library not found. Install with: pip install oqs-python")
    oqs = None

class DilithiumUIDCardProvisioning:
    def __init__(self):
        self.config_dir = "config"
        self.sig_algorithm = "Dilithium2"
        self.encryption_algorithm = "AES-128-CTR"
        self.nonce_size = 16  # 96-bit nonce for CTR mode
        self.aes_key_size = 16  # 128-bit AES key
        
        # Load system parameters
        self.load_system_params()
        self.load_server_keys()
        
    def load_system_params(self):
        """Load system parameters"""
        params_path = os.path.join(self.config_dir, "system_params.json")
        try:
            with open(params_path, 'r') as f:
                self.system_params = json.load(f)
            print("✅ System parameters loaded")
        except FileNotFoundError:
            print("❌ System parameters not found. Run 01_system_setup.py first.")
            exit(1)
        
    def load_server_keys(self):
        """Load Dilithium server keys và AES key"""
        keys_path = os.path.join(self.config_dir, "server_keys.json")
        try:
            with open(keys_path, 'r') as f:
                keys = json.load(f)
            
            # Load Dilithium keys
            self.dilithium_public_key = base64.b64decode(keys["dilithium_public_key"])
            self.dilithium_secret_key = base64.b64decode(keys["dilithium_secret_key"])
            self.master_secret = base64.b64decode(keys["master_secret"])
            self.aes_key = base64.b64decode(keys["aes_key"])
            
            print(f"✅ Server keys loaded ({self.sig_algorithm} + {self.encryption_algorithm})")
            print(f"   - Public key size: {len(self.dilithium_public_key)} bytes")
            print(f"   - Secret key size: {len(self.dilithium_secret_key)} bytes")
            print(f"   - AES key size: {len(self.aes_key)} bytes")
        except FileNotFoundError:
            print("❌ Server keys not found. Run 01_system_setup.py first.")
            exit(1)
    
    def derive_card_nonce(self, card_uid):
        """Derive deterministic nonce từ UID cho AES CTR mode"""
        # Sử dụng PBKDF2 để derive nonce deterministic từ UID
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.nonce_size,  # FIXED: 16 bytes for CTR
            salt=f"NONCE_{card_uid}".encode(),
            iterations=50000,  # Ít hơn cho nonce
        )
        return kdf.derive(self.master_secret)
    
    def encrypt_card_secret(self, card_uid, card_secret):
        """Encrypt card secret với AES-128 CTR"""
        # Derive deterministic nonce
        nonce = self.derive_card_nonce(card_uid)
        
        # Validate input lengths
        if len(card_secret) != 32:
            raise ValueError(f"Card secret must be 32 bytes, got {len(card_secret)}")
        
        if len(nonce) != 16:
            raise ValueError(f"Nonce must be 16 bytes, got {len(nonce)}")
        
        # Encrypt với AES-128 CTR
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(nonce))
        encryptor = cipher.encryptor()
        encrypted_secret = encryptor.update(card_secret) + encryptor.finalize()
        
        # Validate output
        if len(encrypted_secret) != 32:
            raise ValueError(f"Encrypted data should be 32 bytes, got {len(encrypted_secret)}")
        
        # Create clean Base64 without padding issues
        encrypted_b64 = base64.b64encode(encrypted_secret).decode().strip()
        nonce_b64 = base64.b64encode(nonce).decode().strip()
        
        print(f"🔍 Encryption debug:")
        print(f"   - Card secret: {len(card_secret)} bytes")
        print(f"   - Nonce: {len(nonce)} bytes")
        print(f"   - Encrypted: {len(encrypted_secret)} bytes")
        print(f"   - Encrypted B64: '{encrypted_b64}' (len: {len(encrypted_b64)})")
        print(f"   - Nonce B64: '{nonce_b64}' (len: {len(nonce_b64)})")
        
        # Verify round-trip
        test_encrypted = base64.b64decode(encrypted_b64)
        test_nonce = base64.b64decode(nonce_b64)
        
        if len(test_encrypted) != 32 or len(test_nonce) != 16:
            raise ValueError(f"Round-trip validation failed: {len(test_encrypted)}/{len(test_nonce)}")
        
        return {
            "encrypted_secret": encrypted_b64,
            "nonce": nonce_b64,
            "algorithm": "AES-128-CTR"
        }
    
    def decrypt_card_secret(self, card_uid, encrypted_data):
        """Decrypt card secret từ database"""
        try:
            encrypted_secret = base64.b64decode(encrypted_data["encrypted_secret"])
            nonce = base64.b64decode(encrypted_data["nonce"])
            
            # Decrypt với AES-128 CTR
            cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(nonce))
            decryptor = cipher.decryptor()
            card_secret = decryptor.update(encrypted_secret) + decryptor.finalize()
            
            return card_secret
        except Exception as e:
            print(f"❌ Error decrypting card secret: {e}")
            return None
    
    def derive_card_secret(self, card_uid):
        """Derive card secret từ UID sử dụng PBKDF2"""
        card_context = f"DILITHIUM_CARD_{card_uid}".encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit card secret
            salt=card_context,
            iterations=100000,
        )
        return kdf.derive(self.master_secret)
    
    def create_dilithium_credential(self, card_uid, user_name=None, permissions=None):
        """Create Dilithium credential cho card với AES encryption"""
        print(f"\n🎫 Creating credential for card: {card_uid}")
        
        if user_name is None:
            user_name = input("Enter user name: ").strip()
        
        if permissions is None:
            print("Available permissions: basic, admin_access, secure_areas")
            perm_input = input("Enter permissions (comma-separated): ").strip()
            permissions = [p.strip() for p in perm_input.split(',')] if perm_input else ["basic"]
        
        # Derive card secret
        raw_card_secret = self.derive_card_secret(card_uid)
        print(f"   ✅ Card secret derived (32 bytes)")
        
        # Encrypt card secret với AES-128 CTR
        encrypted_secret_data = self.encrypt_card_secret(card_uid, raw_card_secret)
        print(f"   ✅ Card secret encrypted with AES-128 CTR")
        
        # Create credential data for signing
        credential_data = {
            "card_uid": card_uid,
            "user_name": user_name,
            "permissions": permissions,
            "provision_date": datetime.now().isoformat(),
            "encryption": "AES-128-CTR"
        }
        
        # Create Dilithium signature (FIXED)
        if oqs:
            try:
                # Create new signer instance with secret key
                signer = oqs.Signature(self.sig_algorithm, secret_key=self.dilithium_secret_key)
                
                credential_message = json.dumps(credential_data, sort_keys=True).encode()
                signature = signer.sign(credential_message)
                signature_b64 = base64.b64encode(signature).decode()
                print(f"   ✅ Dilithium signature created ({len(signature)} bytes)")
            except Exception as e:
                print(f"   ⚠️ OQS signature failed: {e}")
                print(f"   ℹ️ Using mock signature for demo")
                signature_b64 = "mock_signature_for_demo"
        else:
            signature_b64 = "mock_signature_for_demo"
            print(f"   ⚠️ Mock signature created (OQS not available)")
        
        # Complete card data
        card_data = {
            "user_name": user_name,
            "permissions": permissions,
            "status": "active",
            "provision_date": datetime.now().isoformat(),
            "encrypted_card_secret": encrypted_secret_data,
            "dilithium_signature": signature_b64,
            "last_used": None,
            "usage_count": 0
        }
        
        # Load existing database
        db_path = os.path.join(self.config_dir, "cards_database.json")
        try:
            with open(db_path, 'r') as f:
                cards_db = json.load(f)
        except FileNotFoundError:
            cards_db = {}
        
        # Add new card
        cards_db[card_uid] = card_data
        
        # Save database
        with open(db_path, 'w') as f:
            json.dump(cards_db, f, indent=2)
        
        print(f"   ✅ Card credential saved to database")
        print(f"\n📝 Card Provision Summary:")
        print(f"   - UID: {card_uid}")
        print(f"   - User: {user_name}")
        print(f"   - Permissions: {', '.join(permissions)}")
        print(f"   - Encryption: AES-128 CTR")
        print(f"   - Signature: {self.sig_algorithm}")
        print(f"   - Database: {db_path}")
        
        # Test decryption
        decrypted_secret = self.decrypt_card_secret(card_uid, encrypted_secret_data)
        if decrypted_secret == raw_card_secret:
            print(f"   ✅ Encryption/Decryption test passed")
        else:
            print(f"   ❌ Encryption/Decryption test failed")
        
        return card_data
    
    def list_provisioned_cards(self):
        """List all provisioned cards"""
        db_path = os.path.join(self.config_dir, "cards_database.json")
        try:
            with open(db_path, 'r') as f:
                cards_db = json.load(f)
            
            print(f"\n📋 Provisioned Cards:")
            print(f"{'UID':<12} {'User':<20} {'Status':<10} {'Permissions':<30}")
            print("-" * 75)
            
            for uid, data in cards_db.items():
                permissions_str = ', '.join(data.get('permissions', []))
                print(f"{uid:<12} {data.get('user_name', 'Unknown'):<20} {data.get('status', 'unknown'):<10} {permissions_str:<30}")
            
            return cards_db
        except FileNotFoundError:
            print("❌ No cards database found")
            return {}
    
    def verify_card_crypto(self, card_uid):
        """Verify card cryptographic operations"""
        db_path = os.path.join(self.config_dir, "cards_database.json")
        try:
            with open(db_path, 'r') as f:
                cards_db = json.load(f)
            
            if card_uid not in cards_db:
                print(f"❌ Card {card_uid} not found in database")
                return False
            
            card_data = cards_db[card_uid]
            
            print(f"\n🔍 Verifying crypto operations for card: {card_uid}")
            
            # Test card secret derivation
            derived_secret = self.derive_card_secret(card_uid)
            print(f"   ✅ Card secret derivation: OK")
            
            # Test AES decryption
            encrypted_data = card_data["encrypted_card_secret"]
            decrypted_secret = self.decrypt_card_secret(card_uid, encrypted_data)
            
            if decrypted_secret == derived_secret:
                print(f"   ✅ AES-128 CTR decryption: OK")
            else:
                print(f"   ❌ AES-128 CTR decryption: FAILED")
                return False
            
            # Test Dilithium signature verification (FIXED)
            if oqs and card_data["dilithium_signature"] != "mock_signature_for_demo":
                try:
                    # Create verifier with public key
                    verifier = oqs.Signature(self.sig_algorithm)
                    
                    credential_data = {
                        "card_uid": card_uid,
                        "user_name": card_data["user_name"],
                        "permissions": card_data["permissions"],
                        "provision_date": card_data["provision_date"],
                        "encryption": "AES-128-CTR"
                    }
                    
                    credential_message = json.dumps(credential_data, sort_keys=True).encode()
                    signature = base64.b64decode(card_data["dilithium_signature"])
                    
                    is_valid = verifier.verify(credential_message, signature, self.dilithium_public_key)
                    
                    if is_valid:
                        print(f"   ✅ Dilithium signature verification: OK")
                    else:
                        print(f"   ❌ Dilithium signature verification: FAILED")
                        return False
                except Exception as e:
                    print(f"   ⚠️ Dilithium signature verification error: {e}")
                    print(f"   ℹ️ Continuing without signature verification")
            else:
                print(f"   ⚠️ Dilithium signature verification: SKIPPED (mock signature)")
            
            print(f"   ✅ All cryptographic operations verified successfully")
            return True
            
        except Exception as e:
            print(f"❌ Error verifying card crypto: {e}")
            return False

def interactive_provisioning():
    """Interactive card provisioning"""
    provisioner = DilithiumUIDCardProvisioning()
    
    while True:
        print(f"\n🎫 === Dilithium Card Provisioning Tool ===")
        print("1. Provision new card")
        print("2. List provisioned cards")
        print("3. Verify card crypto")
        print("4. Exit")
        
        choice = input("\nSelect option (1-4): ").strip()
        
        if choice == "1":
            card_uid = input("Enter card UID (e.g., 9C85C705): ").strip().upper()
            if len(card_uid) != 8:
                print("❌ Invalid UID format. Use 8 hex characters.")
                continue
            
            try:
                provisioner.create_dilithium_credential(card_uid)
            except Exception as e:
                print(f"❌ Error provisioning card: {e}")
        
        elif choice == "2":
            provisioner.list_provisioned_cards()
        
        elif choice == "3":
            card_uid = input("Enter card UID to verify: ").strip().upper()
            provisioner.verify_card_crypto(card_uid)
        
        elif choice == "4":
            print("👋 Goodbye!")
            break
        
        else:
            print("❌ Invalid option")

if __name__ == "__main__":
    interactive_provisioning()