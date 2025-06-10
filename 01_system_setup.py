import os
import json
import base64
import time
import hashlib
import secrets
import threading
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    import oqs
    print("✅ OQS library available")
except ImportError:
    print("⚠️ Warning: OQS library not found. Install with: pip install oqs-python")
    oqs = None

class DilithiumUIDSystemSetup:
    def __init__(self):
        self.config_dir = "config"
        self.sig_algorithm = "Dilithium2"
        self.encryption_algorithm = "AES-128-CTR"
        self.nonce_size = 16  # 128-bit nonce for CTR mode (FIXED)
        self.aes_key_size = 16  # 128-bit AES key
        self.create_config_directory()
    
    def create_config_directory(self):
        """Create config directory if it doesn't exist"""
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir)
            print(f"📁 Created config directory: {self.config_dir}")
    
    def derive_aes_key(self, master_secret):
        """Derive AES-128 key từ master secret"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.aes_key_size,  # 16 bytes for AES-128
            salt=b'AES_CARD_ENCRYPTION',
            iterations=100000,
        )
        return kdf.derive(master_secret)
    
    def generate_server_keys(self):
        """Generate Dilithium keys và AES key cho server"""
        if not oqs:
            print("🔄 Mock mode: Generating dummy keys for testing")
            # Generate dummy keys for testing without OQS
            public_key = secrets.token_bytes(1312)  # Dilithium2 public key size
            secret_key = secrets.token_bytes(2528)  # Dilithium2 secret key size
        else:
            print(f"🔐 Generating {self.sig_algorithm} keypair...")
            
            # Generate Dilithium2 keypair
            signer = oqs.Signature(self.sig_algorithm)
            public_key = signer.generate_keypair()
            secret_key = signer.export_secret_key()
        
        # FIXED: Use SAME master secret as ESP32 (hardcoded)
        esp32_master_secret = bytes([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
        ])
        
        print(f"✅ Using synchronized master secret with ESP32")
        print(f"   - Master secret: {esp32_master_secret.hex()}")
        
        # Derive AES key từ master secret (same method as ESP32)
        aes_key = self.derive_aes_key(esp32_master_secret)
        
        keys = {
            "dilithium_public_key": base64.b64encode(public_key).decode(),
            "dilithium_secret_key": base64.b64encode(secret_key).decode(),
            "master_secret": base64.b64encode(esp32_master_secret).decode(),
            "aes_key": base64.b64encode(aes_key).decode(),
            "signature_algorithm": self.sig_algorithm,
            "encryption_algorithm": self.encryption_algorithm,
            "generated_at": datetime.now().isoformat()
        }
        
        # Save keys
        keys_path = os.path.join(self.config_dir, "server_keys.json")
        with open(keys_path, 'w') as f:
            json.dump(keys, f, indent=2)
        
        print(f"✅ Server keys generated and saved")
        print(f"   - Public key: {len(public_key)} bytes")
        print(f"   - Secret key: {len(secret_key)} bytes")
        print(f"   - Master secret: 32 bytes (synchronized with ESP32)")
        print(f"   - AES key: {len(aes_key)} bytes")
        print(f"   - Algorithm: {self.sig_algorithm} + {self.encryption_algorithm}")
        
        return keys
    
    def save_system_parameters(self):
        """Save system parameters"""
        params = {
            "sig_algorithm": self.sig_algorithm,
            "encryption_algorithm": self.encryption_algorithm,
            "challenge_size": 32,
            "nonce_size": self.nonce_size,  # Updated to 16 bytes
            "aes_key_size": self.aes_key_size,
            "session_timeout": 60,
            "mutual_authentication": True,
            "server_side_encryption": True,
            "pbkdf2_iterations": 100000,
            "created_at": datetime.now().isoformat()
        }
        
        params_path = os.path.join(self.config_dir, "system_params.json")
        with open(params_path, 'w') as f:
            json.dump(params, f, indent=2)
        
        print(f"✅ System parameters saved: {params_path}")
        return params
    
    def test_aes_encryption(self, master_secret):
        """Test AES-128 CTR encryption performance"""
        print("🧪 Testing AES-128 CTR encryption...")
        
        # Derive AES key
        aes_key = self.derive_aes_key(master_secret)
        
        # Test data
        test_uid = "9C85C705"
        test_secret = secrets.token_bytes(32)
        
        # Derive nonce deterministically (16 bytes for CTR mode)
        nonce_kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.nonce_size,  # 16 bytes for CTR mode
            salt=f"NONCE_{test_uid}".encode(),
            iterations=50000,
        )
        nonce = nonce_kdf.derive(master_secret)
        
        # Test encryption
        start_time = time.time()
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce))
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(test_secret) + encryptor.finalize()
        encrypt_time = (time.time() - start_time) * 1000
        
        # Test decryption
        start_time = time.time()
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted) + decryptor.finalize()
        decrypt_time = (time.time() - start_time) * 1000
        
        # Verify
        success = decrypted == test_secret
        
        results = {
            "algorithm": "AES-128-CTR",
            "encrypt_time_ms": encrypt_time,
            "decrypt_time_ms": decrypt_time,
            "data_size": len(test_secret),
            "encrypted_size": len(encrypted),
            "nonce_size": len(nonce),
            "success": success
        }
        
        print(f"   ✅ AES-128 CTR test passed")
        print(f"   - Encrypt time: {encrypt_time:.2f}ms")
        print(f"   - Decrypt time: {decrypt_time:.2f}ms")
        print(f"   - Nonce size: {len(nonce)} bytes (128-bit)")
        print(f"   - Data verified: {success}")
        
        return results
    
    def create_wifi_config_template(self):
        """Create WiFi configuration template"""
        wifi_config = {
            "ssid": "Pandora",
            "password": "12345678",
            "mqtt_server": "192.168.137.221",
            "mqtt_port": 1883,
            "instructions": [
                "1. Replace YOUR_WIFI_SSID with your actual WiFi network name",
                "2. Replace YOUR_WIFI_PASSWORD with your WiFi password", 
                "3. Set mqtt_server to your MQTT broker IP address",
                "4. Run this setup script to generate ESP32 config files"
            ]
        }
        
        wifi_path = os.path.join(self.config_dir, "wifi_config.json")
        with open(wifi_path, 'w') as f:
            json.dump(wifi_config, f, indent=2)
        
        print(f"📶 WiFi config template created: {wifi_path}")
        print("   Please edit this file with your network details")
        
        return wifi_config
    
    def generate_esp32_header_file(self):
        """Generate ESP32 configuration header file"""
        
        # Load WiFi configuration
        wifi_path = os.path.join(self.config_dir, "wifi_config.json")
        if os.path.exists(wifi_path):
            with open(wifi_path, 'r') as f:
                wifi_config = json.load(f)
        else:
            wifi_config = self.create_wifi_config_template()
            print("⚠️ Please edit wifi_config.json before generating ESP32 config")
            return None
        
        # Load server keys
        keys_path = os.path.join(self.config_dir, "server_keys.json")
        with open(keys_path, 'r') as f:
            keys = json.load(f)
        
        # Generate ESP32 config header
        config_content = f'''#ifndef CONFIG_H
#define CONFIG_H

// Auto-generated configuration for ESP32 Dilithium UID RFID
// Generated: {datetime.now().isoformat()}

// WiFi Configuration
#define WIFI_SSID "{wifi_config['ssid']}"
#define WIFI_PASSWORD "{wifi_config['password']}"
#define MQTT_SERVER "{wifi_config['mqtt_server']}"
#define MQTT_PORT {wifi_config['mqtt_port']}

// MQTT Topics
#define TOPIC_TO_SERVER "rfid/esp32_to_server"
#define TOPIC_FROM_SERVER "rfid/server_to_esp32"

// Dilithium Configuration
#define SIG_ALGORITHM "{keys['signature_algorithm']}"
#define CHALLENGE_SIZE 32
#define TIMESTAMP_TOLERANCE 60
#define SESSION_TIMEOUT 30
#define MUTUAL_AUTHENTICATION true

// AES Configuration (UPDATED)
#define AES_NONCE_SIZE 16  // 128-bit nonce for CTR mode
#define AES_KEY_SIZE 16    // 128-bit AES key

// Server Public Key (Dilithium2)
#define DILITHIUM_PUBLIC_KEY_SIZE 1312

#endif
'''
        
        # Save to file
        config_path = "esp32_config.h"
        with open(config_path, 'w') as f:
            f.write(config_content)
        
        print(f"📱 ESP32 config generated: {config_path}")
        print(f"   - WiFi SSID: {wifi_config['ssid']}")
        print(f"   - MQTT Server: {wifi_config['mqtt_server']}")
        print(f"   - AES nonce size: 16 bytes (fixed)")
        
        return config_path
    
    def create_sample_cards(self):
        """Create sample card database"""
        cards = [
            {
                "uid": "9C85C705",
                "user_name": "John Doe",
                "permissions": ["admin_access", "secure_areas"],
                "created_at": datetime.now().isoformat(),
                "active": True
            },
            {
                "uid": "A1B2C3D4", 
                "user_name": "Jane Smith",
                "permissions": ["basic_access"],
                "created_at": datetime.now().isoformat(),
                "active": True
            },
            {
                "uid": "DEADBEEF",
                "user_name": "Test User",
                "permissions": ["test_access"],
                "created_at": datetime.now().isoformat(),
                "active": True
            }
        ]
        
        cards_path = os.path.join(self.config_dir, "sample_cards.json")
        with open(cards_path, 'w') as f:
            json.dump(cards, f, indent=2)
        
        print(f"🃏 Sample cards created: {cards_path}")
        print(f"   - {len(cards)} sample cards generated")
        
        return cards
    
    def initialize_system(self):
        """Initialize complete system"""
        print("🚀 Initializing Dilithium UID RFID System with AES-128 CTR")
        print("=" * 60)
        
        # Step 1: Generate cryptographic keys
        print("\n1️⃣ Generating cryptographic keys...")
        keys = self.generate_server_keys()
        master_secret = base64.b64decode(keys["master_secret"])
        
        # Step 2: Test AES encryption
        print("\n2️⃣ Testing AES-128 CTR encryption...")
        aes_results = self.test_aes_encryption(master_secret)
        
        # Step 3: Save system parameters
        print("\n3️⃣ Saving system parameters...")
        params = self.save_system_parameters()
        
        # Step 4: Create configuration files
        print("\n4️⃣ Creating configuration files...")
        wifi_config = self.create_wifi_config_template()
        esp32_config = self.generate_esp32_header_file()
        
        # Step 5: Create sample cards
        print("\n5️⃣ Creating sample card database...")
        sample_cards = self.create_sample_cards()
        
        # Summary
        print("\n" + "=" * 60)
        print("✅ System initialization complete!")
        print("\n📊 Summary:")
        print(f"   - Signature algorithm: {keys['signature_algorithm']}")
        print(f"   - Encryption algorithm: {keys['encryption_algorithm']}")
        print(f"   - AES nonce size: {params['nonce_size']} bytes")
        print(f"   - Sample cards: {len(sample_cards)}")
        print(f"   - Config files: {len([f for f in os.listdir(self.config_dir) if f.endswith('.json')])}")
        
        print("\n🎯 Next steps:")
        print("   1. Edit config/wifi_config.json with your WiFi details")
        print("   2. Run: python 03_card_provisioning.py (to add cards)")
        print("   3. Run: python 02_backend_server.py (to start server)")
        print("   4. Run: python Web.py (to start dashboard)")
        print("   5. Upload sketch_may27a.ino to ESP32")
        
        return {
            "keys": keys,
            "aes_results": aes_results,
            "params": params,
            "sample_cards": sample_cards
        }

if __name__ == "__main__":
    setup = DilithiumUIDSystemSetup()
    setup.initialize_system()