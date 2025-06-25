import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from reader_main import SecureReader
import json
import base64

class DebugSecureReader(SecureReader):
    def __init__(self, config_file="config.json"):
        super().__init__(config_file)
        self.debug_mode = True
    
    def debug_print_encrypted_data(self, title, data, data_type="unknown"):
        """Print encrypted data with nice formatting"""
        print(f"\n{'='*80}")
        print(f"🔒 {title}")
        print(f"{'='*80}")
        print(f"📋 Data Type: {data_type}")
        print(f"📊 Data Size: {len(str(data))} bytes")
        print(f"⏰ Timestamp: {__import__('datetime').datetime.now().isoformat()}")
        
        if isinstance(data, dict):
            print(f"\n📦 Structured Encrypted Data:")
            for key, value in data.items():
                print(f"  🔑 {key}:")
                if isinstance(value, str) and len(value) > 100:
                    print(f"    📝 {value[:60]}...")
                    print(f"       ...{value[-40:]}")
                    print(f"    📏 [Length: {len(value)} characters]")
                elif isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        print(f"      └─ {sub_key}: {sub_value}")
                else:
                    print(f"    📝 {value}")
        else:
            print(f"\n📝 Raw Encrypted Data:")
            data_str = str(data)
            chunk_size = 80
            for i in range(0, len(data_str), chunk_size):
                chunk = data_str[i:i+chunk_size]
                print(f"  {chunk}")
        
        print(f"{'='*80}")
    
    def authenticate_with_server(self):
        """Enhanced authentication with debug output"""
        print("=== Starting Mutual Authentication with Server (Dilithium) ===")
        
        # 1. Prepare handshake data
        ecdh_public_key_b64 = self.crypto.get_ecdh_public_key_b64()
        signed_ecdh_key = self.crypto.sign_data(ecdh_public_key_b64)
        
        handshake_data = {
            "reader_id": self.config['reader_id'],
            "certificate": self.crypto.certificate,
            "ecdh_public_key_b64": ecdh_public_key_b64,
            "signed_ecdh_key_b64": signed_ecdh_key
        }
        
        # Debug: Show outgoing encrypted handshake
        self.debug_print_encrypted_data(
            "OUTGOING HANDSHAKE TO SERVER", 
            handshake_data, 
            "handshake_request"
        )
        
        # Continue with normal authentication
        return super().authenticate_with_server()
    
    def communicate_with_card(self):
        """Enhanced card communication with debug output"""
        print("=== Communicating with JavaCard (AES-GCM) ===")
        
        # Select card
        card_response = super().communicate_with_card()
        
        if card_response and 'encrypted_card_data' in card_response:
            # Debug: Show encrypted card response
            self.debug_print_encrypted_data(
                "ENCRYPTED CARD RESPONSE",
                card_response['encrypted_card_data'],
                "card_aes_gcm_response"
            )
        
        return card_response
    
    def send_access_request(self, card_data):
        """Enhanced access request with debug output"""
        print("=== Sending Access Request to Server (AES-GCM) ===")
        
        if not self.session_key:
            print("✗ No session key available")
            return False
        
        # Prepare request data
        user_id = getattr(self, 'test_user_id', 'user001')
        
        request_data = {
            "reader_id": self.config['reader_id'],
            "user_id": user_id,
            "card_public_key_b64": card_data['card_public_key_b64'],
            "encrypted_card_data": card_data['encrypted_card_data'],
            "challenge_used": card_data['challenge_used'],
            "timestamp": "2025-01-01T12:00:00Z",
            "access_zone": "MAIN_ENTRANCE"
        }
        
        # Encrypt the request
        encrypted_request = self.crypto.encrypt_data(request_data, self.session_key)
        
        # Debug: Show encrypted request before sending
        self.debug_print_encrypted_data(
            "ENCRYPTED ACCESS REQUEST TO SERVER",
            {
                "reader_id": self.config['reader_id'],
                "encrypted_request": encrypted_request
            },
            "access_request_aes_gcm"
        )
        
        # Show session key being used (Base64 encoded for display)
        print(f"\n🔑 SESSION KEY USED:")
        session_key_b64 = base64.b64encode(self.session_key).decode()
        print(f"   {session_key_b64[:32]}...{session_key_b64[-16:]} [{len(self.session_key)} bytes]")
        
        # Continue with sending request
        try:
            import requests
            response = requests.post(
                f"{self.config['server_url']}/verify_access",
                json={
                    "reader_id": self.config['reader_id'],
                    "encrypted_request": encrypted_request
                }
            )
            response.raise_for_status()
            
            server_response = response.json()
            
            # Debug: Show encrypted server response
            self.debug_print_encrypted_data(
                "ENCRYPTED SERVER RESPONSE",
                server_response,
                "server_response_aes_gcm"
            )
            
            # Decrypt and show final result
            decrypted_response = self.crypto.decrypt_data(
                server_response['encrypted_response'],
                self.session_key
            )
            
            print(f"\n🔓 DECRYPTED SERVER RESPONSE:")
            print(f"{'='*80}")
            response_data = json.loads(decrypted_response)
            print(json.dumps(response_data, indent=2))
            print(f"{'='*80}")
            
            decision = response_data['decision']
            print(f"=== ACCESS DECISION: {decision} ===")
            
            return decision == "ALLOW"
            
        except Exception as e:
            print(f"✗ Access request failed: {e}")
            return False

def main():
    """Main function to run debug reader"""
    print("🔍 DEBUG MODE: SECURE READER WITH NETWORK TRAFFIC DISPLAY")
    print("="*80)
    print("This will show all encrypted data transmitted over the network")
    print("="*80)
    
    # Create debug reader
    debug_reader = DebugSecureReader()
    
    # Run access control flow
    debug_reader.run_access_control_flow()

if __name__ == "__main__":
    main()