import requests
import json
import time
import threading
from datetime import datetime
import logging
import base64
import binascii
from flask import Flask, request, jsonify
import urllib.parse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

class TrafficInterceptor:
    def __init__(self):
        self.captured_traffic = []
        self.server_url = "http://localhost:5000"
        self.card_url = "http://localhost:5001"
        self.interceptor_app = Flask(__name__)
        self.setup_interceptor_routes()
        
    def setup_interceptor_routes(self):
        """Setup proxy routes to intercept traffic"""
        
        @self.interceptor_app.route('/intercept/server/<path:endpoint>', methods=['GET', 'POST', 'PUT', 'DELETE'])
        def intercept_server_traffic(endpoint):
            return self.intercept_and_forward("SERVER", f"{self.server_url}/{endpoint}")
        
        @self.interceptor_app.route('/intercept/card/<path:endpoint>', methods=['GET', 'POST', 'PUT', 'DELETE'])
        def intercept_card_traffic(endpoint):
            return self.intercept_and_forward("CARD", f"{self.card_url}/{endpoint}")
    
    def intercept_and_forward(self, service_type, target_url):
        """Intercept, log, and forward requests"""
        
        # Capture request
        request_data = {
            'timestamp': datetime.now().isoformat(),
            'direction': 'REQUEST',
            'service': service_type,
            'method': request.method,
            'url': target_url,
            'headers': dict(request.headers),
            'data': None
        }
        
        if request.is_json:
            request_data['data'] = request.get_json()
        elif request.data:
            request_data['data'] = request.data.decode('utf-8')
        
        self.log_intercepted_traffic(request_data)
        
        # Forward request
        try:
            if request.method == 'GET':
                response = requests.get(target_url, headers=dict(request.headers), timeout=10)
            elif request.method == 'POST':
                response = requests.post(target_url, json=request.get_json() if request.is_json else None, 
                                       data=request.data if not request.is_json else None,
                                       headers=dict(request.headers), timeout=10)
            
            # Capture response
            response_data = {
                'timestamp': datetime.now().isoformat(),
                'direction': 'RESPONSE',
                'service': service_type,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'data': None
            }
            
            try:
                response_data['data'] = response.json()
            except:
                response_data['data'] = response.text
            
            self.log_intercepted_traffic(response_data)
            
            return jsonify(response_data['data']) if response_data['data'] else response.text
            
        except Exception as e:
            error_data = {
                'timestamp': datetime.now().isoformat(),
                'direction': 'ERROR',
                'service': service_type,
                'error': str(e)
            }
            self.log_intercepted_traffic(error_data)
            return jsonify({'error': str(e)}), 500
    
    def log_intercepted_traffic(self, traffic_data):
        """Log intercepted traffic with detailed analysis"""
        
        self.captured_traffic.append(traffic_data)
        
        print(f"\n{'='*100}")
        print(f"🔍 INTERCEPTED NETWORK TRAFFIC")
        print(f"{'='*100}")
        print(f"⏰ Time: {traffic_data['timestamp']}")
        print(f"🎯 Service: {traffic_data['service']}")
        print(f"📡 Direction: {traffic_data['direction']}")
        
        if traffic_data['direction'] == 'REQUEST':
            print(f"🌐 Method: {traffic_data['method']}")
            print(f"🔗 URL: {traffic_data['url']}")
            
        elif traffic_data['direction'] == 'RESPONSE':
            print(f"📊 Status: {traffic_data['status_code']}")
        
        # Analyze data payload
        if traffic_data.get('data'):
            self.analyze_payload(traffic_data['data'], traffic_data['service'])
        
        print(f"{'='*100}")
    
    def analyze_payload(self, data, service_type):
        """Analyze and display encrypted data payloads"""
        
        print(f"\n📦 PAYLOAD ANALYSIS ({service_type}):")
        print(f"{'─'*80}")
        
        if isinstance(data, dict):
            self.analyze_structured_payload(data)
        elif isinstance(data, str):
            print(f"📝 Raw String Data: {data[:200]}{'...' if len(data) > 200 else ''}")
        else:
            print(f"📄 Data Type: {type(data).__name__}")
            print(f"📊 Data: {str(data)[:200]}{'...' if len(str(data)) > 200 else ''}")
    
    def analyze_structured_payload(self, data):
        """Analyze structured JSON payloads"""
        
        for key, value in data.items():
            print(f"\n🔑 {key}:")
            
            # Dilithium signature detection
            if 'signature' in key.lower() or 'sign' in key.lower():
                self.analyze_signature(key, value)
                
            # Certificate analysis
            elif 'certificate' in key.lower() or 'cert' in key.lower():
                self.analyze_certificate(key, value)
                
            # Encrypted data analysis
            elif 'encrypted' in key.lower() or 'cipher' in key.lower():
                self.analyze_encrypted_data(key, value)
                
            # ECDH key analysis
            elif 'ecdh' in key.lower() or 'public_key' in key.lower():
                self.analyze_public_key(key, value)
                
            # Nonce analysis
            elif 'nonce' in key.lower():
                self.analyze_nonce(key, value)
                
            # Authentication tag analysis
            elif 'tag' in key.lower() and 'auth' in key.lower():
                self.analyze_auth_tag(key, value)
                
            # Session key analysis
            elif 'session' in key.lower() and 'key' in key.lower():
                self.analyze_session_key(key, value)
                
            else:
                # Generic field
                if isinstance(value, str) and len(value) > 100:
                    print(f"   📝 {value[:60]}...{value[-20:]}")
                    print(f"   📏 Length: {len(value)} characters")
                elif isinstance(value, dict):
                    print(f"   📦 Nested object with {len(value)} fields")
                    for sub_key in value.keys():
                        print(f"     └─ {sub_key}")
                else:
                    print(f"   📄 {value}")
    
    def analyze_signature(self, field_name, signature_data):
        """Analyze digital signatures"""
        print(f"   ✍️  TYPE: DIGITAL SIGNATURE")
        
        if isinstance(signature_data, str):
            print(f"   📏 Length: {len(signature_data)} characters")
            
            # Check if it's Base64
            try:
                sig_bytes = base64.b64decode(signature_data)
                print(f"   📊 Binary Size: {len(sig_bytes)} bytes")
                
                # Dilithium signature size detection
                if len(sig_bytes) > 2000:
                    print(f"   🔐 ALGORITHM: Likely DILITHIUM (size: {len(sig_bytes)} bytes)")
                    print(f"   🛡️  SECURITY: Post-quantum signature")
                elif len(sig_bytes) > 60:
                    print(f"   🔐 ALGORITHM: Likely ECDSA/RSA (size: {len(sig_bytes)} bytes)")
                
                print(f"   🔢 Hex Preview: {binascii.hexlify(sig_bytes[:32]).decode()}...")
                print(f"   💡 PURPOSE: Authenticate sender & verify data integrity")
                
            except Exception as e:
                print(f"   📝 Raw signature (not Base64): {signature_data[:100]}...")
    
    def analyze_certificate(self, field_name, cert_data):
        """Analyze digital certificates"""
        print(f"   📜 TYPE: DIGITAL CERTIFICATE")
        
        if isinstance(cert_data, dict):
            print(f"   📦 Certificate Structure:")
            for cert_key, cert_value in cert_data.items():
                print(f"     └─ {cert_key}: ", end="")
                if isinstance(cert_value, str) and len(cert_value) > 50:
                    print(f"{cert_value[:40]}... ({len(cert_value)} chars)")
                else:
                    print(f"{cert_value}")
        else:
            print(f"   📄 Raw Certificate: {str(cert_data)[:100]}...")
    
    def analyze_encrypted_data(self, field_name, encrypted_data):
        """Analyze encrypted data structures"""
        print(f"   🔒 TYPE: ENCRYPTED DATA")
        
        if isinstance(encrypted_data, dict):
            print(f"   🛡️  ENCRYPTION STRUCTURE:")
            
            for enc_key, enc_value in encrypted_data.items():
                print(f"     └─ {enc_key}: ", end="")
                
                if 'nonce' in enc_key.lower():
                    try:
                        nonce_bytes = base64.b64decode(enc_value)
                        print(f"🎲 {len(nonce_bytes)}-byte nonce - {binascii.hexlify(nonce_bytes).decode()}")
                    except:
                        print(f"📝 {enc_value}")
                        
                elif 'ciphertext' in enc_key.lower():
                    try:
                        cipher_bytes = base64.b64decode(enc_value)
                        print(f"🔐 {len(cipher_bytes)}-byte ciphertext")
                        print(f"       🔢 First 32 bytes: {binascii.hexlify(cipher_bytes[:32]).decode()}")
                        if len(cipher_bytes) > 64:
                            print(f"       🔢 Last 16 bytes:  {binascii.hexlify(cipher_bytes[-16:]).decode()}")
                    except:
                        print(f"📝 {enc_value[:60]}...")
                        
                elif 'tag' in enc_key.lower():
                    try:
                        tag_bytes = base64.b64decode(enc_value)
                        print(f"🏷️  {len(tag_bytes)}-byte auth tag - {binascii.hexlify(tag_bytes).decode()}")
                    except:
                        print(f"📝 {enc_value}")
                else:
                    print(f"📄 {str(enc_value)[:50]}...")
                    
            # Determine encryption algorithm
            has_nonce = any('nonce' in k.lower() for k in encrypted_data.keys())
            has_tag = any('tag' in k.lower() for k in encrypted_data.keys())
            
            if has_nonce and has_tag:
                print(f"   🔐 ALGORITHM: Likely AES-GCM (Authenticated Encryption)")
            elif has_nonce:
                print(f"   🔐 ALGORITHM: Likely AES-CTR or similar")
            else:
                print(f"   🔐 ALGORITHM: Unknown symmetric encryption")
        else:
            print(f"   📝 Raw Encrypted: {str(encrypted_data)[:100]}...")
    
    def analyze_public_key(self, field_name, key_data):
        """Analyze public keys"""
        print(f"   🔑 TYPE: PUBLIC KEY")
        
        if isinstance(key_data, str):
            try:
                key_bytes = base64.b64decode(key_data)
                print(f"   📊 Key Size: {len(key_bytes)} bytes")
                print(f"   🔢 Key Preview: {binascii.hexlify(key_bytes[:20]).decode()}...")
                
                if 'ecdh' in field_name.lower():
                    print(f"   🔐 TYPE: ECDH Key Exchange")
                    print(f"   💡 PURPOSE: Establish shared secret")
                else:
                    print(f"   💡 PURPOSE: Public key cryptography")
                    
            except:
                print(f"   📝 Raw Key: {key_data[:60]}...")
    
    def analyze_nonce(self, field_name, nonce_data):
        """Analyze cryptographic nonces"""
        print(f"   🎲 TYPE: CRYPTOGRAPHIC NONCE")
        
        if isinstance(nonce_data, str):
            try:
                nonce_bytes = base64.b64decode(nonce_data)
                print(f"   📊 Size: {len(nonce_bytes)} bytes")
                print(f"   🔢 Hex: {binascii.hexlify(nonce_bytes).decode()}")
                print(f"   💡 PURPOSE: Ensure encryption uniqueness")
            except:
                print(f"   📝 Raw Nonce: {nonce_data}")
    
    def analyze_auth_tag(self, field_name, tag_data):
        """Analyze authentication tags"""
        print(f"   🏷️  TYPE: AUTHENTICATION TAG")
        
        if isinstance(tag_data, str):
            try:
                tag_bytes = base64.b64decode(tag_data)
                print(f"   📊 Size: {len(tag_bytes)} bytes")
                print(f"   🔢 Hex: {binascii.hexlify(tag_bytes).decode()}")
                print(f"   🛡️  PURPOSE: Verify data integrity & authenticity")
            except:
                print(f"   📝 Raw Tag: {tag_data}")
    
    def analyze_session_key(self, field_name, key_data):
        """Analyze session keys"""
        print(f"   🔐 TYPE: SESSION KEY")
        print(f"   ⚠️  SECURITY: Should be encrypted/derived, not plaintext")
        
        if isinstance(key_data, str):
            print(f"   📏 Length: {len(key_data)} characters")
            if len(key_data) == 44:  # Base64 encoded 32-byte key
                print(f"   💡 Likely 256-bit AES key (Base64 encoded)")
            elif len(key_data) == 24:  # Base64 encoded 16-byte key  
                print(f"   💡 Likely 128-bit AES key (Base64 encoded)")

def start_interceptor_server():
    """Start the traffic interceptor server"""
    interceptor = TrafficInterceptor()
    
    print("🔍 NETWORK TRAFFIC INTERCEPTOR STARTED")
    print("="*80)
    print("📡 Interceptor running on: http://localhost:8000")
    print("🎯 To intercept traffic, modify Reader to use:")
    print("   Server URL: http://localhost:8000/intercept/server")
    print("   Card URL: http://localhost:8000/intercept/card")
    print("="*80)
    
    interceptor.interceptor_app.run(host='0.0.0.0', port=8000, debug=False)

def simulate_realistic_traffic():
    """Simulate realistic encrypted traffic for demonstration"""
    
    print("🚀 SIMULATING REALISTIC ENCRYPTED TRAFFIC")
    print("="*100)
    
    interceptor = TrafficInterceptor()
    
    # Simulate handshake request
    handshake_request = {
        "reader_id": "reader_pi_01",
        "certificate": {
            "certificate_data": {
                "entity_id": "reader_pi_01",
                "dilithium_public_key": base64.b64encode(b"x" * 1312).decode(),  # Dilithium2 public key
                "validity": "2025-2026"
            },
            "dilithium2_signature": base64.b64encode(b"sig" * 800).decode()  # ~2400 byte signature
        },
        "ecdh_public_key_b64": base64.b64encode(b"ecdh_key_32_bytes_here_12345678").decode(),
        "ecdh_signature": base64.b64encode(b"ecdh_sig" * 300).decode(),
        "timestamp": datetime.now().isoformat()
    }
    
    traffic_data = {
        'timestamp': datetime.now().isoformat(),
        'direction': 'REQUEST',
        'service': 'SERVER',
        'method': 'POST',
        'url': 'http://localhost:5000/handshake',
        'data': handshake_request
    }
    
    interceptor.log_intercepted_traffic(traffic_data)
    
    time.sleep(2)
    
    # Simulate encrypted access request
    access_request = {
        "reader_id": "reader_pi_01",
        "encrypted_request": {
            "nonce_b64": base64.b64encode(b"nonce_12_bytes_").decode(),
            "ciphertext_b64": base64.b64encode(b"encrypted_data" * 50).decode(),
            "auth_tag_b64": base64.b64encode(b"auth_tag_16bytes").decode()
        },
        "sequence": 1
    }
    
    traffic_data = {
        'timestamp': datetime.now().isoformat(),
        'direction': 'REQUEST',
        'service': 'SERVER',
        'method': 'POST',
        'url': 'http://localhost:5000/verify_access',
        'data': access_request
    }
    
    interceptor.log_intercepted_traffic(traffic_data)
    
    time.sleep(2)
    
    # Simulate server response
    server_response = {
        "encrypted_response": {
            "nonce_b64": base64.b64encode(b"resp_nonce_12").decode(),
            "ciphertext_b64": base64.b64encode(b'{"decision":"ALLOW","reason":"Valid access"}').decode(),
            "auth_tag_b64": base64.b64encode(b"response_auth_tag").decode()
        },
        "server_signature": base64.b64encode(b"server_dilithium_sig" * 100).decode(),
        "status": "success"
    }
    
    traffic_data = {
        'timestamp': datetime.now().isoformat(),
        'direction': 'RESPONSE', 
        'service': 'SERVER',
        'status_code': 200,
        'data': server_response
    }
    
    interceptor.log_intercepted_traffic(traffic_data)
    
    print(f"\n📊 SIMULATION COMPLETE")
    print(f"📁 Total traffic captured: {len(interceptor.captured_traffic)}")

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == 'server':
        # Start interceptor server
        start_interceptor_server()
    else:
        # Run simulation
        simulate_realistic_traffic()