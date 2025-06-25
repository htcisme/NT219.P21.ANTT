import base64
import json
import oqs
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class ReaderCrypto:
    def __init__(self, certificate_file, ca_public_key_file):
        # Load certificate (chứa cả private key)
        with open(certificate_file, 'r') as f:
            cert_data = json.load(f)
            
        # Extract private key từ certificate JSON
        self.dilithium_private_key = base64.b64decode(cert_data['private_key'])
        self.certificate = cert_data['certificate']
            
        # Load CA public key
        with open(ca_public_key_file, 'rb') as f:
            self.ca_public_key = f.read()
            
        # Get signature algorithm from certificate
        self.signature_algorithm = self.certificate['certificate_data']['signature_algorithm']
        print(f"Reader using signature algorithm: {self.signature_algorithm}")
        print(f"Reader entity ID: {cert_data['entity_id']}")
        
        # Generate ECDH key pair for this session
        self.ecdh_private_key = ec.generate_private_key(ec.SECP256R1())
        
    def get_ecdh_public_key_b64(self):
        """Lấy khóa công khai ECDH dưới dạng base64"""
        public_key_bytes = self.ecdh_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(public_key_bytes).decode()
    
    def sign_data(self, data):
        """Ký dữ liệu bằng Dilithium từ liboqs"""
        if isinstance(data, str):
            data = data.encode()
            
        signer = oqs.Signature(self.signature_algorithm, secret_key=self.dilithium_private_key)
        signature = signer.sign(data)
        return base64.b64encode(signature).decode()
    
    def verify_certificate(self, certificate):
        """Xác thực certificate bằng CA public key"""
        try:
            cert_json = json.dumps(certificate["certificate_data"], sort_keys=True)
            signature = base64.b64decode(certificate["signature"])
            
            verifier = oqs.Signature(self.signature_algorithm)
            is_valid = verifier.verify(cert_json.encode(), signature, self.ca_public_key)
            
            return is_valid
        except Exception as e:
            print(f"Certificate verification failed: {e}")
            return False
    
    def verify_signature(self, public_key_b64, data, signature_b64):
        """Xác thực chữ ký từ entity khác"""
        try:
            public_key = base64.b64decode(public_key_b64)
            if isinstance(data, str):
                data = data.encode()
            signature = base64.b64decode(signature_b64)
            
            verifier = oqs.Signature(self.signature_algorithm)
            is_valid = verifier.verify(data, signature, public_key)
            
            return is_valid
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False
    
    def perform_ecdh_with_server(self, server_public_key_b64):
        """Thực hiện ECDH với server"""
        server_public_key_bytes = base64.b64decode(server_public_key_b64)
        server_public_key = serialization.load_der_public_key(server_public_key_bytes)
        
        shared_key = self.ecdh_private_key.exchange(ec.ECDH(), server_public_key)
        
        # Derive AES key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'reader-server-session',
        ).derive(shared_key)
        
        return derived_key
    
    def encrypt_data(self, data, aes_key):
        """Mã hóa dữ liệu bằng AES-GCM sử dụng cryptography"""
        if isinstance(data, dict):
            data = json.dumps(data).encode()
        elif isinstance(data, str):
            data = data.encode()
            
        # Tạo nonce 12 bytes cho GCM
        nonce = os.urandom(12)
        
        # Sử dụng AESGCM từ cryptography
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        return {
            "nonce_b64": base64.b64encode(nonce).decode(),
            "ciphertext_b64": base64.b64encode(ciphertext).decode()
        }
    
    def decrypt_data(self, encrypted_data, aes_key):
        """Giải mã dữ liệu AES-GCM sử dụng cryptography"""
        nonce = base64.b64decode(encrypted_data["nonce_b64"])
        ciphertext = base64.b64decode(encrypted_data["ciphertext_b64"])
        
        # Sử dụng AESGCM từ cryptography
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        return plaintext.decode()