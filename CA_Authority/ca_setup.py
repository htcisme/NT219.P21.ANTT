import json
import os
import oqs
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

import base64

class InternalCA:
    def __init__(self):
        ca_dir = "certificates"
        
        # Kiểm tra và xử lý nếu certificates là file thay vì thư mục
        if os.path.exists(ca_dir):
            if os.path.isfile(ca_dir):
                # Nếu là file, xóa file và tạo thư mục
                os.remove(ca_dir)
                os.makedirs(ca_dir, exist_ok=True)
                print(f"Removed file '{ca_dir}' and created directory")
            elif os.path.isdir(ca_dir):
                # Nếu là thư mục, không làm gì
                print(f"Directory '{ca_dir}' already exists")
        else:
            # Nếu không tồn tại, tạo thư mục
            os.makedirs(ca_dir, exist_ok=True)
            print(f"Created directory '{ca_dir}'")
        
        self.ca_dir = ca_dir
        self.ca_config_file = "ca_config.json"
        self.signature_algorithm = "Dilithium2"  # Sử dụng Dilithium2 từ liboqs
        
        # Initialize CA keys as None
        self.ca_private_key = None
        self.ca_public_key = None
        
    def setup_ca(self):
        """Thiết lập CA với khóa Dilithium từ liboqs"""
        print(f"Setting up Internal CA with {self.signature_algorithm}...")
        
        # Tạo signer với Dilithium2 (không truyền secret_key khi tạo mới)
        signer = oqs.Signature(self.signature_algorithm)
        
        # Tạo keypair cho CA
        self.ca_public_key = signer.generate_keypair()
        self.ca_private_key = signer.export_secret_key()
        
        # Lưu CA private key vào file
        ca_private_key_path = os.path.join(self.ca_dir, "ca_private_key.key")
        with open(ca_private_key_path, "wb") as f:
            f.write(self.ca_private_key)
        
        # Lưu CA public key vào file
        ca_public_key_path = os.path.join(self.ca_dir, "ca_public_key.key") 
        with open(ca_public_key_path, "wb") as f:
            f.write(self.ca_public_key)
        
        # Tạo config cho CA
        ca_config = {
            "ca_info": {
                "name": "Secure Access Internal CA",
                "version": "1.0",
                "signature_algorithm": self.signature_algorithm,
                "created": "2024-01-01"
            },
            "ca_public_key": base64.b64encode(self.ca_public_key).decode(),
            "certificates_issued": []
        }
        
        # Lưu config
        with open(self.ca_config_file, "w") as f:
            json.dump(ca_config, f, indent=2)
        
        print(f"✓ CA setup completed")
        print(f"  - CA private key saved to: {ca_private_key_path}")
        print(f"  - CA public key saved to: {ca_public_key_path}")
        print(f"  - CA config saved to: {self.ca_config_file}")
        
        return self.ca_public_key, self.ca_private_key
    
    def generate_entity_keypair(self):
        """Tạo keypair cho entity (Reader/Server)"""
        signer = oqs.Signature(self.signature_algorithm)
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()
        return public_key, private_key
    
    def issue_certificate(self, entity_id, entity_type, entity_public_key):
        """Cấp certificate cho entity"""
        print(f"Issuing certificate for {entity_id} ({entity_type})...")
        
        # Sử dụng CA private key đã có trong memory hoặc đọc từ file
        if self.ca_private_key is None:
            ca_private_key_path = os.path.join(self.ca_dir, "ca_private_key.key")
            if not os.path.exists(ca_private_key_path):
                raise FileNotFoundError(f"CA private key not found at {ca_private_key_path}. Please run setup_ca() first.")
            
            with open(ca_private_key_path, "rb") as f:
                self.ca_private_key = f.read()
        
        # Đọc CA config
        if not os.path.exists(self.ca_config_file):
            raise FileNotFoundError(f"CA config not found at {self.ca_config_file}. Please run setup_ca() first.")
            
        with open(self.ca_config_file, "r") as f:
            ca_config = json.load(f)
        
        # Tạo certificate data
        cert_data = {
            "entity_id": entity_id,
            "entity_type": entity_type,
            "public_key": base64.b64encode(entity_public_key).decode(),
            "ca_public_key": ca_config["ca_public_key"],
            "signature_algorithm": self.signature_algorithm,
            "issued_date": "2024-01-01",
            "expiry_date": "2025-01-01"
        }
        
        # Tạo message để ký
        cert_message = json.dumps(cert_data, sort_keys=True).encode()
        
        # Ký certificate bằng CA private key
        signer = oqs.Signature(self.signature_algorithm, secret_key=self.ca_private_key)
        signature = signer.sign(cert_message)
        
        # Tạo certificate hoàn chỉnh
        certificate = {
            "certificate_data": cert_data,
            "signature": base64.b64encode(signature).decode()
        }
        
        # Cập nhật CA config
        ca_config["certificates_issued"].append({
            "entity_id": entity_id,
            "entity_type": entity_type,
            "issued_date": "2024-01-01"
        })
        
        with open(self.ca_config_file, "w") as f:
            json.dump(ca_config, f, indent=2)
        
        print(f"✓ Certificate issued for {entity_id}")
        return certificate
    
    def create_entity_certificate_file(self, entity_id, entity_type, entity_public_key, entity_private_key):
        """Tạo file certificate hoàn chỉnh cho entity"""
        certificate = self.issue_certificate(entity_id, entity_type, entity_public_key)
        
        # Tạo file certificate với private key
        entity_cert_data = {
            "entity_id": entity_id,
            "private_key": base64.b64encode(entity_private_key).decode(),
            "certificate": certificate
        }
        
        # Lưu vào file
        cert_filename = f"{entity_type}_cert.json"
        cert_path = os.path.join(self.ca_dir, cert_filename)
        with open(cert_path, "w") as f:
            json.dump(entity_cert_data, f, indent=2)
        
        print(f"✓ Certificate file created: {cert_path}")
        return cert_path

def main():
    print("=" * 40)
    print("SECURE ACCESS CONTROL SYSTEM - CA SETUP")
    print("=" * 40)
    
    # Khởi tạo CA
    ca = InternalCA()
    
    # Setup CA
    print("\nSETTING UP CERTIFICATE AUTHORITY")
    print("=" * 40)
    ca_public_key, ca_private_key = ca.setup_ca()
    
    # Kiểm tra CA keys đã được tạo
    if ca.ca_private_key is None:
        print("ERROR: CA private key not properly initialized!")
        return
    
    # Tạo keypairs cho các entities
    print("\nGENERATING ENTITY KEYPAIRS")
    print("=" * 40)
    print("Generating Dilithium keypairs for Reader and Server...")
    
    # Tạo keypair cho Reader
    reader_public_key, reader_private_key = ca.generate_entity_keypair()
    print(f"✓ Reader keypair generated (pub: {len(reader_public_key)} bytes, priv: {len(reader_private_key)} bytes)")
    
    # Tạo keypair cho Server
    server_public_key, server_private_key = ca.generate_entity_keypair()
    print(f"✓ Server keypair generated (pub: {len(server_public_key)} bytes, priv: {len(server_private_key)} bytes)")
    
    # Cấp certificates
    print("\n" + "=" * 40)
    print("ISSUING CERTIFICATES")
    print("=" * 40)
    
    # Cấp certificate cho Reader
    reader_cert_path = ca.create_entity_certificate_file(
        "reader_pi_01", "reader", reader_public_key, reader_private_key
    )
    
    # Cấp certificate cho Server
    server_cert_path = ca.create_entity_certificate_file(
        "management_server_01", "server", server_public_key, server_private_key
    )
    
    print("\n" + "=" * 40)
    print("CA SETUP COMPLETED SUCCESSFULLY!")
    print("=" * 40)
    print(f"✓ Reader certificate: {reader_cert_path}")
    print(f"✓ Server certificate: {server_cert_path}")
    print(f"✓ CA configuration: {ca.ca_config_file}")
    print("\nThe CA is now ready to authenticate secure communications.")

if __name__ == "__main__":
    main()