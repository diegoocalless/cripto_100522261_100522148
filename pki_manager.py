"""
Módulo de Gestión de PKI y Certificados X.509 - Entregable 2
"""

import os
import json
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

class PKIManager:
    """
    Gestiona la infraestructura de clave pública (PKI).
    Implementa una jerarquía de dos niveles:
    - AC1: Autoridad Certificadora Raíz (autofirmada)
    - AC2: Autoridad Certificadora Subordinada (firmada por AC1)
    - Usuarios: Certificados de usuario (firmados por AC2)
    """
    
    def __init__(self, base_dir='pki_data'):
        self.base_dir = base_dir
        self.ca_root_dir = os.path.join(base_dir, 'AC1')
        self.ca_sub_dir = os.path.join(base_dir, 'AC2')
        self.users_cert_dir = os.path.join(base_dir, 'user_certificates')
        
        # Crear estructura de directorios
        for directory in [self.ca_root_dir, self.ca_sub_dir, self.users_cert_dir]:
            if not os.path.exists(directory):
                os.makedirs(directory)
                print(f"[INFO] Directorio creado: {directory}")
        
        # Archivo de registro de certificados
        self.cert_registry = os.path.join(base_dir, 'certificate_registry.json')
        self.registry = self._load_registry()
    
    def _load_registry(self):
        """Carga el registro de certificados emitidos"""
        if os.path.exists(self.cert_registry):
            with open(self.cert_registry, 'r') as f:
                return json.load(f)
        return {
            'root_ca': None,
            'subordinate_ca': None,
            'user_certificates': {}
        }
    
    def _save_registry(self):
        """Guarda el registro de certificados"""
        with open(self.cert_registry, 'w') as f:
            json.dump(self.registry, f, indent=2)
    
    def create_root_ca(self, password, common_name="AC1-ROOT", 
                       organization="SecureMessaging PKI",
                       country="ES", validity_days=3650):
        """
        Crea la Autoridad Certificadora Raíz (AC1).
        Genera un certificado autofirmado.
        """
        print(f"\n[INFO] Creando Autoridad Certificadora Raíz (AC1)...")
        
        # Generar par de claves RSA-2048
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Crear el nombre del sujeto
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name)
        ])
        
        # Crear certificado autofirmado
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(tz=timezone.utc)
        ).not_valid_after(
            datetime.now(tz=timezone.utc) + timedelta(days=validity_days)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        # Guardar clave privada cifrada
        private_key_path = os.path.join(self.ca_root_dir, 'ac1_private_key.pem')
        with open(private_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
            ))
        
        # Guardar certificado
        cert_path = os.path.join(self.ca_root_dir, 'ac1_certificate.pem')
        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Actualizar registro
        self.registry['root_ca'] = {
            'common_name': common_name,
            'serial_number': str(cert.serial_number),
            'not_before': cert.not_valid_before_utc.isoformat(),
            'not_after': cert.not_valid_after_utc.isoformat(),
            'created_at': datetime.now().isoformat()
        }
        self._save_registry()
        
        print(f"[SUCCESS] AC Raíz creada correctamente")
        print(f"  - Nombre: {common_name}")
        print(f"  - Algoritmo: RSA-2048")
        print(f"  - Hash: SHA-256")
        print(f"  - Validez: {validity_days} días")
        print(f"  - Número de serie: {cert.serial_number}")
        print(f"  - Clave privada: {private_key_path} (CIFRADA)")
        print(f"  - Certificado: {cert_path}")
        
        return True
    
    def create_subordinate_ca(self, root_password, sub_password,
                              common_name="AC2-SUBORDINATE",
                              organization="SecureMessaging PKI",
                              country="ES", validity_days=1825):
        """
        Crea una Autoridad Certificadora Subordinada (AC2).
        Certificado firmado por la AC Raíz.
        """
        print(f"\n[INFO] Creando Autoridad Certificadora Subordinada (AC2)...")
        
        # Cargar clave privada de AC1
        root_key_path = os.path.join(self.ca_root_dir, 'ac1_private_key.pem')
        with open(root_key_path, 'rb') as f:
            root_private_key = serialization.load_pem_private_key(
                f.read(),
                password=root_password.encode(),
                backend=default_backend()
            )
        
        # Cargar certificado de AC1
        root_cert_path = os.path.join(self.ca_root_dir, 'ac1_certificate.pem')
        with open(root_cert_path, 'rb') as f:
            root_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        # Generar par de claves para AC2
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Crear nombre del sujeto para AC2
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name)
        ])
        
        # Crear certificado firmado por AC1
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            root_cert.subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(tz=timezone.utc)
        ).not_valid_after(
            datetime.now(tz=timezone.utc) + timedelta(days=validity_days)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_private_key.public_key()),
            critical=False,
        ).sign(root_private_key, hashes.SHA256(), default_backend())
        
        # Guardar clave privada de AC2 cifrada
        private_key_path = os.path.join(self.ca_sub_dir, 'ac2_private_key.pem')
        with open(private_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(sub_password.encode())
            ))
        
        # Guardar certificado de AC2
        cert_path = os.path.join(self.ca_sub_dir, 'ac2_certificate.pem')
        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Actualizar registro
        self.registry['subordinate_ca'] = {
            'common_name': common_name,
            'serial_number': str(cert.serial_number),
            'not_before': cert.not_valid_before_utc.isoformat(),
            'not_after': cert.not_valid_after_utc.isoformat(),
            'issued_by': self.registry['root_ca']['common_name'],
            'created_at': datetime.now().isoformat()
        }
        self._save_registry()
        
        print(f"[SUCCESS] AC Subordinada creada correctamente")
        print(f"  - Nombre: {common_name}")
        print(f"  - Emisor: {root_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
        print(f"  - Algoritmo: RSA-2048")
        print(f"  - Hash: SHA-256")
        print(f"  - Validez: {validity_days} días")
        print(f"  - Número de serie: {cert.serial_number}")
        print(f"  - Clave privada: {private_key_path} (CIFRADA)")
        print(f"  - Certificado: {cert_path}")
        
        return True
    
    def issue_user_certificate(self, username, user_public_key, ca_password,
                               email=None, validity_days=365):
        """
        Emite un certificado de usuario firmado por AC2.
        """
        print(f"\n[INFO] Emitiendo certificado para usuario: {username}...")
        
        # Cargar clave privada de AC2
        ca_key_path = os.path.join(self.ca_sub_dir, 'ac2_private_key.pem')
        with open(ca_key_path, 'rb') as f:
            ca_private_key = serialization.load_pem_private_key(
                f.read(),
                password=ca_password.encode(),
                backend=default_backend()
            )
        
        # Cargar certificado de AC2
        ca_cert_path = os.path.join(self.ca_sub_dir, 'ac2_certificate.pem')
        with open(ca_cert_path, 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        # Crear nombre del sujeto
        subject_attrs = [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMessaging Users"),
            x509.NameAttribute(NameOID.COMMON_NAME, username)
        ]
        
        if email:
            subject_attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
        
        subject = x509.Name(subject_attrs)
        
        # Crear certificado de usuario
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            user_public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(tz=timezone.utc)
        ).not_valid_after(
            datetime.now(tz=timezone.utc) + timedelta(days=validity_days)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=True,
                key_cert_sign=False,
                crl_sign=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(user_public_key),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
            critical=False,
        ).sign(ca_private_key, hashes.SHA256(), default_backend())
        
        # Guardar certificado de usuario
        cert_path = os.path.join(self.users_cert_dir, f'{username}_certificate.pem')
        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Actualizar registro
        self.registry['user_certificates'][username] = {
            'serial_number': str(cert.serial_number),
            'not_before': cert.not_valid_before_utc.isoformat(),
            'not_after': cert.not_valid_after_utc.isoformat(),
            'issued_by': self.registry['subordinate_ca']['common_name'],
            'email': email,
            'created_at': datetime.now().isoformat()
        }
        self._save_registry()
        
        print(f"[SUCCESS] Certificado emitido para {username}")
        print(f"  - Emisor: {ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
        print(f"  - Número de serie: {cert.serial_number}")
        print(f"  - Validez: {validity_days} días")
        print(f"  - Certificado: {cert_path}")
        
        return cert_path
    
    def verify_certificate_chain(self, user_cert_path):
        """
        Verifica la cadena de certificación completa:
        Usuario -> AC2 -> AC1
        """
        try:
            print(f"\n[INFO] Verificando cadena de certificación...")
            
            # Cargar certificados
            with open(user_cert_path, 'rb') as f:
                user_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
            ac2_cert_path = os.path.join(self.ca_sub_dir, 'ac2_certificate.pem')
            with open(ac2_cert_path, 'rb') as f:
                ac2_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
            ac1_cert_path = os.path.join(self.ca_root_dir, 'ac1_certificate.pem')
            with open(ac1_cert_path, 'rb') as f:
                ac1_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
            # Verificar que el certificado de usuario fue firmado por AC2
            ac2_public_key = ac2_cert.public_key()
            ac2_public_key.verify(
                user_cert.signature,
                user_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                user_cert.signature_hash_algorithm
            )
            print(f"  Certificado de usuario firmado por AC2")
            
            # Verificar que AC2 fue firmado por AC1
            ac1_public_key = ac1_cert.public_key()
            ac1_public_key.verify(
                ac2_cert.signature,
                ac2_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                ac2_cert.signature_hash_algorithm
            )
            print(f"  Certificado de AC2 firmado por AC1")
            
            # Verificar que AC1 está autofirmado
            ac1_public_key.verify(
                ac1_cert.signature,
                ac1_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                ac1_cert.signature_hash_algorithm
            )
            print(f"  Certificado de AC1 autofirmado")
            
            # Verificar fechas de validez
            now = datetime.now(tz=timezone.utc)
            if user_cert.not_valid_before_utc <= now <= user_cert.not_valid_after_utc:
                print(f"  Certificado de usuario dentro del período de validez")
            else:
                print(f"  Certificado de usuario fuera del período de validez")
                return False
            
            print(f"\n[SUCCESS] Cadena de certificación VÁLIDA")
            print(f"  Usuario -> AC2 -> AC1 (Raíz)")
            
            return True
            
        except Exception as e:
            print(f"[ERROR] Cadena de certificación INVÁLIDA: {str(e)}")
            return False
    
    def get_certificate_info(self, cert_path):
        """
        Obtiene información detallada de un certificado.
        """
        try:
            with open(cert_path, 'rb') as f:
                cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
            subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            
            info = {
                'subject': subject_cn,
                'issuer': issuer_cn,
                'serial_number': cert.serial_number,
                'not_before': cert.not_valid_before_utc.isoformat(),
                'not_after': cert.not_valid_after_utc.isoformat(),
                'signature_algorithm': cert.signature_algorithm_oid._name
            }
            
            return info
        except Exception as e:
            print(f"[ERROR] No se pudo leer el certificado: {str(e)}")
            return None