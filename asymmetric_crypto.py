"""
Módulo de Cifrado Asimétrico - Entregable 2
Implementa cifrado híbrido RSA + AES
"""

import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

class AsymmetricEncryption:
    """
    Gestiona cifrado asimétrico usando RSA-2048.
    Se utiliza para cifrar claves simétricas (cifrado híbrido).
    """
    
    def __init__(self):
        self.key_size = 2048  # bits
    
    def generate_key_pair(self):
        """
        Genera un par de claves RSA (pública y privada).
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        print(f"[DEBUG] Par de claves RSA generado:")
        print(f"  - Algoritmo: RSA")
        print(f"  - Longitud: {self.key_size} bits")
        
        return private_key, public_key
    
    def save_private_key(self, private_key, filename, password):
        """
        Guarda la clave privada cifrada con contraseña.
        """
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )
        
        with open(filename, 'wb') as f:
            f.write(pem)
        
        print(f"[DEBUG] Clave privada guardada en {filename}")
        print(f"  - Protección: Cifrada con contraseña")
        print(f"  - Algoritmo de protección: PKCS8 + AES")
    
    def load_private_key(self, filename, password):
        """
        Carga la clave privada desde archivo.
        """
        try:
            with open(filename, 'rb') as f:
                pem = f.read()
            
            private_key = serialization.load_pem_private_key(
                pem,
                password=password.encode(),
                backend=default_backend()
            )
            
            print(f"[DEBUG] Clave privada cargada desde {filename}")
            return private_key
        
        except FileNotFoundError:
            print(f"[ERROR] Archivo {filename} no encontrado")
            return None
        except ValueError:
            print(f"[ERROR] Contraseña incorrecta o archivo corrupto")
            return None
    
    def save_public_key(self, public_key, filename):
        """
        Guarda la clave pública (sin cifrar)
        """
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(filename, 'wb') as f:
            f.write(pem)
        
        print(f"[DEBUG] Clave pública guardada en {filename}")
    
    def load_public_key(self, filename):
        """
        Carga la clave pública desde archivo.
        """
        try:
            with open(filename, 'rb') as f:
                pem = f.read()
            
            public_key = serialization.load_pem_public_key(
                pem,
                backend=default_backend()
            )
            
            print(f"[DEBUG] Clave pública cargada desde {filename}")
            return public_key
        
        except FileNotFoundError:
            print(f"[ERROR] Archivo {filename} no encontrado")
            return None
    
    def encrypt_key(self, symmetric_key, public_key):
        """
        Cifra una clave simétrica usando RSA con la clave pública del receptor.
        Usa OAEP con SHA-256.
        """
        encrypted_key = public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        print(f"[DEBUG] Clave simétrica cifrada con RSA:")
        print(f"  - Algoritmo: RSA-2048 con OAEP-SHA256")
        print(f"  - Longitud clave simétrica: {len(symmetric_key)} bytes")
        print(f"  - Longitud clave cifrada: {len(encrypted_key)} bytes")
        
        return base64.b64encode(encrypted_key).decode()
    
    def decrypt_key(self, encrypted_key_b64, private_key):
        """
        Descifra una clave simétrica usando RSA con la clave privada.
        """
        try:
            encrypted_key = base64.b64decode(encrypted_key_b64)
            
            symmetric_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            print(f"[DEBUG] Clave simétrica descifrada con RSA:")
            print(f"  - Algoritmo: RSA-2048 con OAEP-SHA256")
            print(f"  - Longitud clave recuperada: {len(symmetric_key)} bytes")
            
            return symmetric_key
        
        except Exception as e:
            print(f"[ERROR] Fallo al descifrar clave: {str(e)}")
            return None