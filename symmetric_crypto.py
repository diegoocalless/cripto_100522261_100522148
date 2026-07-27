"""
Módulo de Cifrado Simétrico - Entregable 2
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class SymmetricEncryption:
    """
    Gestiona cifrado y descifrado simétrico usando AES-256-GCM.
    AES-GCM proporciona cifrado autenticado (confidencialidad + autenticidad).
    """
    
    def __init__(self):
        self.key_length = 32  # 256 bits para AES-256
        self.nonce_length = 12  # 96 bits recomendado para GCM
    
    def generate_key(self):
        """
        Genera una clave simétrica aleatoria de 256 bits.
        """
        key = os.urandom(self.key_length)
        print(f"[DEBUG] Clave simétrica generada:")
        print(f"  - Algoritmo: AES-256-GCM")
        print(f"  - Longitud: {len(key)} bytes (256 bits)")
        return key
    
    def encrypt(self, plaintext, key):
        """
        Cifra un mensaje usando AES-256-GCM.
        """
        nonce = os.urandom(self.nonce_length)
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        tag = encryptor.tag
        
        print(f"[DEBUG] Cifrado simétrico completado:")
        print(f"  - Algoritmo: AES-256-GCM")
        print(f"  - Longitud de clave: {len(key)} bytes")
        print(f"  - Longitud de nonce: {len(nonce)} bytes")
        print(f"  - Longitud de tag: {len(tag)} bytes")
        print(f"  - Texto plano: {len(plaintext)} caracteres")
        print(f"  - Texto cifrado: {len(ciphertext)} bytes")
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'tag': base64.b64encode(tag).decode()
        }
    
    def decrypt(self, encrypted_data, key):
        """
        Descifra un mensaje usando AES-256-GCM.
        """
        try:
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            nonce = base64.b64decode(encrypted_data['nonce'])
            tag = base64.b64decode(encrypted_data['tag'])
            
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            print(f"[DEBUG] Descifrado simétrico completado:")
            print(f"  - Algoritmo: AES-256-GCM")
            print(f"  - Verificación de autenticidad: EXITOSA")
            print(f"  - Texto descifrado: {len(plaintext.decode())} caracteres")
            
            return plaintext.decode()
        
        except Exception as e:
            print(f"[ERROR] Fallo en descifrado/verificación: {str(e)}")
            return None