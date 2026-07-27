"""
Módulo de Autenticación de Usuarios - Entregable 2
"""

import os
import json
import base64
import hmac
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

class UserAuthentication:
    """
    Gestiona el registro y autenticación de usuarios.
    Las contraseñas se almacenan usando PBKDF2 con salt aleatorio.
    """
    
    def __init__(self, users_file='users.json'):
        self.users_file = users_file
        self.users = self._load_users()
        # Parámetros de PBKDF2
        self.pbkdf2_iterations = 600000  # 600k iteraciones
        self.salt_length = 32  # 256 bits
        self.hash_length = 32  # 256 bits
    
    def _load_users(self):
        """Carga usuarios desde archivo JSON"""
        if os.path.exists(self.users_file):
            with open(self.users_file, 'r') as f:
                return json.load(f)
        return {}
    
    def _save_users(self):
        """Guarda usuarios en archivo JSON"""
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f, indent=2)
    
    def _hash_password(self, password, salt=None):
        """
        Genera hash de contraseña usando PBKDF2-HMAC-SHA256.
        """
        if salt is None:
            salt = os.urandom(self.salt_length)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.hash_length,
            salt=salt,
            iterations=self.pbkdf2_iterations,
            backend=default_backend()
        )
        
        key = kdf.derive(password.encode())
        
        print(f"[DEBUG] Password hashing:")
        print(f"  - Algoritmo: PBKDF2-HMAC-SHA256")
        print(f"  - Iteraciones: {self.pbkdf2_iterations}")
        print(f"  - Longitud salt: {len(salt)} bytes")
        print(f"  - Longitud hash: {len(key)} bytes")
        
        return base64.b64encode(key).decode(), base64.b64encode(salt).decode()
    
    def register_user(self, username, password):
        """
        Registra un nuevo usuario.
        """
        if username in self.users:
            print(f"[ERROR] El usuario '{username}' ya existe")
            return False
        
        if not self._validate_password_strength(password):
            return False
        
        password_hash, salt = self._hash_password(password)
        
        self.users[username] = {
            'password_hash': password_hash,
            'salt': salt,
            'created_at': datetime.now().isoformat()
        }
        
        self._save_users()
        print(f"[SUCCESS] Usuario '{username}' registrado correctamente")
        return True
    
    def _validate_password_strength(self, password):
        """
        Valida que la contraseña sea robusta.
        Requisitos: mínimo 8 caracteres, mayúsculas, minúsculas, números
        """
        if len(password) < 8:
            print("[ERROR] La contraseña debe tener al menos 8 caracteres")
            return False
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        
        if not (has_upper and has_lower and has_digit):
            print("[ERROR] La contraseña debe contener mayúsculas, minúsculas y números")
            return False
        
        return True
    
    def authenticate_user(self, username, password):
        """
        Autentica un usuario verificando su contraseña.
        """

        self.users = self._load_users()

        if username not in self.users:
            print(f"[ERROR] El usuario '{username}' no existe")
            return False
        
        user_data = self.users[username]
        stored_hash = base64.b64decode(user_data['password_hash'])
        salt = base64.b64decode(user_data['salt'])
        
        calculated_hash, _ = self._hash_password(password, salt)
        calculated_hash = base64.b64decode(calculated_hash)
        
        if hmac.compare_digest(stored_hash, calculated_hash):
            print(f"[SUCCESS] Usuario '{username}' autenticado correctamente")
            return True
        else:
            print(f"[ERROR] Contraseña incorrecta para el usuario '{username}'")
            return False
    
    def derive_key_from_password(self, username, password):
        """
        Deriva una clave de cifrado a partir de la contraseña del usuario.
        """
        if not self.authenticate_user(username, password):
            return None
        
        user_data = self.users[username]
        salt = base64.b64decode(user_data['salt'])
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.pbkdf2_iterations,
            backend=default_backend()
        )
        
        key = kdf.derive(password.encode())
        
        print(f"[DEBUG] Clave derivada de contraseña:")
        print(f"  - Algoritmo: PBKDF2-HMAC-SHA256")
        print(f"  - Longitud de clave: {len(key)} bytes (256 bits)")
        
        return key