"""
Módulo de Autenticación de Mensajes - Entregable 2
"""

import os
import base64
import hashlib
import hmac

class MessageAuthentication:
    """
    Gestiona códigos de autenticación de mensajes usando HMAC-SHA256.
    Proporciona integridad y autenticidad de los mensajes.
    """
    
    def __init__(self):
        self.key_length = 32  # 256 bits
    
    def generate_key(self):
        """
        Genera una clave aleatoria para HMAC.
        """
        key = os.urandom(self.key_length)
        print(f"[DEBUG] Clave HMAC generada:")
        print(f"  - Algoritmo: HMAC-SHA256")
        print(f"  - Longitud: {len(key)} bytes (256 bits)")
        return key
    
    def generate_mac(self, message, key):
        """
        Genera un MAC para un mensaje usando HMAC-SHA256.
        """
        mac = hmac.new(key, message.encode(), hashlib.sha256).digest()
        
        print(f"[DEBUG] MAC generado:")
        print(f"  - Algoritmo: HMAC-SHA256")
        print(f"  - Longitud de clave: {len(key)} bytes")
        print(f"  - Longitud de MAC: {len(mac)} bytes")
        print(f"  - Mensaje: {len(message)} caracteres")
        
        return base64.b64encode(mac).decode()
    
    def verify_mac(self, message, mac, key):
        """
        Verifica un MAC de un mensaje.
        """
        try:
            expected_mac = hmac.new(key, message.encode(), hashlib.sha256).digest()
            received_mac = base64.b64decode(mac)
            
            if hmac.compare_digest(expected_mac, received_mac):
                print(f"[DEBUG] Verificación de MAC:")
                print(f"  - Algoritmo: HMAC-SHA256")
                print(f"  - Resultado: VÁLIDO")
                return True
            else:
                print(f"[ERROR] Verificación de MAC falló: MAC no coincide")
                return False
        
        except Exception as e:
            print(f"[ERROR] Verificación de MAC falló: {str(e)}")
            return False