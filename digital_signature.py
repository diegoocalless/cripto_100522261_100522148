"""
Módulo de Firma Digital - Entregable 2
"""

import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

class DigitalSignature:
    """
    Gestiona la generación y verificación de firmas digitales usando RSA.
    Utiliza RSA-PSS con SHA-256.
    """
    
    def __init__(self):
        self.hash_algorithm = hashes.SHA256()
    
    def sign_message(self, message, private_key):
        """
        Firma un mensaje usando RSA-PSS con SHA-256.
        """
        try:
            # Convertir mensaje a bytes
            message_bytes = message.encode('utf-8')
            
            # Generar firma usando RSA-PSS
            signature = private_key.sign(
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(self.hash_algorithm),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                self.hash_algorithm
            )
            
            print(f"[DEBUG] Firma digital generada:")
            print(f"  - Algoritmo: RSA-PSS con SHA-256")
            print(f"  - Longitud del mensaje: {len(message)} caracteres")
            print(f"  - Longitud de la firma: {len(signature)} bytes")
            
            return base64.b64encode(signature).decode()
        
        except Exception as e:
            print(f"[ERROR] Fallo al generar firma: {str(e)}")
            return None
    
    def verify_signature(self, message, signature_b64, public_key):
        """
        Verifica una firma digital usando RSA-PSS con SHA-256.
        """
        try:
            # Decodificar firma
            signature = base64.b64decode(signature_b64)
            message_bytes = message.encode('utf-8')
            
            # Verificar firma
            public_key.verify(
                signature,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(self.hash_algorithm),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                self.hash_algorithm
            )
            
            print(f"[DEBUG] Verificación de firma digital:")
            print(f"  - Algoritmo: RSA-PSS con SHA-256")
            print(f"  - Resultado: VÁLIDA")
            
            return True
        
        except InvalidSignature:
            print(f"[ERROR] Firma digital INVÁLIDA")
            print(f"  - El mensaje puede haber sido alterado")
            print(f"  - O la firma no corresponde a este mensaje")
            return False
        
        except Exception as e:
            print(f"[ERROR] Error al verificar firma: {str(e)}")
            return False
    
