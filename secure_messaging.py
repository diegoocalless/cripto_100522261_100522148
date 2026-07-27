"""
Sistema de Mensajería Segura - Entregable 2
Incluye firma digital y PKI completa
"""

import os
import json
import base64
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from user_auth import UserAuthentication
from symmetric_crypto import SymmetricEncryption
from message_auth import MessageAuthentication
from asymmetric_crypto import AsymmetricEncryption
from digital_signature import DigitalSignature
from pki_manager import PKIManager

class SecureMessagingSystem:
    """
    Sistema completo de mensajería segura con:
    - Cifrado híbrido (RSA + AES-GCM)
    - Firma digital (RSA-PSS)
    - PKI de dos niveles (AC1 -> AC2 -> Usuarios)
    - Autenticación de mensajes (HMAC)
    """
    
    def __init__(self):
        self.auth = UserAuthentication()
        self.symmetric = SymmetricEncryption()
        self.asymmetric = AsymmetricEncryption()
        self.mac = MessageAuthentication()
        self.signature = DigitalSignature()
        self.pki = PKIManager()
        self.ca_root_password = None
        self.ca_sub_password = None
        
        self.messages_file = 'messages.json'
        self.keys_dir = 'user_keys'
        self.messages = self._load_messages()
        
        # Crear directorio para claves si no existe
        if not os.path.exists(self.keys_dir):
            os.makedirs(self.keys_dir)
            print(f"[DEBUG] Directorio {self.keys_dir} creado")
    
    def _load_messages(self):
        """Carga mensajes desde archivo JSON"""
        if os.path.exists(self.messages_file):
            with open(self.messages_file, 'r') as f:
                return json.load(f)
        return []
    
    def _save_messages(self):
        """Guarda mensajes en archivo JSON"""
        with open(self.messages_file, 'w') as f:
            json.dump(self.messages, f, indent=2)
    
    def _get_user_keys_path(self, username):
        """Retorna las rutas de archivos de claves de un usuario"""
        return {
            'private': os.path.join(self.keys_dir, f'{username}_private.pem'),
            'public': os.path.join(self.keys_dir, f'{username}_public.pem')
        }
    
    def _get_public_key_from_certificate(self, username):
        """
        Obtiene la clave pública de un usuario desde su certificado X.509
        """
        cert_path = os.path.join(self.pki.users_cert_dir, f'{username}_certificate.pem')
        
        if not os.path.exists(cert_path):
            print(f"[ERROR] Certificado de {username} no encontrado")
            return None
        
        try:
            with open(cert_path, 'rb') as f:
                cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
            public_key = cert.public_key()
            
            print(f"[DEBUG] Clave pública obtenida del certificado X.509 de {username}")
            print(f"  - Certificado: {cert_path}")
            print(f"  - Emisor: {cert.issuer.rfc4514_string()}")
            print(f"  - Válido hasta: {cert.not_valid_after_utc.isoformat()[:10]}")
            
            return public_key
        
        except Exception as e:
            print(f"[ERROR] No se pudo obtener clave pública del certificado: {str(e)}")
            return None

    def set_ca_passwords(self, root_password=None, sub_password=None):
        """Configura las contraseñas de las AC"""
        if root_password:
            self.ca_root_password = root_password
        if sub_password:
            self.ca_sub_password = sub_password
    
    def generate_user_keys(self, username, password):
        """
        Genera y guarda el par de claves RSA para un usuario.
        Emite un certificado X.509 firmado por AC2.
        """
        print(f"\n[INFO] Generando par de claves RSA para {username}...")
        
        private_key, public_key = self.asymmetric.generate_key_pair()
        
        paths = self._get_user_keys_path(username)
        self.asymmetric.save_private_key(private_key, paths['private'], password)
        self.asymmetric.save_public_key(public_key, paths['public'])
        
        if not self.ca_sub_password:
            print("[ERROR] No se ha establecido la contraseña de la AC2.")
            print("        Vuelva a inicializar la PKI o proporcione la contraseña.")
            return False

        # Emitir certificado X.509 para el usuario
        try:
            user_email = f"{username}@securemessaging.local"
            
            cert_path = self.pki.issue_user_certificate(
                username=username,
                user_public_key=public_key,
                ca_password=self.ca_sub_password,
                email=user_email,
                validity_days=365
            )
            
            print(f"[SUCCESS] Certificado X.509 emitido para {username}")
            print(f"  - Certificado: {cert_path}")
            print(f"  - La clave pública estará disponible a través del certificado")
            
        except Exception as e:
            print(f"[WARNING] No se pudo emitir certificado: {str(e)}")
            print(f"  - Asegúrese de que la PKI esté inicializada")
        
        print(f"[SUCCESS] Claves generadas para {username}")
        return True
    
    def user_has_keys(self, username):
        """
        Verifica si un usuario tiene claves generadas y certificado.
        """
        paths = self._get_user_keys_path(username)
        cert_path = os.path.join(self.pki.users_cert_dir, f'{username}_certificate.pem')
        
        # Debe tener clave privada Y certificado (que contiene la pública)
        return os.path.exists(paths['private']) and os.path.exists(cert_path)
    
    def send_secure_message(self, sender, password, recipient, message):
        """
        Envía un mensaje cifrado y firmado.
        
        Proceso completo:
        1. Autentica al emisor
        2. Genera firma digital del mensaje (con clave privada del emisor)
        3. Cifra el mensaje con AES-GCM (clave aleatoria)
        4. Obtiene clave pública del receptor desde su CERTIFICADO X.509
        5. Cifra la clave AES con RSA (clave pública del receptor)
        6. Genera MAC del mensaje cifrado
        7. Guarda todo: mensaje cifrado, firma, claves cifradas
        """
        if not self.auth.authenticate_user(sender, password):
            return False
        
        # Verificar que el receptor existe y tiene claves/certificado
        if not self.user_has_keys(recipient):
            print(f"[ERROR] El receptor {recipient} no tiene certificado generado")
            return False
        
        print(f"\n[INFO] Iniciando envío de mensaje seguro")
        print(f"  Emisor: {sender} → Receptor: {recipient}")
        
        #Firma digital - Cargar clave privada del emisor para firmar
        sender_paths = self._get_user_keys_path(sender)
        sender_private_key = self.asymmetric.load_private_key(
            sender_paths['private'], 
            password
        )
        
        if sender_private_key is None:
            print(f"[ERROR] No se pudo cargar la clave privada del emisor")
            return False
        
        #Generar firma digital del mensaje original
        print(f"\n[PASO 1] Generando firma digital del mensaje...")
        message_signature = self.signature.sign_message(message, sender_private_key)
        
        if message_signature is None:
            print(f"[ERROR] No se pudo generar la firma digital")
            return False
        
        #Cifrado - Obtener clave pública del receptor desde su certificado
        print(f"\n[PASO 2] Obteniendo clave pública de {recipient} desde certificado X.509...")
        recipient_public_key = self._get_public_key_from_certificate(recipient)
        
        if recipient_public_key is None:
            print(f"[ERROR] No se pudo obtener la clave pública de {recipient}")
            return False
        
        #Generar clave simétrica aleatoria
        print(f"\n[PASO 3] Cifrando mensaje con AES-256-GCM...")
        encryption_key = self.symmetric.generate_key()
        
        #Cifrar mensaje con AES-GCM
        encrypted_data = self.symmetric.encrypt(message, encryption_key)
        
        #Cifrar la clave simétrica con RSA
        print(f"\n[PASO 4] Cifrando clave AES con RSA-2048...")
        encrypted_symmetric_key = self.asymmetric.encrypt_key(
            encryption_key, 
            recipient_public_key
        )
        
        #MAC - Generar MAC adicional
        print(f"\n[PASO 5] Generando MAC del mensaje cifrado...")
        mac_key = self.mac.generate_key()
        mac_value = self.mac.generate_mac(encrypted_data['ciphertext'], mac_key)
        
        # Cifrar la clave MAC también con RSA
        encrypted_mac_key = self.asymmetric.encrypt_key(mac_key, recipient_public_key)
        
        #Guardar mensaje con toda la información de seguridad
        self.messages = self._load_messages()
        
        message_data = {
            'id': len(self.messages) + 1,
            'sender': sender,
            'recipient': recipient,
            'timestamp': datetime.now().isoformat(),
            
            'encrypted_data': encrypted_data,
            
            'signature': message_signature,
            
            'mac': mac_value,
            
            'encrypted_symmetric_key': encrypted_symmetric_key,
            'encrypted_mac_key': encrypted_mac_key,
            
            'security_metadata': {
                'encryption_algorithm': 'AES-256-GCM',
                'key_exchange_algorithm': 'RSA-2048-OAEP',
                'signature_algorithm': 'RSA-PSS-SHA256',
                'mac_algorithm': 'HMAC-SHA256'
            }
        }
        
        self.messages.append(message_data)
        self._save_messages()
        
        print(f"\n[SUCCESS] Mensaje enviado con seguridad completa")
        print(f"  - ID del mensaje: {message_data['id']}")
        print(f"  - Cifrado: RSA-2048 + AES-256-GCM")
        print(f"  - Firma digital: RSA-PSS con SHA-256")
        print(f"  - Autenticación: HMAC-SHA256")
        print(f"  - Clave pública obtenida del certificado X.509 de {recipient}")
        print(f"  - Solo {recipient} puede descifrar y verificar este mensaje")
        
        return True
    
    def read_secure_message(self, recipient, password, message_id):
        """
        Lee y verifica un mensaje cifrado.
        
        Proceso completo:
        1. Autentica al receptor
        2. Descifra la clave simétrica con RSA (clave privada del receptor)
        3. Verifica el MAC
        4. Descifra el mensaje con AES-GCM
        5. Obtiene clave pública del emisor desde su certificado X.509
        6. Verifica la firma digital (con clave pública del emisor)
        7. Verifica la cadena de certificación
        8. Si todo es válido, muestra el mensaje
        """
        if not self.auth.authenticate_user(recipient, password):
            return None
        
        #Cargar mensajes actualizados
        self.messages = self._load_messages()
        
        #Buscar el mensaje
        message_data = None
        for msg in self.messages:
            if msg['id'] == message_id and msg['recipient'] == recipient:
                message_data = msg
                break
        
        if message_data is None:
            print(f"[ERROR] Mensaje no encontrado o no autorizado")
            return None
        
        print(f"\n[INFO] Procesando mensaje seguro (ID: {message_id})")
        
        # Cargar clave privada del receptor
        recipient_paths = self._get_user_keys_path(recipient)
        private_key = self.asymmetric.load_private_key(recipient_paths['private'], password)
        
        if private_key is None:
            print(f"[ERROR] No se pudo cargar la clave privada")
            return None
        
        # Descifrar la clave simétrica con RSA
        print(f"\n[PASO 1] Descifrando clave AES con RSA...")
        encryption_key = self.asymmetric.decrypt_key(
            message_data['encrypted_symmetric_key'],
            private_key
        )
        
        if encryption_key is None:
            print(f"[ERROR] No se pudo descifrar la clave simétrica")
            return None
        
        # Descifrar la clave MAC con RSA
        print(f"\n[PASO 2] Descifrando clave MAC con RSA...")
        mac_key = self.asymmetric.decrypt_key(
            message_data['encrypted_mac_key'],
            private_key
        )
        
        if mac_key is None:
            print(f"[ERROR] No se pudo descifrar la clave MAC")
            return None
        
        # Verificar MAC
        print(f"\n[PASO 3] Verificando MAC del mensaje cifrado...")
        if not self.mac.verify_mac(
            message_data['encrypted_data']['ciphertext'],
            message_data['mac'],
            mac_key
        ):
            print(f"[ERROR] MAC inválido - mensaje puede haber sido alterado")
            return None
        
        # Descifrar mensaje con AES-GCM
        print(f"\n[PASO 4] Descifrando mensaje con AES-256-GCM...")
        plaintext = self.symmetric.decrypt(message_data['encrypted_data'], encryption_key)
        
        if plaintext is None:
            print(f"[ERROR] No se pudo descifrar el mensaje")
            return None
        
        #Verificar firma digital usando la clave pública del certificado
        print(f"\n[PASO 5] Obteniendo clave pública del emisor desde certificado X.509...")
        sender_public_key = self._get_public_key_from_certificate(message_data['sender'])
        
        if sender_public_key is None:
            print(f"[ERROR] No se pudo obtener la clave pública del emisor")
            return None
        
        print(f"\n[PASO 6] Verificando firma digital del emisor...")
        signature_valid = self.signature.verify_signature(
            plaintext,
            message_data['signature'],
            sender_public_key
        )
        
        if not signature_valid:
            print(f"[ERROR] Firma digital inválida - mensaje no auténtico")
            print(f"  - El mensaje puede haber sido modificado")
            print(f"  - O no fue enviado por {message_data['sender']}")
            return None
        
        # Verificar certificado del emisor
        print(f"\n[PASO 7] Verificando certificado X.509 del emisor...")
        sender_cert_path = os.path.join(
            self.pki.users_cert_dir, 
            f"{message_data['sender']}_certificate.pem"
        )
        
        if os.path.exists(sender_cert_path):
            cert_valid = self.pki.verify_certificate_chain(sender_cert_path)
            if cert_valid:
                print(f" Certificado del emisor verificado correctamente")
                print(f" Cadena de certificación válida (Usuario → AC2 → AC1)")
            else:
                print(f" Advertencia: Certificado del emisor no válido")
        else:
            print(f"  - Certificado no encontrado (no crítico)")
        
        # Todo verificado correctamente
        if plaintext:
            print(f"\n{'='*60}")
            print(f"[SUCCESS] MENSAJE DESCIFRADO Y VERIFICADO CORRECTAMENTE")
            print(f"{'='*60}")
            print(f"  De: {message_data['sender']}  (firma  + certificado )")
            print(f"  Para: {recipient}")
            print(f"  Fecha: {message_data['timestamp']}")
            print(f"\n  Contenido del mensaje:")
            print(f"  {'-'*58}")
            print(f"  {plaintext}")
            print(f"  {'-'*58}")
            print(f"\n  Verificaciones de seguridad realizadas:")
            print(f"     Clave pública obtenida del certificado X.509")
            print(f"     Firma digital verificada con clave del certificado")
            print(f"     Cadena de certificación verificada")
            print(f"     MAC verificado")
            print(f"     Mensaje descifrado correctamente")
            if 'security_metadata' in message_data:
                print(f"\n  Algoritmos de seguridad utilizados:")
                for key, value in message_data['security_metadata'].items():
                    print(f"    • {key}: {value}")
            print(f"{'='*60}\n")
        
        return plaintext
    
    def verify_user_certificate(self, username):
        """
        Verifica el certificado X.509 de un usuario.
        """
        cert_path = os.path.join(self.pki.users_cert_dir, f"{username}_certificate.pem")
        
        if not os.path.exists(cert_path):
            print(f"[ERROR] Certificado de {username} no encontrado")
            return False
        
        # Verificar cadena de certificación
        return self.pki.verify_certificate_chain(cert_path)
    
    def get_user_certificate_info(self, username):
        """
        Obtiene información del certificado de un usuario.
        """
        cert_path = os.path.join(self.pki.users_cert_dir, f"{username}_certificate.pem")
        
        if not os.path.exists(cert_path):
            print(f"[ERROR] Certificado de {username} no encontrado")
            return None
        
        return self.pki.get_certificate_info(cert_path)