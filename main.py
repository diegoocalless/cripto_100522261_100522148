"""
Sistema de Mensajería Segura - Entregable 2
Aplicación principal con PKI completa y firma digital
"""

import os
import sys
from getpass import getpass
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from secure_messaging import SecureMessagingSystem

class SimpleMessagingApp:
    
    def __init__(self):
        self.system = SecureMessagingSystem()
        self.current_user = None
        self.current_password = None
        self.pki_initialized = False
        self.ac1_password = None
        self.ac2_password = None
    
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_header(self):
        print("=" * 60)
        print("   SISTEMA MENSAJERÍA SEGURA - PKI + FIRMA DIGITAL")
        print("=" * 60)
        if self.current_user:
            print(f"Usuario actual: {self.current_user}")
        print("\n")
    
    def wait_for_enter(self):
        input("\nPresione Enter para continuar...")

    def _prompt_password(self, message, confirm=True):
        """Solicita una contraseña desde terminal (sin almacenar en texto plano)."""
        while True:
            pwd = getpass(f"{message}: ")
            if not pwd:
                print("[ERROR] La contraseña no puede estar vacía")
                continue
            if not confirm:
                return pwd
            confirmation = getpass("Confirme la contraseña: ")
            if pwd == confirmation:
                return pwd
            print("[ERROR] Las contraseñas no coinciden. Intente nuevamente.")

    def _ensure_ac2_password_loaded(self):
        """Solicita la contraseña de AC2 si aún no se ha proporcionado."""
        if not self.ac2_password:
            print("\n[SEGURIDAD] Se requiere la contraseña de la AC2 para emitir certificados.")
            key_path = os.path.join(self.system.pki.ca_sub_dir, 'ac2_private_key.pem')
            while True:
                candidate = self._prompt_password(
                    "Introduzca la contraseña de AC2 existente", confirm=False
                )
                try:
                    with open(key_path, 'rb') as key_file:
                        serialization.load_pem_private_key(
                            key_file.read(),
                            password=candidate.encode(),
                            backend=default_backend()
                        )
                    self.ac2_password = candidate
                    self.system.set_ca_passwords(sub_password=self.ac2_password)
                    break
                except FileNotFoundError:
                    print("[ERROR] No se encontró la clave privada de AC2. Reejecute la inicialización de la PKI.")
                    break
                except ValueError:
                    print("[ERROR] Contraseña incorrecta para AC2. Inténtelo nuevamente.")
                except Exception as exc:
                    print(f"[ERROR] No se pudo verificar la contraseña de AC2: {exc}")
                    break
    
    def initialize_pki(self):
        """
        Inicializa la PKI si no existe.
        Crea AC1 (raíz) y AC2 (subordinada).
        """
        # Verificar si ya existe la PKI
        ac1_cert = os.path.join(self.system.pki.ca_root_dir, 'ac1_certificate.pem')
        ac2_cert = os.path.join(self.system.pki.ca_sub_dir, 'ac2_certificate.pem')

        if os.path.exists(ac1_cert) and os.path.exists(ac2_cert):
            print("[INFO] PKI ya inicializada")
            self.pki_initialized = True
            self._ensure_ac2_password_loaded()
            return True

        self.clear_screen()
        self.print_header()
        print("INICIALIZACIÓN DE LA PKI")
        print("-" * 60)
        print("\nSe va a crear la infraestructura de clave pública:")
        print("  AC1: Autoridad Certificadora Raíz (autofirmada)")
        print("  AC2: Autoridad Certificadora Subordinada")
        print("\n")

        print("[SEGURIDAD] Defina las contraseñas para las autoridades de certificación.")
        ac1_password = self._prompt_password("Nueva contraseña para AC1 (Raíz)")
        ac2_password = self._prompt_password("Nueva contraseña para AC2 (Subordinada)")

        print("[PASO 1] Creando Autoridad Certificadora Raíz (AC1)...")
        success = self.system.pki.create_root_ca(
            password=ac1_password,
            common_name="AC1-ROOT-SecureMessaging",
            organization="SecureMessaging PKI System",
            country="ES",
            validity_days=3650  # 10 años
        )

        if not success:
            print("[ERROR] No se pudo crear AC1")
            self.wait_for_enter()
            return False

        print("\n[PASO 2] Creando Autoridad Certificadora Subordinada (AC2)...")
        success = self.system.pki.create_subordinate_ca(
            root_password=ac1_password,
            sub_password=ac2_password,
            common_name="AC2-SUBORDINATE-SecureMessaging",
            organization="SecureMessaging PKI System",
            country="ES",
            validity_days=1825  # 5 años
        )

        if not success:
            print("[ERROR] No se pudo crear AC2")
            self.wait_for_enter()
            return False

        print(f"\n[SUCCESS] PKI inicializada correctamente")

        self.ac1_password = ac1_password
        self.ac2_password = ac2_password
        self.system.set_ca_passwords(root_password=ac1_password, sub_password=ac2_password)

        self.pki_initialized = True
        self.wait_for_enter()
        return True

    def login_menu(self):
        # Inicializar PKI si es necesario
        if not self.pki_initialized:
            self.initialize_pki()
        
        while True:
            self.clear_screen()
            self.print_header()
            print("MENÚ DE AUTENTICACIÓN")
            print("-" * 60)
            print("1. Iniciar sesión")
            print("2. Registrar nuevo usuario")
            print("3. Información de la PKI")
            print("4. Salir")
            print("\n")
            
            choice = input("Seleccione una opción: ").strip()
            
            if choice == "1":
                self.login()
            elif choice == "2":
                self.register()
            elif choice == "3":
                self.show_pki_info()
            elif choice == "4":
                print("¡Hasta pronto!")
                sys.exit(0)
            else:
                print("Opción inválida. Intente nuevamente.")
                self.wait_for_enter()
    
    def show_pki_info(self):
        """Muestra información sobre la PKI"""
        self.clear_screen()
        self.print_header()
        print("INFORMACIÓN DE LA PKI")
        print("-" * 60)
        
        # Verificar si existe la PKI
        ac1_cert = os.path.join(self.system.pki.ca_root_dir, 'ac1_certificate.pem')
        ac2_cert = os.path.join(self.system.pki.ca_sub_dir, 'ac2_certificate.pem')
        
        if not os.path.exists(ac1_cert):
            print("\n[INFO] La PKI aún no ha sido inicializada")
            print("Se inicializará automáticamente al registrar el primer usuario")
            self.wait_for_enter()
            return
        
        print("\nESTRUCTURA DE LA PKI:")
        print("  AC1 (Raíz)")
        print("    └─ AC2 (Subordinada)")
        print("         └─ Certificados de usuarios")
        
        # Información de AC1
        print("\n[AC1] AUTORIDAD CERTIFICADORA RAÍZ:")
        ac1_info = self.system.pki.get_certificate_info(ac1_cert)
        if ac1_info:
            print(f"  • Nombre: {ac1_info['subject']}")
            print(f"  • Número de serie: {ac1_info['serial_number']}")
            print(f"  • Válido desde: {ac1_info['not_before'][:10]}")
            print(f"  • Válido hasta: {ac1_info['not_after'][:10]}")
            print(f"  • Algoritmo: {ac1_info['signature_algorithm']}")
        
        # Información de AC2
        print("\n[AC2] AUTORIDAD CERTIFICADORA SUBORDINADA:")
        ac2_info = self.system.pki.get_certificate_info(ac2_cert)
        if ac2_info:
            print(f"  • Nombre: {ac2_info['subject']}")
            print(f"  • Emisor: {ac2_info['issuer']}")
            print(f"  • Número de serie: {ac2_info['serial_number']}")
            print(f"  • Válido desde: {ac2_info['not_before'][:10]}")
            print(f"  • Válido hasta: {ac2_info['not_after'][:10]}")
            print(f"  • Algoritmo: {ac2_info['signature_algorithm']}")
        
        # Certificados de usuario
        print(f"\n[USUARIOS] CERTIFICADOS EMITIDOS:")
        user_certs = [f for f in os.listdir(self.system.pki.users_cert_dir) 
                     if f.endswith('_certificate.pem')]
        
        if user_certs:
            print(f"  • Total de certificados emitidos: {len(user_certs)}")
            for cert_file in sorted(user_certs):
                username = cert_file.replace('_certificate.pem', '')
                print(f"    - {username}")
        else:
            print("  • No hay certificados de usuario emitidos aún")
        
        self.wait_for_enter()
    
    def login(self):
        self.clear_screen()
        self.print_header()
        print("INICIAR SESIÓN")
        print("-" * 60)
        
        username = input("Usuario: ").strip()
        password = input("Contraseña: ").strip()
        
        if self.system.auth.authenticate_user(username, password):
            # Verificar si tiene claves generadas
            if not self.system.user_has_keys(username):
                print(f"\n[ADVERTENCIA] No tienes claves RSA generadas")
                print("Generando claves y certificado X.509...")
                self._ensure_ac2_password_loaded()
                self.system.generate_user_keys(username, password)
            
            self.current_user = username
            self.current_password = password
            print(f"\n[SUCCESS] Bienvenido, {username}!")
            self.wait_for_enter()
            self.main_menu()
        else:
            print("\n[ERROR] Autenticación fallida")
            self.wait_for_enter()
    
    def register(self):
        self.clear_screen()
        self.print_header()
        print("REGISTRAR NUEVO USUARIO")
        print("-" * 60)
        print("\nRequisitos de contraseña:")
        print("  - Mínimo 8 caracteres")
        print("  - Al menos una mayúscula")
        print("  - Al menos una minúscula")
        print("  - Al menos un número")
        print("\n")
        
        username = input("Nuevo usuario: ").strip()
        password = input("Nueva contraseña: ").strip()
        confirm_password = input("Confirmar contraseña: ").strip()
        
        if password != confirm_password:
            print("\n[ERROR] Las contraseñas no coinciden")
            self.wait_for_enter()
            return
        
        if self.system.auth.register_user(username, password):
            print(f"\n[SUCCESS] Usuario {username} registrado exitosamente")
            
            # Generar par de claves RSA y certificado X.509
            print("\n[INFO] Generando claves RSA y certificado X.509...")
            self._ensure_ac2_password_loaded()
            self.system.generate_user_keys(username, password)
            
            print("\n¡Registro completado! Ya puedes iniciar sesión.")
            self.wait_for_enter()
        else:
            self.wait_for_enter()
    
    def main_menu(self):
        while True:
            self.clear_screen()
            self.print_header()
            print("MENÚ PRINCIPAL")
            print("-" * 60)
            print("1. Enviar mensaje seguro (cifrado + firmado)")
            print("2. Leer mis mensajes")
            print("3. Verificar mi certificado X.509")
            print("4. Información del sistema")
            print("5. Cerrar sesión")
            print("\n")
            
            choice = input("Seleccione una opción: ").strip()
            
            if choice == "1":
                self.send_message()
            elif choice == "2":
                self.read_messages()
            elif choice == "3":
                self.verify_certificate()
            elif choice == "4":
                self.system_info()
            elif choice == "5":
                self.current_user = None
                self.current_password = None
                print("Sesión cerrada.")
                self.wait_for_enter()
                break
            else:
                print("Opción inválida. Intente nuevamente.")
                self.wait_for_enter()
    
    def send_message(self):
        self.clear_screen()
        self.print_header()
        print("ENVIAR MENSAJE SEGURO")
        print("-" * 60)
        
        recipient = input("Destinatario: ").strip()
        message = input("Mensaje: ").strip()
        
        if not recipient or not message:
            print("\n[ERROR] Todos los campos son obligatorios")
            self.wait_for_enter()
            return
        
        # Verificar que el usuario existe
        with open("users.json", "r") as f:
            content = f.read()
            if not (recipient in content):
                print("\n[ERROR] No existe el usuario de destino")
                self.wait_for_enter()
                return
        
        # Verificar que el receptor tiene claves generadas
        if not self.system.user_has_keys(recipient):
            print(f"\n[ERROR] El usuario {recipient} no tiene claves RSA generadas")
            print("El receptor debe iniciar sesión al menos una vez")
            self.wait_for_enter()
            return
        
        if self.system.send_secure_message(self.current_user, self.current_password, recipient, message):
            print(f"\n[SUCCESS] Mensaje enviado a {recipient}")
            print("\nProtección aplicada:")
            print("  Mensaje firmado digitalmente con tu clave privada")
            print("  Mensaje cifrado con AES-256-GCM (clave aleatoria)")
            print(f"  Clave AES cifrada con RSA-2048 (clave pública de {recipient})")
            print("  MAC generado con HMAC-SHA256")
            print(f"  Solo {recipient} puede descifrar y verificar")
        else:
            print("\n[ERROR] No se pudo enviar el mensaje")
        
        self.wait_for_enter()
    
    def read_messages(self):
        self.clear_screen()
        self.print_header()
        print("MENSAJES RECIBIDOS")
        print("-" * 60)

        self.system.messages = self.system._load_messages()
        
        user_messages = []
        for msg in self.system.messages:
            if msg['recipient'] == self.current_user:
                user_messages.append(msg)
        
        if not user_messages:
            print("No hay mensajes nuevos.")
            self.wait_for_enter()
            return
        
        print(f"Tiene {len(user_messages)} mensaje(s):\n")
        for msg in user_messages:
            signed_mark = "" if 'signature' in msg else ""
            print(f"ID: {msg['id']} {signed_mark} - De: {msg['sender']} - Fecha: {msg['timestamp'][:19]}")
        
        print("\n" + "-" * 60)
        msg_id = input("Ingrese el ID del mensaje para leer (0 para volver): ").strip()
        
        if msg_id == "0":
            return
        
        try:
            msg_id = int(msg_id)
            print("\n[INFO] Descifrando y verificando mensaje...")
            print("Este proceso incluye:")
            print("  1. Descifrado con tu clave privada RSA")
            print("  2. Verificación de MAC")
            print("  3. Descifrado con AES-GCM")
            print("  4. Verificación de firma digital del emisor")
            print("  5. Verificación de certificado X.509")
            
            self.system.read_secure_message(self.current_user, self.current_password, msg_id)
        except ValueError:
            print("[ERROR] ID inválido")
        except Exception as e:
            print(f"[ERROR] {str(e)}")
        
        self.wait_for_enter()
    
    def verify_certificate(self):
        """Verifica el certificado X.509 del usuario actual"""
        self.clear_screen()
        self.print_header()
        print("VERIFICAR CERTIFICADO X.509")
        print("-" * 60)
        
        print(f"\nVerificando certificado de {self.current_user}...")
        
        # Obtener información del certificado
        cert_info = self.system.get_user_certificate_info(self.current_user)
        
        if cert_info:
            print("\nINFORMACIÓN DEL CERTIFICADO:")
            print(f"  • Titular: {cert_info['subject']}")
            print(f"  • Emisor: {cert_info['issuer']}")
            print(f"  • Número de serie: {cert_info['serial_number']}")
            print(f"  • Válido desde: {cert_info['not_before'][:10]}")
            print(f"  • Válido hasta: {cert_info['not_after'][:10]}")
            print(f"  • Algoritmo de firma: {cert_info['signature_algorithm']}")
            
            # Verificar cadena de certificación
            print("\nVERIFICANDO CADENA DE CERTIFICACIÓN:")
            self.system.verify_user_certificate(self.current_user)
        else:
            print("[ERROR] No se pudo obtener información del certificado")
        
        self.wait_for_enter()
    
    def system_info(self):
        self.clear_screen()
        self.print_header()
        print("INFORMACIÓN DEL SISTEMA - ENTREGABLE 2")
        print("-" * 60)
        
        print("\nALGORITMOS IMPLEMENTADOS:")
        print("  • Autenticación: PBKDF2-HMAC-SHA256 (600k iteraciones)")
        print("  • Cifrado híbrido:")
        print("    - Asimétrico: RSA-2048 con OAEP-SHA256")
        print("    - Simétrico: AES-256-GCM (cifrado autenticado)")
        print("  • Autenticación de mensajes: HMAC-SHA256")
        print("  • Firma digital: RSA-PSS con SHA-256")
        print("  • Certificados: X.509v3 con SHA-256")
        
        print("\nINFRAESTRUCTURA DE CLAVE PÚBLICA (PKI):")
        print("  • AC1: Autoridad Certificadora Raíz (autofirmada)")
        print("    - Validez: 10 años")
        print("    - Algoritmo: RSA-2048")
        print("  • AC2: Autoridad Certificadora Subordinada")
        print("    - Firmada por: AC1")
        print("    - Validez: 5 años")
        print("    - Algoritmo: RSA-2048")
        print("  • Certificados de usuario:")
        print("    - Firmados por: AC2")
        print("    - Validez: 1 año")
        print("    - Algoritmo: RSA-2048")
        
        print("\nFLUJO DE SEGURIDAD DEL MENSAJE:")
        print("  1. Emisor firma el mensaje con su clave privada (RSA-PSS)")
        print("  2. Se genera clave AES única para el mensaje")
        print("  3. Mensaje se cifra con AES-256-GCM")
        print("  4. Clave AES se cifra con RSA (clave pública del receptor)")
        print("  5. Se genera MAC del mensaje cifrado (HMAC-SHA256)")
        print("  6. Receptor descifra clave AES con su clave privada RSA")
        print("  7. Verifica MAC del mensaje cifrado")
        print("  8. Descifra mensaje con AES-GCM")
        print("  9. Verifica firma digital con clave pública del emisor")
        print("  10. Verifica certificado X.509 del emisor")
        
        print("\nESTADÍSTICAS:")
        print(f"  • Usuarios registrados: {len(self.system.auth.users)}")
        print(f"  • Mensajes enviados: {len(self.system.messages)}")
        
        # Verificar cuántos usuarios tienen claves
        users_with_keys = 0
        users_with_certs = 0
        for username in self.system.auth.users.keys():
            if self.system.user_has_keys(username):
                users_with_keys += 1
            cert_path = os.path.join(
                self.system.pki.users_cert_dir, 
                f"{username}_certificate.pem"
            )
            if os.path.exists(cert_path):
                users_with_certs += 1
        
        print(f"  • Usuarios con claves RSA: {users_with_keys}/{len(self.system.auth.users)}")
        print(f"  • Usuarios con certificados X.509: {users_with_certs}/{len(self.system.auth.users)}")
        
        print("\nARCHIVOS DEL SISTEMA:")
        files = [
            ("Usuarios", "users.json"),
            ("Mensajes", "messages.json"),
            ("PKI - AC1 Certificado", os.path.join(self.system.pki.ca_root_dir, "ac1_certificate.pem")),
            ("PKI - AC2 Certificado", os.path.join(self.system.pki.ca_sub_dir, "ac2_certificate.pem")),
        ]
        
        for name, path in files:
            if os.path.exists(path):
                size = os.path.getsize(path)
                print(f"  • {name}: {size} bytes")
            else:
                print(f"  • {name}: No existe")
        
        # Mostrar información del usuario actual
        if self.current_user:
            print(f"\nTU INFORMACIÓN DE SEGURIDAD:")
            paths = self.system._get_user_keys_path(self.current_user)
            if os.path.exists(paths['private']):
                size_priv = os.path.getsize(paths['private'])
                size_pub = os.path.getsize(paths['public'])
                print(f"  • Clave privada: {size_priv} bytes (cifrada con contraseña)")
                print(f"  • Clave pública: {size_pub} bytes")
            else:
                print("  • No tienes claves generadas")
            
            # Información del certificado
            cert_path = os.path.join(
                self.system.pki.users_cert_dir, 
                f"{self.current_user}_certificate.pem"
            )
            if os.path.exists(cert_path):
                size_cert = os.path.getsize(cert_path)
                print(f"  • Certificado X.509: {size_cert} bytes")
                cert_info = self.system.get_user_certificate_info(self.current_user)
                if cert_info:
                    print(f"    - Emisor: {cert_info['issuer']}")
                    print(f"    - Válido hasta: {cert_info['not_after'][:10]}")
            else:
                print("  • No tienes certificado X.509")
        
        self.wait_for_enter()

def main():
    """Función principal para Entregable 2"""
    app = SimpleMessagingApp()

    print("\n" + "=" * 60)
    print(" SISTEMA DE MENSAJERÍA SEGURA")
    print(" Entregable 2 - PKI + Firma Digital")
    print("=" * 60)
    print("\nCaracterísticas implementadas:")
    print("  Registro y autenticación de usuarios (PBKDF2)")
    print("  Cifrado híbrido (RSA-2048 + AES-256-GCM)")
    print("  Firma digital (RSA-PSS con SHA-256)")
    print("  Autenticación de mensajes (HMAC-SHA256)")
    print("  PKI de dos niveles (AC1 → AC2 → Usuarios)")
    print("  Certificados X.509v3")
    print("\nPresione Enter para continuar...")
    input()

    while True:
        try:
            app.login_menu()
        except KeyboardInterrupt:
            print("\n\n¡Hasta pronto!")
            break
        except Exception as e:
            print(f"\n[ERROR] Error inesperado: {str(e)}")
            import traceback
            traceback.print_exc()
            app.wait_for_enter()

if __name__ == "__main__":
    main()
