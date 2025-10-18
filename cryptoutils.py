import hashlib
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
import base64

class CryptoUtils:
    # ===== HASHES =====
    @staticmethod
    def generar_hash(mensaje):
        """Genera hash SHA-256 de un mensaje"""
        return hashlib.sha256(mensaje.encode()).hexdigest()
    
    @staticmethod
    def verificar_hash(mensaje, hash_esperado):
        """Verifica si el hash del mensaje coincide con el esperado"""
        return CryptoUtils.generar_hash(mensaje) == hash_esperado
    
    @staticmethod
    def hash_con_salt(password):
        """Genera hash de contraseña con salt"""
        salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return salt + key
    
    @staticmethod
    def verificar_password(password, hash_almacenado):
        """Verifica contraseña contra hash almacenado"""
        salt = hash_almacenado[:32]
        key_almacenado = hash_almacenado[32:]
        key_calculado = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return key_calculado == key_almacenado

    # ===== CIFRADO SIMÉTRICO =====
    @staticmethod
    def generar_clave_simetrica():
        """Genera clave para cifrado simétrico AES"""
        return Fernet.generate_key()
    
    @staticmethod
    def cifrar_simetrico(mensaje, clave):
        """Cifra mensaje con clave simétrica"""
        fernet = Fernet(clave)
        return fernet.encrypt(mensaje.encode())
    
    @staticmethod
    def descifrar_simetrico(mensaje_cifrado, clave):
        """Descifra mensaje con clave simétrica"""
        fernet = Fernet(clave)
        return fernet.decrypt(mensaje_cifrado).decode()

    # ===== CIFRADO ASIMÉTRICO (Funciones originales, no usadas en la solución simétrica) =====
    @staticmethod
    def generar_par_claves():
        """Genera par de claves pública/privada RSA"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def serializar_clave_publica(public_key):
        """Serializa clave pública para enviar"""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    @staticmethod
    def deserializar_clave_publica(public_key_bytes):
        """Deserializa clave pública recibida"""
        return serialization.load_pem_public_key(public_key_bytes)
    
    @staticmethod
    def cifrar_asimetrico(mensaje, public_key):
        """Cifra mensaje con clave pública del destinatario"""
        mensaje_bytes = mensaje.encode()
        cifrado = public_key.encrypt(
            mensaje_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(cifrado)
    
    @staticmethod
    def descifrar_asimetrico(mensaje_cifrado, private_key):
        """Descifra mensaje con clave privada"""
        mensaje_cifrado = base64.b64decode(mensaje_cifrado)
        descifrado = private_key.decrypt(
            mensaje_cifrado,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return descifrado.decode()