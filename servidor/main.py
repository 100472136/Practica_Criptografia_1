import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from socket import *

# CREA SERVER SOCKET
port = 12000
server_ip = "localhost"

server_socket = socket(AF_INET, SOCK_STREAM)
server_socket.bind((server_ip, port))
server_socket.listen(1)

# INICIA COMUNICACIÓN CON EL CLIENTE, CREA CONNECTION SOCKET
connection_socket, client_ip = server_socket.accept()

# CREA CLAVE PÚBLICA Y CERTIFICADO\


class Certificate:
    def __init__(self):
        self.__asymmetric_key = self.__generate_key()
        self.__store_key()
        self.__certificate = self.__generate_certificate()
        self.__store_certificate()

    @staticmethod
    def __generate_key():
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

    def __store_key(self):
        #   GUARDA CLAVE PRIVADA EN DISCO
        with open("pemfiles/private_key.pem", "wb") as f:
            f.write(self.__asymmetric_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()       #   HAY QUE ENCRIPTAR LA CLAVE PRIVADA AL ALMACENARLA
            ))

    def __generate_certificate(self):           #   GENERA CERTIFICADO
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Colmenarejo"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UC3M"),
            x509.NameAttribute(NameOID.COMMON_NAME, "uc3m.es")
        ])

        certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.__asymmetric_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365) #   certificado válido por un año
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        ).sign(self.__asymmetric_key, hashes.SHA256())

        return certificate

    def __store_certificate(self):
        #   ALMACENA CERTIFICADO EN DISCO
        with open("pemfiles/certificate.pem", "wb") as f:
            f.write(self.__certificate.public_bytes(serialization.Encoding.PEM))


#ENVÍA SU CERTIFICADO

with open("pemfiles/certificate.pem", "rb") as f:
    certificate_pem_data = f.read()
connection_socket.send(certificate_pem_data)

#RECIBE CLAVE SIMÉTRICA ENCRIPTADA CON CLAVE PÚBLICA
encrypted_symmetric_key = connection_socket.recv(2048)

#DESENCRIPTA CLAVE SIMÉTRICA CON CLAVE PRIVADA
with open("pemfiles/private_key.pem", "rb") as f:
    private_key_pem_data = f.read()

private_key = serialization.load_pem_private_key(data=private_key_pem_data, password=None)
print(private_key)

#

#RECIBE USUARIO ENCRIPTADO CON CLAVE SIMÉTRICA

#DESENCRIPTA USUARIO CON CLAVE SIMÉTRICA

#COMPRUEBA SU USUARIO ESTÁ EN BASE DE DATOS

#RECIBE CONTRASEÑA ENCRIPTADA CON CLAVE SIMÉTRICA

#DESENCRIPTA CONTRASEÑA CON CLAVE SIMÉTRICA

#VALIDA SI LA CONTRASEÑA ESTÁ EN SU SERVIDOR