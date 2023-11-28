import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from socket import *


PASSPHRASE = b'"uG\x08\x05\x92\xf9\x8f\x0e\x0c\x9a\x01\xc9\xfe7\x8b'


class CertificateAuthority:
    def __init__(self, passphrase: bytes):
        self.__asymmetric_key = None
        self.__passphrase = passphrase
        self.__check_key()
        self.__certificate = None
        self.__check_cert()
        self.main()

    @staticmethod
    def __generate_key():
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

    def __check_key(self):
        try:
            with open("database/ca_key.pem", "rb") as f:
                ca_key_pem_data = f.read()
                self.__asymmetric_key = serialization.load_pem_private_key(
                    data=ca_key_pem_data, password=self.__passphrase)
        except FileNotFoundError:
            self.__asymmetric_key = self.__generate_key()
            self.__store_key()
            self.__certificate = self.__generate_certificate()
            self.__store_certificate()


    def __check_cert(self):
        try:
            with open("database/ca_cert.pem.", "rb") as f:
                ca_cert_pem_data = f.read()
                self.__certificate = x509.load_pem_x509_certificate(ca_cert_pem_data)

        except FileNotFoundError:
            self.__certificate = self.__generate_certificate()
            self.__store_certificate()
        except ValueError:
            self.__certificate = self.__generate_certificate()
            self.__store_certificate()

    def __generate_certificate(self):  # GENERA CERTIFICADO
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
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
                days=365)  # certificado válido por un año
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        ).sign(self.__asymmetric_key, hashes.SHA256())

        return certificate

    def __store_key(self):
        #   GUARDA CLAVE PRIVADA EN DISCO
        with open("database/ca_key.pem", "wb") as f:
            f.write(self.__asymmetric_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization
                .BestAvailableEncryption(self.__passphrase)
                # HAY QUE ENCRIPTAR LA CLAVE PRIVADA AL ALMACENARLA
            ))

    def __store_certificate(self):
        # ALMACENA CERTIFICADO EN DISCO
        with open("database/ca_cert.pem", "wb") as f:
            f.write(self.__certificate.public_bytes
                    (serialization.Encoding.PEM))

    # Creating the certificate and signing the certificate
    def create_certificate(self, csr_req):
        with open("database/ca_key.pem", "rb") as f:
            ca_key_pem_data = f.read()
        with open("database/ca_cert.pem", "rb") as f:
            ca_cert_pem_data = f.read()

        ca_key = serialization.load_pem_private_key(
            data=ca_key_pem_data, password=self.__passphrase)

        try:
            ca_cert = x509.load_pem_x509_certificate(ca_cert_pem_data)
        except ValueError:
            ca_cert = CertificateAuthority.__generate_certificate(self)
            # SI NO TIENE UN CERTIFICADO CORRECTO, CREA OTRO

        certificate = (x509.CertificateBuilder()
                       .subject_name(csr_req.subject)
                       .issuer_name(ca_cert.subject)
                       .public_key(csr_req.public_key())
                       .serial_number(x509.random_serial_number())
                       .not_valid_before(datetime.datetime.now(datetime
                                                               .timezone.utc))
                       .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
                days=365)  # certificado válido por un año
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        ).sign(ca_key, hashes.SHA256()))
        with open("database/certificate.pem", "wb") as f:
            f.write(certificate.public_bytes
                    (serialization.Encoding.PEM))

        with open("database/certificate.pem", "rb") as f:
            certificate_pem_data = f.read()

        return certificate_pem_data

    def main(self):
        port = 12002
        ca_ip = "localhost"

        low_ac_socket = socket(AF_INET, SOCK_STREAM)
        low_ac_socket.bind((ca_ip, port))
        low_ac_ip = None

        # INICIA COMUNICACIÓN CON EL CLIENTE, CREA CONNECTION SOCKET
        while True:
            if low_ac_ip is not None:
                print(f"Conexión finalizada con {low_ac_ip[0]}\n\n")
            print("Esperando conexión")
            low_ac_socket.listen(1)
            connection_socket, low_ac_ip = low_ac_socket.accept()
            print(f"\n\nConexión iniciada con {low_ac_ip[0]}")

            # COMPRUEBA SI TIENE UN CERTIFICADO CORRECT0
            with open("database/ca_cert.pem", "rb") as f:
                certificate_pem_data = f.read()

            try:
                x509.load_pem_x509_certificate(certificate_pem_data)
            except ValueError:
                CertificateAuthority(PASSPHRASE)

            # RECIBE LA SOLICITUD DE CERTIFICADO
            print("Recibiendo csr...")
            csr_pem_data = connection_socket.recv(2048)

            csr_req = x509.load_pem_x509_csr(csr_pem_data)
            cliente_cert_pem_data = self.create_certificate(csr_req)
            print("Enviando certificado...")
            connection_socket.send(cliente_cert_pem_data)


CertificateAuthority(PASSPHRASE).main()
