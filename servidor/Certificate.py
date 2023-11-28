from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from socket import *
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature




class Certificate:
    def __init__(self, passphrase: bytes):
        self.__asymmetric_key = None
        self.__passphrase = passphrase
        self.__check_key()
        self.__certificate = None
        self.__check_cert()

    @staticmethod
    def __generate_key():
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

    def __check_key(self):
        try:
            with open("database/private_key.pem", "rb") as f:
                ca_key_pem_data = f.read()
                self.__asymmetric_key = serialization.load_pem_private_key(
                    data=ca_key_pem_data, password=self.__passphrase)
        except FileNotFoundError:
            self.__asymmetric_key = self.__generate_key()
            self.__store_key()

    def __check_cert(self):
        try:
            with open("database/certificate.pem", "rb") as f:
                ca_cert_pem_data = f.read()
                self.__certificate = ca_cert = x509.load_pem_x509_certificate(
                    ca_cert_pem_data)

        except FileNotFoundError:
            self.__certificate = self.__create_csr()
            self.__store_certificate()
        except ValueError:
            self.__certificate = self.__create_csr()
            self.__store_certificate()

    def __store_key(self):
        #   GUARDA CLAVE PRIVADA EN DISCO
        with open("database/private_key.pem", "wb") as f:
            f.write(self.__asymmetric_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(self.__passphrase)
                # HAY QUE ENCRIPTAR LA CLAVE PRIVADA AL ALMACENARLA
            ))

    def __store_certificate(self):
        #   ALMACENA CERTIFICADO EN DISCO
        with open("database/certificate.pem", "wb") as f:
            f.write(self.__certificate.public_bytes(serialization.Encoding.PEM))


    # Generar solicitud
    def __create_csr(self):
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            # Provide various details about who we are.
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Colmenarejo"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UC3M"),
            x509.NameAttribute(NameOID.COMMON_NAME, "uc3m.es")
        ])).add_extension(
            x509.SubjectAlternativeName([
                # Describe what sites we want this certificate for.
                x509.DNSName("mysite.com"),
                x509.DNSName("www.mysite.com"),
                x509.DNSName("subdomain.mysite.com"),
            ]),
            critical=False,
        # Sign the CSR with our private key.
        ).sign(self.__asymmetric_key, hashes.SHA256())
        # Write our CSR out to disk.
        with open("database/csr.pem", "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))

        #se llama a la CA y envia la solicitud y esta devuelve el certificado
        with open("database/csr.pem", "rb") as f:
            csr_pem_data = f.read()

        #  iniciar comunicación a través de socket
        server_name = "localhost"
        port = 12001
        client_socket = socket(AF_INET, SOCK_STREAM)
        try:
            client_socket.connect((server_name, port))
        except ConnectionRefusedError:
            raise ConnectionRefusedError(
                "Error: Certificate Authority not active\n")

        # enviar csr a CA
        client_socket.send(csr_pem_data)

        # recibir certificado de la autoridad certificadora
        certificate_pem_data = client_socket.recv(2048)
        certificate = x509.load_pem_x509_certificate(certificate_pem_data)

        # verificar que la firma del certificado es válida
        with open("../CA_low/database/ca_cert.pem", "rb") as f:
            ca_cert_pem_data = f.read()
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem_data)
        try:
            ca_cert.public_key().verify(
                signature=certificate.signature,
                data=certificate.tbs_certificate_bytes,
                padding=padding.PKCS1v15(),
                algorithm=certificate.signature_hash_algorithm
            )
        except BrokenPipeError:
            client_socket.close()
            print("Error: cliente ha finalizado conexión")
        except InvalidSignature:
            client_socket.close()
            print("La firma del certificado es incorrecta")
        client_socket.close()
        return certificate

PASSPHRASE = b'\x94sO\xc1\xd4\x13\x0e\x11\x98\xee\x9a\x95W\xf6\xb5\x16'
Certificate(PASSPHRASE)



