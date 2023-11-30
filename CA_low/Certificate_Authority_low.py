import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from socket import *
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


PASSPHRASE = b"5\x9a'\xd1\xe8\x8eg\xba\xa8\x11&\xfa\x0f\x92\xa5\x0f"


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
            with open("database/ca_key.pem.", "rb") as f:
                ca_key_pem_data = f.read()
                self.__asymmetric_key = serialization.load_pem_private_key(
                    data=ca_key_pem_data, password=self.__passphrase)
        except FileNotFoundError:
            self.__asymmetric_key = self.__generate_key()
            self.__store_key()
            self.__certificate = self.__create_csr()
            self.__store_certificate()

    def __check_cert(self):
        try:
            with open("database/ca_cert.pem", "rb") as f:
                ca_cert_pem_data = f.read()
                self.__certificate = x509.load_pem_x509_certificate(ca_cert_pem_data)

        except FileNotFoundError:
            self.__certificate = self.__create_csr()
            self.__store_certificate()
        except ValueError:
            self.__certificate = self.__create_csr()
            self.__store_certificate()

    def __create_csr(self):
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            # Provide various details about who we are.
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Madrid"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CNI"),
            x509.NameAttribute(NameOID.COMMON_NAME, "cni.es")
        ])).add_extension(
            x509.SubjectAlternativeName([
                # Describe what sites we want this certificate for.
                x509.DNSName("cni.es")
            ]),
            critical=False,
            # Sign the CSR with our private key.
        ).sign(self.__asymmetric_key, hashes.SHA256())
        # Write our CSR out to disk.
        with open("database/csr.pem", "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))

        # se llama a la CA y envia la solicitud y esta devuelve el certificado
        with open("database/csr.pem", "rb") as f:
            csr_pem_data = f.read()

        #  iniciar comunicación a través de socket
        server_name = "localhost"
        port = 12002
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
        own_certificate = x509.load_pem_x509_certificate(certificate_pem_data)

        # verificar que la firma del certificado es válida
        with open("../CA_high/database/ca_cert.pem", "rb") as f:
            ca_cert_high_pem_data = f.read()
        ca_cert_high = x509.load_pem_x509_certificate(ca_cert_high_pem_data)
        try:
            ca_cert_high.public_key().verify(
                signature=own_certificate.signature,
                data=own_certificate.tbs_certificate_bytes,
                padding=padding.PKCS1v15(),
                algorithm=own_certificate.signature_hash_algorithm
            )
        except BrokenPipeError:
            client_socket.close()
            print("Error: cliente ha finalizado conexión")
        except InvalidSignature:
            client_socket.close()
            print("La firma del certificado es incorrecta")
        client_socket.close()
        return own_certificate

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
            ca_cert = CertificateAuthority.__create_csr(self)
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
        port = 12001
        ca_ip = "localhost"

        server_socket = socket(AF_INET, SOCK_STREAM)
        server_socket.bind((ca_ip, port))
        server_ip = None

        # INICIA COMUNICACIÓN CON EL CLIENTE, CREA CONNECTION SOCKET
        while True:
            if server_ip is not None:
                print(f"Conexión finalizada con {server_ip[0]}\n\n")
            print("Esperando conexión")
            server_socket.listen(1)
            connection_socket, server_ip = server_socket.accept()
            print(f"\n\nConexión iniciada con {server_ip[0]}")

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
