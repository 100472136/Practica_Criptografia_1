from cryptography import x509
from cryptography.x509.oid import NameOID


class VerifyCertificate:
    def __init__(self, cert: x509.Certificate):
        if not isinstance(cert, x509.Certificate):
            raise TypeError("Given certificate not of x509 Certificate type.")
        self.__certificate = cert
        self.__expected_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Colmenarejo"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UC3M"),
            x509.NameAttribute(NameOID.COMMON_NAME, "uc3m.es")
            ])
        self.__certificate_validity = self.__verify_certificate()

    @property
    def certificate_validity(self):
        return self.__certificate_validity

    def __verify_certificate(self):
        if self.__certificate.subject != self.__expected_subject:
            return False
        return True
