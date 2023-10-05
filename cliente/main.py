from VerifyCertificate import VerifyCertificate
from CreateLoginInfo import Login
from cryptography.fernet import Fernet


from cryptography import x509
#  INICIAR COMUNICACIÓN
# RECIBIR CERTIFICADO DEL SERVIDOR
with open("../servidor/pemfiles/certificate.pem", "rb") as f:
    t_cert = x509.load_pem_x509_certificate(f.read())

# VERIFICAR CERTIFICADO

# GENERAR CLAVE SIMÉTRICA
symmetric_key = Fernet.generate_key()

#   GUARDA CLAVE SIMÉTRICA EN PEMFILES

#   ENCRIPTAR  CLAVE SIMÉTRICA CON CLAVE PÚBLICA DEL SERVIDOR
encrypted_symmetric_key = t_cert.public_key().encrypt(symmetric_key)

# PIDE INPUT DE USUARIO(LOGIN)
login = Login(symmetric_key)
encrypted_login_info = login.encrypt_login()

# ENCRIPTA LOGIN (CLAVE SIMÉTRICA)

# RECIBE VALIDACION DEL SERVIDOR
