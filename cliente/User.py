from cryptography.fernet import Fernet


class User:
    def __init__(self, username: str, password: str, interaction_type: str):
        self.username = username
        self.password = password
        self.interaction_type = interaction_type

