from cryptography.fernet import Fernet


class User:
    def __init__(self, username: str, password: str, account_type: str):
        self.username = username
        self.password = password
        if account_type != "Trainer" and account_type != "Client":
            raise ValueError("Account type must be client or trainer")
        self.account_type = account_type

