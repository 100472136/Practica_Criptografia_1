class User:
    def __init__(self, username: str, password: str, account_type: str):
        self.__username = username,
        self.__password = password,
        self.__type = account_type

    @property
    def username(self):
        return self.__username

    @property
    def password(self):
        return self.__password

    @property
    def type(self):
        return self.__type
