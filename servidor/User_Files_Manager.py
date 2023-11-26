from User import User
import os
import json
from cryptography.fernet import Fernet


class UserFiles:
    def __init__(self, user: User, trainer: User):
        if user.type != "Client" or trainer.type != "Trainer":
            raise ValueError("Client and trainer must be of their corresponding type")
        self.__user = user
        self.__trainer = trainer
        self.__path = f"database/user_files/{self.__trainer.username}/{self.__user.username}.txt"
        self.__exercises = {}
        if not os.path.exists(self.__path):
            self.__init_file()
        self.__fernet = Fernet(key=user.password)

    def __init_file(self):
        with open(self.__path,  'w') as file:
            file.write(self.__encrypt(json.dumps({"routines": {}, "comments": {}}, indent=4)))

    def __write(self, json_content: dict) -> int:
        ciphertext = self.__fernet.encrypt(json.dumps(json_content).encode("latin-1"))
        with open(self.__path, "w") as file:
            if file.write(ciphertext.decode("latin-1")) < 0:
                return -1
        return 0

    def __read(self) -> dict:
        with open(self.__path, "r") as file:
            cleartext = file.read()
        return json.loads(self.__fernet.decrypt(cleartext))

    def __encrypt(self, file_content: str) -> str:
        """
        Encrypts json style data using fernet symmetric encryption
        :param file_content: json style string with data to encrypt
        :return: encrypted data
        """
        return self.__fernet.encrypt(file_content.encode("latin-1")).decode("latin-1")

    def __decrypt(self, file_content: str) -> dict:
        decrypted_file_content = self.__fernet.decrypt(file_content)
        return json.loads(decrypted_file_content)

    def add_routine(self, routine_name: str) -> int:
        data_list = self.__read()
        if routine_name in data_list.get("routines"):
            return -1
        data_list.get("routines")[routine_name] = {}
        self.__write(data_list)

    def add_custom_exercise(self, exercise_name: str, targeted_muscles: list):
        if exercise_name in self.__exercises:
            return -1
        self.__exercises[exercise_name] = targeted_muscles

    def add_set_to_routine(self, routine_name: str, exercise_name: str, rep_number: int):
        data_list = self.__read()
        if routine_name not in data_list.get("routines"):
            return -1
        if exercise_name not in self.__exercises:
            return -2
        data_list.get("routines")[routine_name][exercise_name] = rep_number
        self.__write(data_list)
