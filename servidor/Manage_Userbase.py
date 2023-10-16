import json


class Userbase:
    def __init__(self):
        self.__path = "database/userbase.json"
        self.__init_userbase()

    def __init_userbase(self):
        try:
            with open(self.__path, "r") as file:
                json.load(file)
        except json.decoder.JSONDecodeError:
            base_userbase = {"users": []}
            with open(self.__path, "w") as file:
                json.dump(base_userbase, file, indent=4)

    def user_with_username(self, username: str):
        with open(self.__path, "r") as file:
            datalist = json.load(file)
        for user in datalist["users"]:
            if user.get("username") == username:
                return user
        return None

    def add_user(self, user: dict):
        if self.user_with_username(user["username"]) is not None:
            raise ValueError("Intentando añadir usuario ya existente.")

        with open(self.__path, "r") as file:
            datalist = json.load(file)
        datalist["users"].append(user)
        with open(self.__path, "w") as file:
            json.dump(datalist, file, indent=4)

    def user_password_match(self, username: str, password: str):
        user = self.user_with_username(username)
        if user is None:
            raise ValueError("Intentando comprobar contraseña de usuario no existente.")
        if user["password"] == password:
            return True
        return False

