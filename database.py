import json
import pathlib


def get_user(database_path: str, username: str, password: str) -> dict | None:
    all_users = json.loads(pathlib.Path(database_path).read_text())
    users = list(filter(lambda u: u["username"] == username and u["password"] == password, all_users))
    return users[0] if len(users) == 1 else None
