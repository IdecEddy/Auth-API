from utils.db import get_db
from utils.hashing import hash_password
from sqlalchemy.orm import Session
from models.user import User


def main():
    db = next(get_db())
    password = input("Enter the password: ")
    name = input("Enter a name for the user: ")
    email = input("Enter a email for the user: ")
    new_user = User(name=name, email=email, hashed_password=hash_password(password))

    db.add(new_user)
    db.commit()
    db.refresh(new_user)


if __name__ == "__main__":
    main()
