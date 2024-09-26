# import os
#
# # Generate a secure random secret key
# secret_key = os.urandom(24).hex()  # Generates a 48-character hex key
# print(secret_key)
# '6e21170d998b7e87cb3eb38324764a4c78984905a71b2b6d'
# from app import db, User  # Import User model and db
# users = User.query.all()  # Query all users
# for user in users:
#     print(user.username, user.email)  # Print usernames and emails
import os

# Generate a 32-byte secure token
password_salt = os.urandom(32).hex()

print(password_salt)
"a4e3f0b951e808b197c2ef8b9dda17f0c17c81df97e8c9a3365dd31ff42053d0"