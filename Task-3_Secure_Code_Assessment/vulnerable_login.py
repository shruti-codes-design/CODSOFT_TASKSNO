# Vulnerable Login System

USERNAME = "admin"
PASSWORD = "12345"

print("=== Login System ===")

username = input("Enter Username: ")
password = input("Enter Password: ")

if username == USERNAME and password == PASSWORD:
    print("Login Successful!")
else:
    print("Invalid Username or Password!")