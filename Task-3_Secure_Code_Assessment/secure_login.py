# Secure Login System

USERNAME = "admin"
PASSWORD = "Strong@123"

MAX_ATTEMPTS = 3
attempts = 0

print("=== Secure Login System ===")

while attempts < MAX_ATTEMPTS:

    username = input("Enter Username: ")
    password = input("Enter Password: ")

    if username == USERNAME and password == PASSWORD:
        print("Login Successful!")
        break

    else:
        attempts += 1
        print("Invalid Username or Password!")

        remaining = MAX_ATTEMPTS - attempts

        if remaining > 0:
            print(f"Attempts remaining: {remaining}")

else:
    print("Account Locked!")
    print("Too many failed login attempts.")