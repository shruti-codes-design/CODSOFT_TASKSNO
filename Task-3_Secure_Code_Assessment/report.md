# Secure Code Assessment Report

## Project Overview

This project analyzes the security of a simple Python login system by identifying common vulnerabilities and implementing secure coding practices.

---

## Vulnerability 1: Hardcoded Credentials

### Description
The username and password are directly stored in the source code.

### Risk
Anyone with access to the source code can view the credentials.

### Recommended Fix
Store credentials securely using a database or environment variables and use password hashing.

---

## Vulnerability 2: Weak Password

### Description
The vulnerable application uses a weak password.

### Risk
Weak passwords are easy to guess using brute-force or dictionary attacks.

### Recommended Fix
Use strong passwords containing uppercase letters, lowercase letters, numbers, and special characters.

---

## Vulnerability 3: Unlimited Login Attempts

### Description
The vulnerable application allows unlimited login attempts.

### Risk
Attackers can repeatedly guess passwords using brute-force attacks.

### Recommended Fix
Limit login attempts and temporarily lock the account after multiple failed attempts.

---

# Improvements Implemented

- Strong password
- Maximum of 3 login attempts
- Account lock after failed attempts

---

# Conclusion

The secure version of the application follows better security practices and reduces common security risks.