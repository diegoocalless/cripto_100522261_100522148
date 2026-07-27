# 🔐 Secure Messaging System with Public Key Infrastructure (PKI)

Academic project developed for the **Cryptography** course (Universidad Carlos III de Madrid). The project implements a **secure messaging platform** based on modern cryptographic techniques, combining **hybrid encryption**, **digital signatures**, **certificate-based authentication**, and a complete **Public Key Infrastructure (PKI)**.

## 📌 Overview

The application enables secure communication between registered users while guaranteeing:

* **Confidentiality** through hybrid encryption (RSA + AES).
* **Integrity** using HMAC and authenticated encryption.
* **Authentication** through X.509 certificates.
* **Non-repudiation** using RSA-PSS digital signatures.
* **Secure key management** with a hierarchical Public Key Infrastructure.

The project follows real-world security practices commonly used in secure communication systems.

---

## 🏗️ System Architecture

The platform is composed of several independent modules:

```
Root CA
    │
    ▼
Intermediate CA
    │
    ├── Issues X.509 certificates
    │
    ▼
Registered Users
    │
    ├── Authentication
    ├── Digital Signature
    ├── Hybrid Encryption
    └── Secure Message Exchange
```

The infrastructure includes:

* Root Certificate Authority (CA)
* Intermediate Certificate Authority
* User registration and authentication
* Certificate generation and validation
* Secure message encryption and decryption
* Digital signature generation and verification

---

## 🔒 Cryptographic Components

The system combines several cryptographic mechanisms:

| Component              | Purpose                                        |
| ---------------------- | ---------------------------------------------- |
| **AES-256-GCM**        | Authenticated symmetric encryption of messages |
| **RSA-2048**           | Encryption of session keys (hybrid encryption) |
| **RSA-PSS**            | Digital signatures                             |
| **HMAC-SHA256**        | Message integrity verification                 |
| **PBKDF2**             | Secure password-based key derivation           |
| **X.509 Certificates** | User authentication and trust management       |

---

## 🔄 Secure Communication Workflow

A secure message exchange follows these steps:

1. The sender authenticates using their credentials.
2. A random AES session key is generated.
3. The message is encrypted using **AES-256-GCM**.
4. The AES key is encrypted with the recipient's **RSA public key**.
5. The encrypted message is digitally signed using **RSA-PSS**.
6. The recipient verifies the signature, decrypts the AES key and finally decrypts the message.

This hybrid approach combines the efficiency of symmetric encryption with the security of public-key cryptography.

---

## 📂 Project Structure

```
├── CA/                     # Root and Intermediate Certificate Authorities
├── certificates/           # Generated user certificates
├── keys/                   # Public and private keys
├── users/                  # User management
├── messaging/              # Secure messaging logic
├── crypto/                 # Cryptographic utilities
├── main.py                 # Application entry point
└── README.md
```

*(Directory names may vary depending on the project structure.)*

---

## 🚀 Features

* User registration and authentication
* Secure password storage using PBKDF2
* Automatic generation of RSA key pairs
* X.509 certificate creation
* Certificate-based identity verification
* Secure message encryption using hybrid cryptography
* Digital signature generation and verification
* Message integrity protection
* Modular cryptographic architecture

---

## 🛠️ Technologies

`Python` · `cryptography` · `RSA-2048` · `AES-256-GCM` · `RSA-PSS` · `PBKDF2` · `HMAC-SHA256` · `X.509 Certificates` · `PKI`

---

## 🎯 Learning Outcomes

During the development of this project, the following concepts were applied:

* Public Key Infrastructure (PKI)
* Hybrid cryptography
* Symmetric and asymmetric encryption
* Digital signatures
* Certificate management
* Secure authentication
* Key generation and distribution
* Cryptographic best practices

---

## 👥 Authors

* Diego Calles Duque
* Tristán Serrano Álvarez

Project developed for the **Cryptography** course, **Bachelor's Degree in Computer Engineering**, Universidad Carlos III de Madrid (2025–2026).
