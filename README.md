
# RAT-crypter

RATCrypter is an open-source tool designed to encrypt and obfuscate remote access Trojans (RATs) in order to bypass antivirus detection. By leveraging advanced encryption techniques and code obfuscation, RATCrypter helps enhance the stealth capabilities of RATs, making them harder to detect by traditional antivirus scanners. With a user-friendly interface and customizable encryption options, this tool empowers security researchers and penetration testers to analyze and test the effectiveness of antivirus software against encrypted RATs. Please note that RATCrypter should only be used for ethical and lawful purposes, such as security testing, and any unauthorized use is strictly prohibited.



## Features

- Encryption: The code demonstrates the encryption of a trojan using both AES and RSA algorithms, providing a secure way to protect the trojan payload from detection and analysis.

- AES Encryption: The code utilizes the cryptography library to perform AES encryption, ensuring the confidentiality of the trojan data by encrypting it with a symmetric encryption algorithm.

- RSA Encryption: The code showcases the usage of RSA encryption to encrypt the AES key, enhancing the security of the trojan by encrypting the key with an asymmetric encryption algorithm.

- Password-Based Key Derivation: The code employs PBKDF2HMAC to derive a strong and secure AES key from a password and salt, adding an additional layer of security to the encryption process.

- Base64 Encoding: The code utilizes base64 encoding to encode the encrypted trojan data and encrypted AES key, enabling easy and safe representation of binary data as ASCII strings.

- File Operations: The code demonstrates file handling operations, reading the original trojan file and writing the encrypted trojan data to a new file, facilitating the storage and distribution of the encrypted trojan payload.

- Modular Design: The code is organized into reusable functions, making it easy to understand, modify, and integrate the encryption functionality into existing projects or security research.

- Documentation: The code includes comments and variable names that provide clear explanations and help other developers and researchers understand the encryption process and the purpose of each step.

- Security Awareness: The code serves as a learning resource for understanding encryption techniques, highlighting the importance of encryption in securing sensitive data and applications.


## Installation
 ## `linux`
```bash
  sudo su
  apt update
  apt upgrade
  apt install git 
  apt install python
  git clone https://github.com/bl6ndr/RAT-crypter.git
  cd RAT-crypter
  pip install cryptography
  python darkcrypt.py
```
## `Windows`
```bash
 git clone https://github.com/bl6ndr/RAT-crypter.git
 cd RAT-crypter
 pip install cryptography
 python darkcrypt.py
```
