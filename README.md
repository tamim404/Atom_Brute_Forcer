# Atom – Ethical Brute Force Tool

Atom is a lightweight, multi-threaded, and modular brute-force framework designed for security professionals and authorized penetration testers. It is built to be fast, easily extensible, and protocol-agnostic.

> ⚠️ **LEGAL DISCLAIMER**  
> This tool is provided strictly for educational purposes and authorized security auditing.  
> Do **not** use this tool against systems without explicit written permission.  
> Unauthorized access is illegal.  
> The authors are not responsible for any misuse or damage caused by this tool.

---

## 🚀 Features

- **Multi-threaded Architecture**  
  High-speed parallel testing using `concurrent.futures`.

- **Modular Design**  
  Protocols such as SSH, FTP, and SMB are isolated for easy extension (e.g., HTTP, RDP).

- **Smart Input Handling**  
  Automatically detects whether an argument is a literal value or a file path.

- **Fail-safe Logging**  
  Successful credentials are written immediately to `atom_success.log`.

---

## 📦 Installation

### Linux / macOS

```bash
git clone https://github.com/yourusername/atom.git
cd atom
pip3 install -r requirements.txt
python3 atom.py --help

```
### Windows
```powershell

py -m pip install -r requirements.txt
# OR:
# & "C:/Path/To/python.exe" -m pip install -r requirements.txt
```
## 🛠 Usage Guide

### Basic Syntax

```bash

python atom.py -H <TARGET> -M <MODULE> [OPTIONS]
```
## 🔍 Real-World Examples

### 1. Targeted SSH Audit
#### Test the root user against a host using a password list:
```bash 
python atom.py -H 192.168.1.10 -u root -P /usr/share/wordlists/rockyou.txt -M ssh
```
### 2. Mass FTP Scan (Stop on Success)
#### Scan a list of 100 IPs for default credentials:
```bash 

python atom.py -H targets.txt -u admin -p admin -M ftp -f
```
### 3. High-Performance SMB Attack
#### Use 20 threads for maximum speed:
```bash 
python atom.py -H 192.168.1.50 -U users.txt -P passwords.txt -M smb -t 20
```



