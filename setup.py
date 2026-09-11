#!/usr/bin/env python3
"""
NIDS Setup - Configures Snort 3 rules and validates syntax
Also fixes directory permissions for regular user access
"""
import os
import sys
import subprocess
import shutil
import stat

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def check_root():
    if os.geteuid() != 0:
        print("[!] Needs root for Snort configuration. Run: sudo python3 setup.py")
        return False
    return True

def fix_permissions():
    print("[*] Fixing directory permissions...")
    for d in ["data", "data/preprocessed", "logs", "pcaps", "dashboard/static/charts"]:
        path = os.path.join(BASE_DIR, d)
        os.makedirs(path, exist_ok=True)
        os.chmod(path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
        print(f"[+] chmod 777 {path}")

def setup_snort3_rules():
    print("="*60)
    print("CONFIGURING SNORT 3 RULES")
    print("="*60)

    snort_path = shutil.which("snort")
    if not snort_path:
        print("[!] Snort not found. Install: sudo apt install snort -y")
        return False
    print(f"[+] Snort: {snort_path}")

    result = subprocess.run(["snort", "-V"], capture_output=True, text=True)
    output = result.stdout + result.stderr
    for line in output.split("\n"):
        if "Version" in line:
            print(f"[+] {line.strip()}")

    config_file = None
    for path in ["/etc/snort/snort.lua", "/usr/local/etc/snort/snort.lua"]:
        if os.path.exists(path):
            config_file = path
            break
    if not config_file:
        for root, dirs, files in os.walk("/etc"):
            if "snort.lua" in files:
                config_file = os.path.join(root, "snort.lua")
                break
    if not config_file:
        print("[!] snort.lua not found")
        return False
    print(f"[+] Config: {config_file}")

    rules_dir = None
    for path in ["/etc/snort/rules", "/usr/local/etc/snort/rules"]:
        if os.path.exists(path):
            rules_dir = path
            break
    if not rules_dir:
        rules_dir = "/etc/snort/rules"
        os.makedirs(rules_dir, exist_ok=True)
    print(f"[+] Rules dir: {rules_dir}")

    local_rules = os.path.join(rules_dir, "local.rules")
    project_rules = os.path.join(BASE_DIR, "rules", "local.rules")

    if os.path.exists(local_rules):
        shutil.copy2(local_rules, local_rules + ".backup")
        print(f"[+] Backed up existing rules")

    if os.path.exists(project_rules):
        shutil.copy2(project_rules, local_rules)
        print(f"[+] Copied new rules: {local_rules}")
    else:
        print(f"[!] Project rules not found: {project_rules}")
        return False

    print("[*] Validating rules...")
    test_cmd = f"sudo snort -c {config_file} -R {local_rules} -T"
    result = subprocess.run(test_cmd, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        print("[+] Rule syntax: VALID")
    else:
        print("[!] Validation failed:")
        for line in result.stderr.split("\n"):
            if "ERROR" in line or "FATAL" in line:
                print(f"    {line}")
        return False

    os.makedirs("/var/log/snort", exist_ok=True)
    print("[+] Log directory ready")
    return True

def create_dirs():
    print("="*60)
    print("CREATING DIRECTORIES")
    print("="*60)
    for d in ["data", "data/preprocessed", "logs", "pcaps", "dashboard/static/charts"]:
        path = os.path.join(BASE_DIR, d)
        os.makedirs(path, exist_ok=True)
        print(f"[+] {d}/")

def main():
    print("="*60)
    print("NIDS SETUP - Snort 3")
    print("="*60)
    create_dirs()
    fix_permissions()
    if check_root():
        if setup_snort3_rules():
            print("\n" + "="*60)
            print("SETUP COMPLETE")
            print("="*60)
        else:
            print("\n[!] Setup failed")
    else:
        print("[!] Run with sudo to configure Snort")
    print("\nNext steps:")
    print("  python3 test_pcap_generator.py")
    print("  sudo python3 main.py --pcap pcaps/test.pcap")
    print("  python3 dashboard/app.py")

if __name__ == "__main__":
    main()
