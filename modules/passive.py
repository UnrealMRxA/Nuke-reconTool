import os
import json
import subprocess
from datetime import datetime
import re

# Colors
G = "\033[92m"
Y = "\033[93m"
R = "\033[91m"
B = "\033[94m"
W = "\033[0m"

OUTPUT_DIR = "output/passive"

def header(text):
    print(f"\n{B}=== {text} ==={W}")

def is_installed(tool):
    return subprocess.run(
        ["which", tool],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    ).returncode == 0

def run_cmd(cmd, capture_json=False):
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if capture_json:
            try:
                return json.loads(result.stdout)
            except:
                return {}
        return result.stdout.strip()
    except:
        return None

def clean_whois(raw_text):
    keys = [
        "NetRange", "CIDR", "inetnum", "netname", "descr",
        "OrgName", "OrgId", "Country", "Registrar",
        "Creation Date", "Updated Date", "Expiry", "Name Server"
    ]
    data = {}
    for line in raw_text.splitlines():
        for key in keys:
            if key.lower() in line.lower():
                parts = line.split(":", 1)
                if len(parts) >= 2:
                    if key not in data:
                        data[key] = parts[1].strip()
    return data

def strip_ansi(s: str):
    return re.sub(r'\x1b\[[0-9;]*m', '', s)

def run():
    target = input("Enter domain: ").strip()
    if not target:
        print(R + "Invalid domain." + W)
        input("Press Enter...")
        return

    safe_target = target.replace("/", "_").replace("\\", "_")
    out_path = os.path.join(OUTPUT_DIR, safe_target)
    os.makedirs(out_path, exist_ok=True)

    print(f"\n{G}[+] Starting Passive Recon on {target}{W}")

    # ─────────────────────────────────────────────────────────────
    header("HOST LOOKUP")
    # ─────────────────────────────────────────────────────────────
    host_output = run_cmd(["host", target])
    print(host_output if host_output else R + "Host lookup failed." + W)

    ip = None
    if host_output:
        ipv4 = re.findall(r"has address ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", host_output)
        ipv6 = re.findall(r"has IPv6 address ([0-9a-fA-F:]+)", host_output)
        if ipv4:
            ip = ipv4[0]
            print(G + f"[+] IPv4 Found: {ip}" + W)
        elif ipv6:
            ip = ipv6[0]
            print(G + f"[+] IPv6 Found: {ip}" + W)

    # ─────────────────────────────────────────────────────────────
    header("WHOIS")
    # ─────────────────────────────────────────────────────────────
    print(Y + "[*] Running WHOIS (domain)..." + W)
    domain_raw = run_cmd(["whois", "-H", target]) or ""
    domain_whois = clean_whois(domain_raw)

    ip_whois = {}
    if ip:
        print(Y + "[*] Running WHOIS (IP)..." + W)
        ip_raw = run_cmd(["whois", "-H", ip]) or ""
        ip_whois = clean_whois(ip_raw)

    merged_whois = {**domain_whois, **ip_whois}

    print(G + f"[+] WHOIS entries collected: {len(merged_whois)}" + W)
    for k, v in merged_whois.items():
        print(f"{G}{k}:{W} {v}")

    # ─────────────────────────────────────────────────────────────
    header("DIG ANY")
    # ─────────────────────────────────────────────────────────────
    dig_output = run_cmd(["dig", "any", target, "+noall", "+answer"])
    print(dig_output if dig_output else "No DIG results")

    # ─────────────────────────────────────────────────────────────
    header("WHATWEB")
    # ─────────────────────────────────────────────────────────────

    print(Y + "[*] Running WhatWeb..." + W)

    if is_installed("whatweb"):
        os.system(f"whatweb {target}")
    else:
        print(R + "[-] whatweb not installed" + W)

    
    # ─────────────────────────────────────────────────────────────
    header("SUBDOMAIN ENUM")
    # ─────────────────────────────────────────────────────────────
    subdomains = []

    print(Y + "[*] Running Subfinder..." + W)
    if is_installed("subfinder"):
        out = run_cmd(["subfinder", "-d", target, "-silent"])
        if out:
            subdomains.extend(out.splitlines())
    else:
        print(R + "[-] subfinder not installed" + W)

    print(Y + "[*] Running Assetfinder..." + W)
    if is_installed("assetfinder"):
        out = run_cmd(["assetfinder", "--subs-only", target])
        if out:
            subdomains.extend(out.splitlines())
    else:
        print(R + "[-] assetfinder not installed" + W)

    subdomains = sorted(set(subdomains))
    print(G + f"[+] Found {len(subdomains)} subdomains" + W)

    with open(f"{out_path}/subs_raw.txt", "w") as f:
        f.write("\n".join(subdomains))

    # ─────────────────────────────────────────────────────────────
    header("DNSX")
    # ─────────────────────────────────────────────────────────────
    alive = {}

    print(Y + "[*] Running dnsx..." + W)
    if is_installed("dnsx"):
        proc = subprocess.Popen(
            ["dnsx", "-silent", "-resp", "-a", "-r", "8.8.8.8"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True
        )

        for sub in subdomains:
            proc.stdin.write(sub + "\n")
        proc.stdin.close()

        for line in proc.stdout:
            line = strip_ansi(line.strip())  # FIX ANSI COLOR CODES
            parts = line.split()
            if len(parts) >= 3:
                domain = parts[0]
                rtype = parts[1]
                rvalue = " ".join(parts[2:])
                alive.setdefault(domain, {})[rtype] = rvalue

        print(G + f"[+] Alive: {len(alive)}" + W)

        with open(f"{out_path}/subs_alive.json", "w") as f:
            json.dump(alive, f, indent=4)

    else:
        print(R + "[-] dnsx not installed." + W)


    print(G + f"[+] Results saved to: {out_path}" + W)
    input("\nPress Enter to return...")
