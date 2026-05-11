#!/usr/bin/env python3
"""
Memory Forensics Kit - RAM Analysis & Malware Detection
Author: Youssef Zeidi | Red Team Specialist
"""

import argparse, subprocess, json, os, re
from datetime import datetime

def banner():
    print("""
    ╔══════════════════════════════════════╗
    ║    Memory Forensics Kit v1.0         ║
    ║    RAM Analysis & IR Toolkit         ║
    ╚══════════════════════════════════════╝
    """)

def run_vol(dump, plugin, profile="Win10x64"):
    """Run Volatility3 plugin"""
    cmd = f"vol -f {dump} {plugin}"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        return result.stdout
    except subprocess.TimeoutExpired:
        return "[!] Plugin timed out"
    except Exception as e:
        return f"[!] Error: {e}"

def analyze_processes(dump, profile):
    print("\n[*] Analyzing running processes...")
    output = run_vol(dump, "windows.pslist.PsList")
    
    suspicious = []
    for line in output.split("\n"):
        for sus in ["svchost", "lsass", "explorer", "cmd", "powershell", "wscript", "cscript"]:
            if sus.lower() in line.lower() and line.strip():
                suspicious.append(line)
    
    print(output[:3000] if output else "[!] No output")
    return output

def check_injections(dump, profile):
    print("\n[*] Checking for process injection...")
    output = run_vol(dump, "windows.malfind.Malfind")
    
    if "VAD" in output:
        print(f"[!] Potential injection detected!")
        print(output[:2000])
    else:
        print("[+] No obvious injection detected")
    return output

def dump_lsass(dump, profile):
    print("\n[*] Extracting LSASS credentials...")
    output = run_vol(dump, "windows.lsadump.Lsadump")
    if output:
        with open("lsass_dump.txt", "w") as f:
            f.write(output)
        print("[+] LSASS data saved to lsass_dump.txt")
    return output

def network_scan(dump, profile):
    print("\n[*] Scanning network connections...")
    output = run_vol(dump, "windows.netstat.NetStat")
    print(output[:2000] if output else "[!] No connections found")
    return output

def generate_report(results, output_file):
    report = {
        "timestamp": datetime.now().isoformat(),
        "analyses": results
    }
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] Report saved: {output_file}")

def main():
    banner()
    parser = argparse.ArgumentParser()
    parser.add_argument("--dump", required=True, help="Path to memory dump file")
    parser.add_argument("--profile", default="Win10x64", help="OS profile")
    parser.add_argument("--output", default="forensics_report.json")
    parser.add_argument("--all", action="store_true", help="Run all plugins")
    parser.add_argument("--module", choices=["processes","inject","lsass","network"])
    args = parser.parse_args()

    if not os.path.exists(args.dump):
        print(f"[!] Dump file not found: {args.dump}")
        return

    results = {}
    if args.all or args.module == "processes":
        results["processes"] = analyze_processes(args.dump, args.profile)
    if args.all or args.module == "inject":
        results["injections"] = check_injections(args.dump, args.profile)
    if args.all or args.module == "lsass":
        results["credentials"] = dump_lsass(args.dump, args.profile)
    if args.all or args.module == "network":
        results["network"] = network_scan(args.dump, args.profile)

    generate_report(results, args.output)

if __name__ == "__main__":
    main()
