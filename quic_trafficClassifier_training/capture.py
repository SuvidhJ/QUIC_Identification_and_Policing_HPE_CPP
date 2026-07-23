import subprocess
import argparse
import os
import time

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"
CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
INTERFACE = r"\Device\NPF_{EABA8242-802F-459A-AA0E-8AC78516FF05}"
RAW_DIR = "raw"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--service",  required=True, help="e.g. youtube, meet, spotify, drive, web")
    parser.add_argument("--session",  required=True, type=int, help="session number 1-5")
    parser.add_argument("--duration", type=int, default=60)
    args = parser.parse_args()

    os.makedirs(RAW_DIR, exist_ok=True)
    base     = f"{args.service}_session{args.session}"
    pcap_file = os.path.join(RAW_DIR, f"{base}.pcap")
    keys_file = os.path.join(RAW_DIR, f"{base}_keys.log")

    print(f"[*] service  : {args.service}")
    print(f"[*] session  : {args.session}")
    print(f"[*] pcap     : {pcap_file}")
    print(f"[*] keys     : {keys_file}")
    print(f"[*] duration : {args.duration}s")

    chrome_env = os.environ.copy()
    chrome_env["SSLKEYLOGFILE"] = os.path.abspath(keys_file)

    print("[*] launching chrome (incognito)...")
    chrome_proc = subprocess.Popen(
        [CHROME_PATH, "--no-first-run", "--no-default-browser-check",
         "--incognito", "--ssl-key-log-file=" + os.path.abspath(keys_file),
         "about:blank"],
        env=chrome_env
    )
    time.sleep(2)

    tshark_cmd = [TSHARK_PATH, "-i", INTERFACE, "-f", "udp port 443", "-w", pcap_file, "-q"]
    print("[*] starting tshark...")
    tshark_proc = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    print(f"[*] capturing for {args.duration}s - do your activity now!")
    try:
        for elapsed in range(args.duration):
            time.sleep(1)
            if elapsed % 10 == 0 and elapsed > 0:
                print(f"    [{elapsed}s / {args.duration}s]")
    except KeyboardInterrupt:
        print("[!] interrupted")

    tshark_proc.terminate()
    tshark_proc.wait()
    chrome_proc.terminate()
    print("[*] stopped tshark and chrome")

    pcap_size = os.path.getsize(pcap_file) if os.path.exists(pcap_file) else 0
    keys_size = os.path.getsize(keys_file) if os.path.exists(keys_file) else 0
    print(f"[*] {pcap_file} : {pcap_size / 1024:.1f} KB")
    print(f"[*] {keys_file} : {keys_size} bytes")

    if keys_size == 0:
        print("[!] WARNING: keys file empty - kill all chrome processes first")
    else:
        print("[*] done")

if __name__ == "__main__":
    main()