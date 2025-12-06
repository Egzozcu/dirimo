import argparse
import socket
import concurrent.futures
import ipaddress
import os
import subprocess
import time

def ping_host(host):
    param = "-n" if os.name == "nt" else "-c"
    command = ["ping", param, "1", host]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return host, (result.returncode == 0)
    except:
        return host, False

def scan_port(host, port, timeout=1):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return port, True
    except:
        return port, False

def scan_ports(host, ports):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, host, p) for p in ports]
        for f in concurrent.futures.as_completed(futures):
            port, status = f.result()
            if status:
                open_ports.append(port)
    return open_ports

def list_hosts(network):
    net = ipaddress.ip_network(network, strict=False)
    hosts = [str(h) for h in net.hosts()]
    live = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(ping_host, h) for h in hosts]
        for f in concurrent.futures.as_completed(futures):
            host, status = f.result()
            if status:
                live.append(host)
    return live

def banner_grab(host, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((host, port))
        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = s.recv(2048)
        s.close()
        return data.decode(errors="ignore")
    except:
        return None

def full_scan(host):
    common_ports = [21,22,23,25,53,80,110,135,139,143,443,445,587,3306,3389,8080]
    result = {}
    open_ports = scan_ports(host, common_ports)
    result["open_ports"] = open_ports
    result["banners"] = {}
    for p in open_ports:
        b = banner_grab(host, p)
        if b:
            result["banners"][p] = b.strip()
    return result

def main():
    parser = argparse.ArgumentParser(prog="dirimo")
    parser.add_argument("-n", "--network", help="Scan a network")
    parser.add_argument("-H", "--host", help="Scan a single host")
    parser.add_argument("-p", "--ports", help="Custom port range. Example: 1-1000")
    parser.add_argument("-f", "--full", action="store_true", help="Full scan")
    args = parser.parse_args()

    start = time.time()

    if args.network:
        print("[*] Scanning Network:", args.network)
        live_hosts = list_hosts(args.network)
        print("[*] Live Hosts:")
        for h in live_hosts:
            print(" -", h)

    if args.host:
        print("[*] Scanning Host:", args.host)

        if args.ports:
            p1, p2 = args.ports.split("-")
            ports = list(range(int(p1), int(p2) + 1))
            print("[*] Scanning ports:", args.ports)
            found = scan_ports(args.host, ports)
            print("[*] Open Ports:")
            for p in found:
                print(" -", p)

        if args.full:
            print("[*] Running Full Scan...")
            result = full_scan(args.host)
            print("[*] Open Ports:")
            for p in result["open_ports"]:
                print(" -", p)

            print("[*] Banners:")
            for p, b in result["banners"].items():
                print(f"--- Port {p} ---")
                print(b)
                print("----------------")

    end = time.time()
    print(f"Completed in {end-start:.2f}s")

if __name__ == "__main__":
    main()
