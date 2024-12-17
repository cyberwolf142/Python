import socket
import ipaddress
import os
import time
import datetime

def scan_host(ip):
    """
    Scans a single host for open ports.

    Args:
        ip (str): The IP address of the host to scan.

    Returns:
        list: A list of open ports.
    """
    open_ports = []
    for port in range(1, 1025):  # Scan ports 1 to 1024
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.1)  # Set a timeout for each connection attempt
                s.connect((ip, port))
                open_ports.append(port)
                print(f"[+] {port} is open on {ip}")
        except socket.error:
            pass  # Ignore exceptions for closed ports
    return open_ports

def scan_network(start_ip, end_ip):
    """
    Scans a range of IP addresses for open ports sequentially.

    Args:
        start_ip (str): The starting IP address of the network.
        end_ip (str): The ending IP address of the network.

    Returns:
        None
    """
    try:
        # Validate IP addresses using ipaddress library
        ipaddress.ip_address(start_ip)
        ipaddress.ip_address(end_ip)

        current_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{current_time}.txt"

        with open(filename, "w") as f:
            for ip in range(int(start_ip.split(".")[3]), int(end_ip.split(".")[3]) + 1):
                ip_address = f"{start_ip.rsplit('.', 1)[0]}.{ip}"
                print(f"Scanning host: {ip_address}")

                try:
                    open_ports = scan_host(ip_address)
                except KeyboardInterrupt:
                    print("\nScanning stopped by user.")
                    return

                f.write(f"Host: {ip_address}\n")
                f.write(f"Scanning {start_ip}-{end_ip}\n")
                if open_ports:
                    for port in open_ports:
                        f.write(f"  - Port {port} is open\n")
                else:
                    f.write(f"  - No open ports found.\n")
                f.write("\n")

    except ValueError:
        print("Invalid IP address format. Please enter valid IP addresses.")
    except KeyboardInterrupt:
        print("\nScanning stopped by user.")


if __name__ == "__main__":
    start_ip = input("Enter starting IP address: ")
    end_ip = input("Enter ending IP address: ")

    try:
        scan_network(start_ip, end_ip)
        print("Scan results written to scan_results_{current_time}.txt")
        print("Scan complete.")
    except KeyboardInterrupt:
        print("\nScanning stopped by user.")
