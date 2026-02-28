import nmap

# Create scanner object
scanner = nmap.PortScanner()

print("Welcome, this is a simple Nmap automation tool")
print("------------------------------------------------")

# Get IP address
ip_addr = input("Please enter the IP address you want to scan: ").strip()

print("The IP you entered is:", ip_addr)

# Menu
resp = input("""
Please enter the type of scan you want to run

1) SYN ACK Scan
2) UDP Scan
3) Comprehensive Scan

Your option: """).strip()

print("You have selected option:", resp)

# Select scan type
if resp == '1':
    arguments = '-v -sS'

elif resp == '2':
    arguments = '-v -sU'

elif resp == '3':
    arguments = '-v -sS -sV -sC -A -O'

else:
    print("Invalid option selected.")
    exit()

# Show Nmap version
print("Nmap Version:", scanner.nmap_version())

try:
    # Run scan
    scanner.scan(ip_addr, '1-1024', arguments)

    # Print scan info
    print("Scan Info:", scanner.scaninfo())

    # Check if host is found
    if ip_addr in scanner.all_hosts():

        print("IP Status:", scanner[ip_addr].state())

        protocols = scanner[ip_addr].all_protocols()
        print("Protocols:", protocols)

        for proto in protocols:
            ports = scanner[ip_addr][proto].keys()
            print(f"Open Ports ({proto}):", list(ports))

    else:
        print("Host is down or not responding.")

except Exception as e:
    print("An error occurred:", e)